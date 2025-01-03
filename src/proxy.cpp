#include <iostream>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <errno.h>
#include <signal.h>
#include "crypto.h"
#include <map>
#include <sstream>
#include <iomanip>
#include <getopt.h>
#include <vector>
#include <sys/select.h>
#include <netinet/tcp.h>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192
#define PROXY_PORT 8888
#define WORKER_COUNT 4  // 进程数量
#define BLOCK_SIZE 16
#define COLOR_RESET   "\033[0m"
#define COLOR_ERROR   "\033[1;31m"      // 亮红色
#define COLOR_WARN    "\033[1;33m"      // 亮黄色
#define COLOR_INFO    "\033[1;32m"      // 亮绿色
#define COLOR_DEBUG   "\033[1;36m"      // 亮青色

// 全局变量声明
std::string target_ip = "127.0.0.1";  // 默认值
int target_port = 9000;               // 默认值

uint64_t total_bytes_sent = 0;
uint64_t total_bytes_received = 0;

// 定义日志级别
enum LogLevel {
    LOG_ERROR = 0,
    LOG_WARN = 1,
    LOG_INFO = 2,
    LOG_DEBUG = 3
};

class Logger {
public:
    static void setLevel(LogLevel level) {
        currentLevel = level;
    }

    static LogLevel getLevel() {
        return currentLevel;
    }

    static void error(const std::string& msg) {
        if (currentLevel >= LOG_ERROR) {
            std::cerr << COLOR_ERROR << "ERROR" << COLOR_RESET << ": " 
                     << msg << std::endl;
        }
    }

    static void warn(const std::string& msg) {
        if (currentLevel >= LOG_WARN) {
            std::cout << COLOR_WARN << "WARN" << COLOR_RESET << ": " 
                     << msg << std::endl;
        }
    }

    static void info(const std::string& msg) {
        if (currentLevel >= LOG_INFO) {
            std::cout << COLOR_INFO << "INFO" << COLOR_RESET << ": " 
                     << msg << std::endl;
        }
    }

    static void debug(const std::string& msg) {
        if (currentLevel >= LOG_DEBUG) {
            std::cout << COLOR_DEBUG << "DEBUG" << COLOR_RESET << ": " 
                     << msg << std::endl;
        }
    }

    template<typename T>
    static std::string toString(const T& value) {
        std::ostringstream oss;
        oss << value;
        return oss.str();
    }

private:
    static LogLevel currentLevel;
};

// 在文件中定义静态成员
LogLevel Logger::currentLevel = LOG_INFO;  // 默认日志级别

struct Connection {
    int clientFd;
    int serverFd;
    CryptoContext crypto;
    std::vector<char> remaining_data;  // 添加缓冲区
};

// 设置套接字为非阻塞
void setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// 添加一个辅助函数来处理非阻塞发送
ssize_t sendAll(int fd, const char* buffer, size_t length) {
    size_t total_sent = 0;
    while (total_sent < length) {
        ssize_t sent = send(fd, buffer + total_sent, length - total_sent, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 等待socket可写
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(fd, &write_fds);

                struct timeval tv = {.tv_sec = 1, .tv_usec = 0};  // 1秒超时
                int ready = select(fd + 1, NULL, &write_fds, NULL, &tv);
                
                if (ready < 0) {
                    //Logger::error("Select error: " + std::string(strerror(errno)));
                    return -1;
                } else if (ready == 0) {
                    //Logger::warn("Send timeout");
                    continue;
                }
                // socket 可写，继续发送
                continue;
            }
            //Logger::error("Send error: " + std::string(strerror(errno)));
            return -1;
        }

        total_sent += sent;
    }
    return total_sent;
}

// 连接到目标服务器
int connectToServer() {
    //Logger::debug("Connecting to server " + target_ip + ":" + Logger::toString(target_port));
    
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        //Logger::error("Failed to create socket: " + std::string(strerror(errno)));
        return -1;
    }

    // 添加TCP优化选项
    int flag = 1;
    setsockopt(serverFd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    int sendbuf = 256 * 1024;
    int recvbuf = 256 * 1024;
    setsockopt(serverFd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
    setsockopt(serverFd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));


    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip.c_str(), &serverAddr.sin_addr) <= 0) {
        //Logger::error("Invalid target IP address: " + target_ip);
        close(serverFd);
        return -1;
    }

    setNonBlocking(serverFd);
    //Logger::debug("Attempting to connect...");
    
    if (connect(serverFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        if (errno != EINPROGRESS) {
            //Logger::error("Connect to server failed: " + std::string(strerror(errno)));
            close(serverFd);
            return -1;
        }

        //Logger::debug("Connection in progress, waiting...");
        // 等待连接完成
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(serverFd, &write_fds);

        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};  // 5秒超时
        int ready = select(serverFd + 1, NULL, &write_fds, NULL, &tv);
        
        if (ready <= 0) {
            //Logger::error("Connect timeout or error");
            close(serverFd);
            return -1;
        }

        // 检查连接是否成功
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(serverFd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            //Logger::error("Connect failed after select: " + std::string(strerror(error)));
            close(serverFd);
            return -1;
        }
    }

    //Logger::info("Successfully connected to upstream server");
    return serverFd;
}

/*
// 当前的数据流程：
buffer -> remaining_data -> pipe -> encrypt/decrypt -> pipe -> encrypted/decrypted buffer -> send
内存拷贝占用了大量CPU事件
尝试去除read和remaing_data，使用splice直接从server socket传递给AF_ALG socket，并从AF_ALG socket传递给client socket
需要考虑到补位
优化狗的数据流应该为
splice -> pipe -> encrypt/decrypt -> pipe -> send
*/
// 数据转发
void forwardData(Connection* conn, int fromFd, int toFd, bool encrypt, int epollFd) {
    char buffer[BUFFER_SIZE];
    
    while (true) {
        ssize_t n = read(fromFd, buffer, sizeof(buffer));
        
        
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if(conn->remaining_data.size()){
                    //Logger::debug("Read " + Logger::toString(conn->remaining_data.size()) + " bytes from fd " + Logger::toString(fromFd));
                }
                return;  // 等待下次事件
            }
            //Logger::error("Read error: " + std::string(strerror(errno)));
            goto close_connection;
        } else if (n == 0) {
            // 在关闭连接前处理剩余数据
            if (!conn->remaining_data.empty() && encrypt) {
                //Logger::debug("\033[0;31m Processing remaining " + 
                            //  Logger::toString(conn->remaining_data.size()) + 
                            //  " bytes before closing \033[0m");

                // 如果剩余数据不是BLOCK_SIZE的整数倍，需要进行填充
                size_t padding_needed = 0;
                if (conn->remaining_data.size() % BLOCK_SIZE != 0) {
                    padding_needed = BLOCK_SIZE - (conn->remaining_data.size() % BLOCK_SIZE);
                    size_t original_size = conn->remaining_data.size();
                    conn->remaining_data.resize(original_size + padding_needed);
                    // PKCS7填充
                    for (size_t i = original_size; i < conn->remaining_data.size(); i++) {
                        conn->remaining_data[i] = padding_needed;
                    }
                }else{
                    //原始数据为16的倍数时，填充16个0x10
                    size_t original_size = conn->remaining_data.size();
                    conn->remaining_data.resize(original_size + BLOCK_SIZE);
                    for (size_t i = original_size; i < conn->remaining_data.size(); i++) {
                        conn->remaining_data[i] = BLOCK_SIZE;
                    }
                }

                // 处理剩余数据
                ssize_t process_size = conn->remaining_data.size();
                
                int pipefd[2];
                if (pipe(pipefd) < 0) {
                    //Logger::error("Failed to create pipe for remaining data");
                    goto close_connection;
                }

                ssize_t written = write(pipefd[1], conn->remaining_data.data(), process_size);
                close(pipefd[1]);
                
                if (written != process_size) {
                    //Logger::error("Failed to write remaining data to pipe");
                    close(pipefd[0]);
                    goto close_connection;
                }

                int outpipefd[2];
                if (pipe(outpipefd) < 0) {
                    //Logger::error("Failed to create output pipe for remaining data");
                    close(pipefd[0]);
                    goto close_connection;
                }

                conn->crypto.encrypt(pipefd[0], outpipefd[1], process_size);
                close(pipefd[0]);
                close(outpipefd[1]);

                char encrypted[BUFFER_SIZE * 2];
                ssize_t enc_len = read(outpipefd[0], encrypted, BUFFER_SIZE * 2);
                if(enc_len != process_size){
                    //Logger::error("Read encrypted data failed");
                    close(outpipefd[0]);
                    goto close_connection;
                }
                close(outpipefd[0]);

                if (enc_len > 0) {
                    ssize_t sent = sendAll(toFd, encrypted, enc_len);
                    if (sent < 0) {
                        //Logger::error("Failed to send remaining encrypted data");
                        goto close_connection;
                    }
                    //Logger::debug("Sent final " + Logger::toString(sent) + " encrypted bytes");
                }
                conn->remaining_data.clear();
            }

            if (fromFd == conn->clientFd) {
                //Logger::info("Client connection closed");
            } else {
                //Logger::info("Server connection closed");
            }
            goto close_connection;
        }

        //Logger::debug("Read " + Logger::toString(n) + " bytes from fd " + Logger::toString(fromFd));
        

        if (encrypt) {
            // 将数据添加到缓冲区
            if(conn->remaining_data.size()){
                //Logger::debug("\033[0;30;41m Have data \033[0m");
            }
            conn->remaining_data.insert(conn->remaining_data.end(), buffer, buffer + n);

            total_bytes_received += n;
            //Logger::info("Total bytes received: " + Logger::toString(total_bytes_received));

            // 处理完整的数据块
            while (!conn->remaining_data.empty()) {
                // 计算可以处理的数据大小
                ssize_t process_size = conn->remaining_data.size();
                
                // 如果数据不是BLOCK_SIZE的整数倍，需要填充
                size_t padding_needed = 0;
                if (process_size % BLOCK_SIZE != 0) {
                    padding_needed = BLOCK_SIZE - (process_size % BLOCK_SIZE);
                    size_t original_size = process_size;
                    conn->remaining_data.resize(original_size + padding_needed);
                    // PKCS7填充
                    for (size_t i = original_size; i < conn->remaining_data.size(); i++) {
                        conn->remaining_data[i] = padding_needed;
                    }
                    process_size += padding_needed;
                }else{
                    //原始数据为16的倍数时，填充16个0x10
                    size_t original_size = process_size;
                    conn->remaining_data.resize(original_size + BLOCK_SIZE);
                    for (size_t i = original_size; i < conn->remaining_data.size(); i++) {
                        conn->remaining_data[i] = BLOCK_SIZE;
                    }
                    process_size += BLOCK_SIZE;
                }

                // 确保不超过缓冲区大小
                /* if (process_size > BUFFER_SIZE) {
                    //Logger::debug("\033[0;30;41m Process size too large \033[0m");
                    process_size = (BUFFER_SIZE / BLOCK_SIZE) * BLOCK_SIZE;
                } */

                // 加密数据
                int pipefd[2];
                if (pipe(pipefd) < 0) {
                    //Logger::error("Failed to create pipe");
                    goto close_connection;
                }

                ssize_t written = write(pipefd[1], conn->remaining_data.data(), process_size);
                close(pipefd[1]);
                total_bytes_sent += written;
                //Logger::info("Total bytes sent: " + Logger::toString(total_bytes_sent) + "remain:" + Logger::toString(conn->remaining_data.size()));

                if (written != process_size) {
                    //Logger::error("Failed to write to pipe");
                    close(pipefd[0]);
                    goto close_connection;
                }

                int outpipefd[2];
                if (pipe(outpipefd) < 0) {
                    //Logger::error("Failed to create output pipe");
                    close(pipefd[0]);
                    goto close_connection;
                }

                conn->crypto.encrypt(pipefd[0], outpipefd[1], process_size);
                close(pipefd[0]);
                close(outpipefd[1]);

                char encrypted[BUFFER_SIZE * 2];
                ssize_t enc_len = read(outpipefd[0], encrypted, BUFFER_SIZE * 2);
                if(enc_len != process_size){
                    //Logger::error("Read encrypted data failed");
                    close(outpipefd[0]);
                    goto close_connection;
                }
                close(outpipefd[0]);

                if (enc_len > 0) {
                    ssize_t sent = sendAll(toFd, encrypted, enc_len);
                    if (sent < 0) {
                        //Logger::error("Send failed");
                        goto close_connection;
                    }
                    //Logger::debug("Sent " + Logger::toString(sent) + " encrypted bytes");
                }

                // 从缓冲区移除已处理的数据
                conn->remaining_data.erase(conn->remaining_data.begin(), 
                                        conn->remaining_data.begin() + process_size);
            }
        } else {
            // 从客户端收到的加密数据，直接解密并转发
            if (n % BLOCK_SIZE != 0) {
                //Logger::error("Received data length not multiple of block size");
                goto close_connection;
            }

            int pipefd[2];
            if (pipe(pipefd) < 0) {
                //Logger::error("Failed to create pipe");
                goto close_connection;
            }

            ssize_t written = write(pipefd[1], buffer, n);
            close(pipefd[1]);

            if (written != n) {
                //Logger::error("Failed to write to pipe");
                close(pipefd[0]);
                goto close_connection;
            }

            int outpipefd[2];
            if (pipe(outpipefd) < 0) {
                //Logger::error("Failed to create output pipe");
                close(pipefd[0]);
                goto close_connection;
            }

            conn->crypto.decrypt(pipefd[0], outpipefd[1], n);
            close(pipefd[0]);
            close(outpipefd[1]);

            char decrypted[BUFFER_SIZE];
            ssize_t dec_len = read(outpipefd[0], decrypted, BUFFER_SIZE);
            close(outpipefd[0]);

            if (dec_len > 0) {
                //去除填充
                size_t padding_len = decrypted[dec_len - 1];
                dec_len -= padding_len;
                //打印解密后的数据
                ssize_t sent = sendAll(toFd, decrypted, dec_len);
                if (sent < 0) {
                    //Logger::error("Send failed");
                    goto close_connection;
                }
                //Logger::debug("Sent " + Logger::toString(sent) + " decrypted bytes");
            }
        }
    }

close_connection:
    //Logger::info("Closing connection");
    epoll_ctl(epollFd, EPOLL_CTL_DEL, conn->clientFd, NULL);
    epoll_ctl(epollFd, EPOLL_CTL_DEL, conn->serverFd, NULL);
    
    shutdown(conn->clientFd, SHUT_RDWR);
    shutdown(conn->serverFd, SHUT_RDWR);
    
    close(conn->clientFd);
    close(conn->serverFd);
    conn->clientFd = -1;
    conn->serverFd = -1;
    delete conn;
}



void forwardDataNoCopy(Connection* conn, int fromFd, int toFd, bool encrypt, int epollFd){
    uint8_t padding_data[BLOCK_SIZE];
    memset(padding_data, BLOCK_SIZE, BLOCK_SIZE);
    char buffer[BUFFER_SIZE];
    int pipefd[2];
    int outpipefd[2];
    while(true){
        if(encrypt){
            //Logger::debug("Encrypt data");
            
            ssize_t spliced = 0;
            ssize_t total_spliced = 0;
            ssize_t total_sent = 0;

        if(pipe(pipefd) < 0){
            //Logger::error("Failed to create pipe");
            goto close_connection;
        }
        while(total_spliced < BUFFER_SIZE){
            size_t remaining = BUFFER_SIZE - total_spliced;
            
            spliced = splice(fromFd, NULL, pipefd[1], NULL, remaining, SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);
            //Logger::debug("Splice " + Logger::toString(spliced) + " bytes");
            if(spliced < 0){
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if(total_spliced > 0) break;
                    //Logger::debug("Wait for next event");
                    return;  // 等待下次事件
                }
                //Logger::debug("Failed to splice data");
                goto cleanup;
            }else if(spliced == 0){
                // 如果返回 0，表示数据传输完成

                if(total_spliced == 0) {
                    //Logger::info(fromFd == conn->clientFd ? 
                                // "Client connection closed" : 
                                // "Server connection closed");
                    goto cleanup;
                }
                break;
            }
            total_spliced += spliced;
        }
        if(total_spliced == 0){
            //Logger::debug("Total spliced is 0");
            goto close_connection;
        }

        
            if(total_spliced % BLOCK_SIZE == 0){
                //pkcs7 填充
                ssize_t written = write(pipefd[1], padding_data, BLOCK_SIZE);
                //Logger::debug("Write " + Logger::toString(written) + " bytes");
                total_spliced += written;
                // close(pipefd[1]);
            }else{
                // 如果total_spliced不为BLOCK_SIZE的整数倍，说明数据不足，需要填充
                size_t need_padding = BLOCK_SIZE - total_spliced % BLOCK_SIZE;
                uint8_t *need_padding_data = new uint8_t[need_padding];
                memset(need_padding_data, need_padding, need_padding);
                ssize_t written = write(pipefd[1], need_padding_data, need_padding);
                //Logger::debug("Write " + Logger::toString(written) + " bytes");
                total_spliced += written;
                // close(pipefd[1]);
                delete[] need_padding_data;
            }

            
            if(pipe(outpipefd) < 0){
                //Logger::error("Failed to create output pipe");
                goto close_connection;
            }

            conn->crypto.encrypt(pipefd[0], outpipefd[1], total_spliced);
            // close(pipefd[0]);
            // close(outpipefd[1]);

            //发送加密后的数据
            
            while(total_sent < total_spliced){
                ssize_t sent = splice(outpipefd[0], NULL, toFd, NULL, total_spliced, SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);
                //Logger::debug("sent " + Logger::toString(sent) + " bytes");
                if(sent < 0){
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // 等待socket可写
                        fd_set write_fds;
                        FD_ZERO(&write_fds);
                        FD_SET(toFd, &write_fds);

                        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};  // 1秒超时
                        int ready = select(toFd + 1, NULL, &write_fds, NULL, &tv);
                        
                        if (ready < 0) {
                            //Logger::error("Select error: " + std::string(strerror(errno)));
                            goto close_connection;
                        } else if (ready == 0) {
                            //Logger::warn("Send timeout");
                            continue;
                        }
                        // socket 可写，继续发送
                        continue;
                    }
                    //Logger::error("Failed to send encrypted data");
                    goto close_connection;
                }
                total_sent += sent;
                //Logger::debug("Total sent " + Logger::toString(total_sent) + " bytes");
            }

            if(total_spliced == 0){
                //Logger::debug("Total spliced is 0");
                goto close_connection;
            }
cleanup:
            // if(pipefd[0] != -1) close(pipefd[0]);
            // if(pipefd[1] != -1) close(pipefd[1]);
            // if(outpipefd[0] != -1) close(outpipefd[0]);
            // if(outpipefd[1] != -1) close(outpipefd[1]);
            // if(spliced < 0 || total_spliced == 0) goto close_connection;
        }else{
            //当前存在问题
            ssize_t n = read(fromFd, buffer, sizeof(buffer));
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if(conn->remaining_data.size()){
                        //Logger::debug("Read " + Logger::toString(conn->remaining_data.size()) + " bytes from fd " + Logger::toString(fromFd));
                    }
                    return;  // 等待下次事件
                }
                //Logger::error("Read error: " + std::string(strerror(errno)));
                goto close_connection;
            } else if (n == 0) {
                    if (fromFd == conn->clientFd) {
                    //Logger::info("Client connection closed");
                } else {
                    //Logger::info("Server connection closed");
                }
                goto close_connection;
            }

            // 从客户端收到的加密数据，直接解密并转发
                if (n % BLOCK_SIZE != 0) {
                    //Logger::error("Received data length not multiple of block size");
                    goto close_connection;
                }

                int pipefd[2];
                if (pipe(pipefd) < 0) {
                    //Logger::error("Failed to create pipe");
                    goto close_connection;
                }

                ssize_t written = write(pipefd[1], buffer, n);
                close(pipefd[1]);

                if (written != n) {
                    //Logger::error("Failed to write to pipe");
                    close(pipefd[0]);
                    goto close_connection;
                }

                int outpipefd[2];
                if (pipe(outpipefd) < 0) {
                    //Logger::error("Failed to create output pipe");
                    close(pipefd[0]);
                    goto close_connection;
                }

                conn->crypto.decrypt(pipefd[0], outpipefd[1], n);
                close(pipefd[0]);
                close(outpipefd[1]);

                char decrypted[BUFFER_SIZE];
                ssize_t dec_len = read(outpipefd[0], decrypted, BUFFER_SIZE);
                close(outpipefd[0]);

                if (dec_len > 0) {
                    //去除填充
                    size_t padding_len = decrypted[dec_len - 1];
                    dec_len -= padding_len;
                    //打印解密后的数据
                    ssize_t sent = sendAll(toFd, decrypted, dec_len);
                    if (sent < 0) {
                        //Logger::error("Send failed");
                        goto close_connection;
                    }
                    //Logger::debug("Sent " + Logger::toString(sent) + " decrypted bytes");
                }
        }
        
        
    }


close_connection:
    //Logger::info("Closing connection");
    epoll_ctl(epollFd, EPOLL_CTL_DEL, conn->clientFd, NULL);
    epoll_ctl(epollFd, EPOLL_CTL_DEL, conn->serverFd, NULL);
    
    shutdown(conn->clientFd, SHUT_RDWR);
    shutdown(conn->serverFd, SHUT_RDWR);
    
    close(conn->clientFd);
    close(conn->serverFd);
    conn->clientFd = -1;
    conn->serverFd = -1;
    delete conn;

}


void workerProcess(int listenFd) {
    //创建epoll
    int epollFd = epoll_create1(0);
    if (epollFd < 0) {
        //Logger::error("Failed to create epoll: " + std::string(strerror(errno)));
        return;
    }
    struct epoll_event ev, events[MAX_EVENTS];

    ev.events = EPOLLIN; //监听可读事件
    ev.data.fd = listenFd;
    
    if(epoll_ctl(epollFd, EPOLL_CTL_ADD, listenFd, &ev) < 0){
        //Logger::error("Failed to add listenFd to epoll: " + std::string(strerror(errno)));
        return;
    }

    unsigned char key[AES_KEY_SIZE] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
                                     0x39,0x30,0x61,0x62,0x63,0x64,0x65,0x66};

    std::map<int, Connection*> connections;

    while (true) {
        int ready = epoll_wait(epollFd, events, MAX_EVENTS, -1);
        if (ready < 0) {
            if (errno == EINTR) continue;  // 被信号中断，继续等待
            //Logger::error("Epoll wait error: " + std::string(strerror(errno)));
            break;
        }

        for (int i = 0; i < ready; i++) {
            int currentFd = events[i].data.fd;
            
            if (currentFd == listenFd) {
                struct sockaddr_in clientAddr;
                socklen_t clientAddrLen = sizeof(clientAddr);
                int clientFd = accept4(listenFd, (struct sockaddr*)&clientAddr, 
                                     &clientAddrLen, SOCK_NONBLOCK);
                
                if (clientFd < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // 没有更多连接，继续等待
                        continue;
                    }
                    //Logger::error("Accept failed: " + std::string(strerror(errno)));
                    continue;
                }

                // 添加TCP优化选项
                int flag = 1;
                setsockopt(clientFd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
                int sendbuf = 256 * 1024;
                int recvbuf = 256 * 1024;
                setsockopt(clientFd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
                setsockopt(clientFd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));

                Connection* conn = new Connection();
                conn->clientFd = clientFd;
                
                // 连接上游服务器
                conn->serverFd = connectToServer();
                if (conn->serverFd < 0) {
                    //Logger::error("Failed to connect to upstream server");
                    close(clientFd);
                    delete conn;
                    continue;
                }

                // 初始化加密上下文
                if (!conn->crypto.init(key, AES_KEY_SIZE)) {
                    //Logger::error("Failed to initialize crypto context");
                    close(clientFd);
                    close(conn->serverFd);
                    delete conn;
                    continue;
                }

                // 添加到epoll
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = clientFd;
                if (epoll_ctl(epollFd, EPOLL_CTL_ADD, clientFd, &ev) < 0) {
                    //Logger::error("Failed to add client FD to epoll");
                    close(clientFd);
                    close(conn->serverFd);
                    delete conn;
                    continue;
                }

                ev.data.fd = conn->serverFd;
                if (epoll_ctl(epollFd, EPOLL_CTL_ADD, conn->serverFd, &ev) < 0) {
                    //Logger::error("Failed to add server FD to epoll");
                    epoll_ctl(epollFd, EPOLL_CTL_DEL, clientFd, NULL);
                    close(clientFd);
                    close(conn->serverFd);
                    delete conn;
                    continue;
                }

                connections[clientFd] = conn;
                connections[conn->serverFd] = conn;
                
                //Logger::info("New connection established: client=" + 
                        //    Logger::toString(clientFd) + ", server=" + 
                        //    Logger::toString(conn->serverFd));
            } else {
                auto it = connections.find(currentFd);
                if (it == connections.end()) {
                    //Logger::error("No connection found for FD: " + Logger::toString(currentFd));
                    epoll_ctl(epollFd, EPOLL_CTL_DEL, currentFd, NULL);
                    close(currentFd);
                    continue;
                }

                Connection* conn = it->second;
                if (currentFd == conn->clientFd) {
                    forwardDataNoCopy(conn, currentFd, conn->serverFd, false, epollFd);
                } else {
                    forwardDataNoCopy(conn, currentFd, conn->clientFd, true, epollFd);
                }
            }
        }

        // 清理已关闭的连接
        auto it = connections.begin();
        while (it != connections.end()) {
            if (it->second->clientFd == -1 || it->second->serverFd == -1) {
                Connection* conn = it->second;
                //Logger::info("Cleaning up connection: client=" + 
                        //    Logger::toString(conn->clientFd) + ", server=" + 
                        //    Logger::toString(conn->serverFd));
                delete conn;
                it = connections.erase(it);
            } else {
                ++it;
            }
        }
    }

    // 清理所有连接
    for (auto& pair : connections) {
        Connection* conn = pair.second;
        close(conn->clientFd);
        close(conn->serverFd);
        delete conn;
    }
    connections.clear();
    close(epollFd);
}

// 修改 main 函数，添加命令行参数解析
void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [-l log_level] [-h] [-i target_ip] [-p target_port]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -l log_level   Set log level (default: 2)" << std::endl;
    std::cout << "    0 - ERROR only" << std::endl;
    std::cout << "    1 - ERROR and WARN" << std::endl;
    std::cout << "    2 - ERROR, WARN, and INFO" << std::endl;
    std::cout << "    3 - ERROR, WARN, INFO, and DEBUG" << std::endl;
    std::cout << "  -i target_ip   Set target server IP (default: 127.0.0.1)" << std::endl;
    std::cout << "  -p target_port Set target server port (default: 9000)" << std::endl;
    std::cout << "  -h             Show this help message" << std::endl;
}

int main(int argc, char* argv[]) {
    // 解析命令行参数
    int opt;
    while ((opt = getopt(argc, argv, "l:i:p:h")) != -1) {
        switch (opt) {
            case 'l':
                {
                    int level = std::atoi(optarg);
                    if (level >= LOG_ERROR && level <= LOG_DEBUG) {
                        Logger::setLevel(static_cast<LogLevel>(level));
                    } else {
                        //Logger::error("Invalid log level: " + std::to_string(level));
                        printUsage(argv[0]);
                        return 1;
                    }
                }
                break;
            case 'i':
                target_ip = optarg;
                break;
            case 'p':
                {
                    int port = std::atoi(optarg);
                    if (port > 0 && port < 65536) {
                        target_port = port;
                    } else {
                        //Logger::error("Invalid port number: " + std::to_string(port));
                        printUsage(argv[0]);
                        return 1;
                    }
                }
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    //Logger::info("Starting proxy with target server: " + target_ip + ":" + Logger::toString(target_port));

    signal(SIGCHLD, SIG_IGN);  // 避免僵尸进程

    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    int socket_opt = 1;

    // 设置TCP缓冲区大小
    int sendbuf = 256 * 1024;  // 256KB
    int recvbuf = 256 * 1024;  // 256KB
    setsockopt(listenFd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
    setsockopt(listenFd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));

    //设置socket选项
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &socket_opt, sizeof(socket_opt));

    int flag = 1;
    setsockopt(listenFd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PROXY_PORT);

    bind(listenFd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listenFd, SOMAXCONN);
    setNonBlocking(listenFd);

    //Logger::info("Proxy server listening on port " + Logger::toString(PROXY_PORT));

    // 创建多个子进程
    for (int i = 0; i < WORKER_COUNT; i++) {
        pid_t pid = fork();
        if (pid == 0) {  // 子进程
            workerProcess(listenFd);
            exit(0);
        }
    }

    // 父进程等待子进程
    while (true) {
        pause();
    }

    close(listenFd);
    return 0;
}
