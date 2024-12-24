#include <iostream>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <errno.h>
#include "crypto.h"
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192
#define CLIENT_PORT 10800
#define PROXY_PORT 8888
#define BLOCK_SIZE 16

uint64_t total_received_from_proxy = 0;
uint64_t total_sent_to_client = 0;

struct Connection {
    int clientFd;      // 应用程序连接
    int proxyFd;       // 代理连接
    CryptoContext crypto;
    bool connected;    // 是否已连接到代理
    std::vector<char> remaining_data;  // 每个连接独立的缓冲区
};

void setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// 连接到代理服务器
int connectToProxy() {
    int proxyFd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in proxyAddr;
    memset(&proxyAddr, 0, sizeof(proxyAddr));
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(PROXY_PORT);
    inet_pton(AF_INET, "192.168.2.203", &proxyAddr.sin_addr);

    if (connect(proxyFd, (struct sockaddr*)&proxyAddr, sizeof(proxyAddr)) < 0) {
        std::cerr << "Failed to connect to proxy: " << strerror(errno) << std::endl;
        close(proxyFd);
        return -1;
    }

    setNonBlocking(proxyFd);
    return proxyFd;
}

// 添加 HTTP 代理相关的函数
void processHttpRequest(Connection* conn, const char* buffer, size_t n) {
    // 解析 HTTP 请求的第一行，获取目标 URL
    std::string request(buffer, n);
    size_t first_line_end = request.find("\r\n");
    if (first_line_end == std::string::npos) {
        std::cerr << "Invalid HTTP request" << std::endl;
        return;
    }

    // 修改 HTTP 请求
    std::string first_line = request.substr(0, first_line_end);
    size_t first_space = first_line.find(" ");
    size_t second_space = first_line.find(" ", first_space + 1);
    if (first_space == std::string::npos || second_space == std::string::npos) {
        std::cerr << "Invalid HTTP request line" << std::endl;
        return;
    }

    // 提取原始 URL 并修改请求
    std::string method = first_line.substr(0, first_space);
    std::string url = first_line.substr(first_space + 1, second_space - first_space - 1);
    std::string version = first_line.substr(second_space + 1);

    // 移除 "http://host:port" 部分
    size_t path_start = url.find("/", 7);  // 跳过 "http://"
    if (path_start == std::string::npos) {
        path_start = url.length();
    }

    // 构建新的请求
    std::string new_request = method + " " + url.substr(path_start) + " " + version + "\r\n";
    new_request += request.substr(first_line_end + 2);  // 添加剩余的请求头

    // 加密并发送修改后的请求
    size_t padding_len = BLOCK_SIZE - (new_request.length() % BLOCK_SIZE);
    size_t total_len = new_request.length() + padding_len;
    std::vector<char> padded_data(total_len);
    
    memcpy(padded_data.data(), new_request.c_str(), new_request.length());
    for (size_t i = new_request.length(); i < total_len; i++) {
        padded_data[i] = padding_len;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        std::cerr << "Failed to create pipe" << std::endl;
        return;
    }

    ssize_t written = write(pipefd[1], padded_data.data(), total_len);
    close(pipefd[1]);

    if (written != total_len) {
        std::cerr << "Failed to write to pipe" << std::endl;
        close(pipefd[0]);
        return;
    }

    int outpipefd[2];
    if (pipe(outpipefd) < 0) {
        std::cerr << "Failed to create output pipe" << std::endl;
        close(pipefd[0]);
        return;
    }

    conn->crypto.encrypt(pipefd[0], outpipefd[1], total_len);
    close(pipefd[0]);
    close(outpipefd[1]);

    char encrypted[BUFFER_SIZE];
    ssize_t enc_len = read(outpipefd[0], encrypted, BUFFER_SIZE);
    close(outpipefd[0]);

    if (enc_len > 0) {
        size_t total_sent = 0;
        while (total_sent < enc_len) {
            ssize_t sent = write(conn->proxyFd, encrypted + total_sent, enc_len - total_sent);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    fd_set write_fds;
                    FD_ZERO(&write_fds);
                    FD_SET(conn->proxyFd, &write_fds);

                    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
                    int ready = select(conn->proxyFd + 1, NULL, &write_fds, NULL, &tv);
                    
                    if (ready > 0) continue;
                    std::cerr << "Write timeout" << std::endl;
                    return;
                }
                std::cerr << "Write error: " << strerror(errno) << std::endl;
                return;
            }
            total_sent += sent;
        }
        std::cout << "Sent " << total_sent << " encrypted bytes to proxy" << std::endl;
    }
}

// 修改 forwardData 函数
void forwardData(Connection* conn, int fromFd, int toFd, bool encrypt, int epollFd) {
    char buffer[BUFFER_SIZE];
    size_t total_sent = 0;
    
    while (true) {
        ssize_t n = read(fromFd, buffer, sizeof(buffer));
        
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;  // 等待下次事件
            }
            std::cerr << "Read error: " << strerror(errno) << std::endl;
            goto close_connection;
        } else if (n == 0) {
            // 在关闭连接前处理剩余数据
            if (!conn->remaining_data.empty() && fromFd == conn->proxyFd) {
                std::cout << "Processing remaining " << conn->remaining_data.size() 
                         << " bytes before closing" << std::endl;

                // 确保处理所有剩余数据，即使不是BLOCK_SIZE的整数倍
                while (!conn->remaining_data.empty()) {
                    // 计算本次处理的数据大小
                    size_t process_size = conn->remaining_data.size();
                    if (process_size % BLOCK_SIZE != 0) {
                        std::cerr << "Invalid remaining data size: " << process_size << std::endl;
                        goto close_connection;
                    }

                    if (process_size > BUFFER_SIZE) {
                        process_size = (BUFFER_SIZE / BLOCK_SIZE) * BLOCK_SIZE;
                    }

                    int pipefd[2];
                    if (pipe(pipefd) < 0) {
                        std::cerr << "Failed to create pipe for remaining data" << std::endl;
                        goto close_connection;
                    }

                    ssize_t written = write(pipefd[1], conn->remaining_data.data(), process_size);
                    close(pipefd[1]);

                    if (written != process_size) {
                        std::cerr << "Failed to write remaining data to pipe" << std::endl;
                        close(pipefd[0]);
                        goto close_connection;
                    }

                    int outpipefd[2];
                    if (pipe(outpipefd) < 0) {
                        std::cerr << "Failed to create output pipe for remaining data" << std::endl;
                        close(pipefd[0]);
                        goto close_connection;
                    }

                    conn->crypto.decrypt(pipefd[0], outpipefd[1], process_size);
                    close(pipefd[0]);
                    close(outpipefd[1]);

                    char decrypted[BUFFER_SIZE];
                    ssize_t dec_len = read(outpipefd[0], decrypted, BUFFER_SIZE);
                    close(outpipefd[0]);

                    //解除pkcs7填充
                    size_t padding_len = decrypted[dec_len - 1];
                    dec_len -= padding_len;

                    if (dec_len > 0) {
                        ssize_t sent = write(conn->clientFd, decrypted, dec_len);
                        if (sent > 0) {
                            std::cout << "Sent final " << sent << " decrypted bytes" << std::endl;
                        } else if (sent < 0) {
                            std::cerr << "Failed to send decrypted data: " << strerror(errno) << std::endl;
                            goto close_connection;
                        }
                    }

                    // 从缓冲区移除已处理的数据
                    conn->remaining_data.erase(conn->remaining_data.begin(), 
                                            conn->remaining_data.begin() + process_size);
                }
            }
            goto close_connection;
        }

        std::cout << "Read " << n << " bytes from fd " << fromFd << std::endl;

        if (fromFd == conn->clientFd) {
            // 从客户端收到的数据需要加密
            processHttpRequest(conn, buffer, n);
        } else {
            total_received_from_proxy += n;
            std::cout << "Total received from proxy: " << total_received_from_proxy << std::endl;

            // 将数据添加到缓冲区
            conn->remaining_data.insert(conn->remaining_data.end(), buffer, buffer + n);

            // 处理完整的数据块
            while (conn->remaining_data.size() >= BLOCK_SIZE) {
                // 计算可以处理的数据大小（必须是块大小的倍数）
                size_t process_size = conn->remaining_data.size();
                // 确保不超过缓冲区大小
                if (process_size > BUFFER_SIZE) {
                    process_size = (BUFFER_SIZE / BLOCK_SIZE) * BLOCK_SIZE;
                }

                int pipefd[2];
                if (pipe(pipefd) < 0) {
                    std::cerr << "Failed to create pipe" << std::endl;
                    goto close_connection;
                }

                ssize_t written = write(pipefd[1], conn->remaining_data.data(), process_size);
                close(pipefd[1]);

                if (written != process_size) {
                    std::cerr << "Failed to write to pipe" << std::endl;
                    close(pipefd[0]);
                    goto close_connection;
                }

                int outpipefd[2];
                if (pipe(outpipefd) < 0) {
                    std::cerr << "Failed to create output pipe" << std::endl;
                    close(pipefd[0]);
                    goto close_connection;
                }

                conn->crypto.decrypt(pipefd[0], outpipefd[1], process_size);
                close(pipefd[0]);
                close(outpipefd[1]);

                char decrypted[BUFFER_SIZE];
                ssize_t dec_len = read(outpipefd[0], decrypted, BUFFER_SIZE);
                close(outpipefd[0]);
                //解除pkcs7填充
                size_t padding_len = decrypted[dec_len - 1];
                dec_len -= padding_len;

                if (dec_len > 0) {
                    // 使用循环确保所有数据都被发送
                    size_t block_sent = 0;
                    while (block_sent < dec_len) {
                        ssize_t sent = write(conn->clientFd, decrypted + block_sent, dec_len - block_sent);
                        total_sent_to_client += sent;
                        std::cout << "Total sent to client: " << total_sent_to_client << std::endl;
                        if (sent < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                // 等待可写
                                fd_set write_fds;
                                FD_ZERO(&write_fds);
                                FD_SET(conn->clientFd, &write_fds);
                                struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
                                int ready = select(conn->clientFd + 1, NULL, &write_fds, NULL, &tv);
                                if (ready > 0) continue;
                                std::cerr << "Write timeout" << std::endl;
                                goto close_connection;
                            }
                            std::cerr << "Write error: " << strerror(errno) << std::endl;
                            goto close_connection;
                        }
                        block_sent += sent;
                    }
                    total_sent += block_sent;
                    std::cout << "Sent " << block_sent << " decrypted bytes to client" << std::endl;
                }

                // 从缓冲区移除已处理的数据
                conn->remaining_data.erase(conn->remaining_data.begin(), 
                                         conn->remaining_data.begin() + process_size);
            }
        }

    }

close_connection:
    std::cout << "Closing connection" << std::endl;
    epoll_ctl(epollFd, EPOLL_CTL_DEL, conn->clientFd, NULL);
    epoll_ctl(epollFd, EPOLL_CTL_DEL, conn->proxyFd, NULL);
    
    // 确保所有数据都被发送
    if (fromFd == conn->proxyFd) {
        shutdown(conn->clientFd, SHUT_WR);
        char temp[1024];
        while (read(conn->clientFd, temp, sizeof(temp)) > 0);
    } else {
        shutdown(conn->proxyFd, SHUT_WR);
        char temp[1024];
        while (read(conn->proxyFd, temp, sizeof(temp)) > 0);
    }
    
    close(conn->clientFd);
    close(conn->proxyFd);
    delete conn;
}

int main() {
    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(CLIENT_PORT);

    bind(listenFd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listenFd, SOMAXCONN);
    setNonBlocking(listenFd);

    std::cout << "Client listening on port " << CLIENT_PORT << std::endl;

    int epollFd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];

    ev.events = EPOLLIN;
    ev.data.fd = listenFd;
    epoll_ctl(epollFd, EPOLL_CTL_ADD, listenFd, &ev);

    unsigned char key[AES_KEY_SIZE] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
                                     0x39,0x30,0x61,0x62,0x63,0x64,0x65,0x66};

    std::map<int, Connection*> connections;

    while (true) {
        int ready = epoll_wait(epollFd, events, MAX_EVENTS, -1);
        if (ready < 0) continue;

        for (int i = 0; i < ready; i++) {
            int currentFd = events[i].data.fd;
            
            if (currentFd == listenFd) {
                struct sockaddr_in clientAddr;
                socklen_t clientAddrLen = sizeof(clientAddr);
                int clientFd = accept(listenFd, (struct sockaddr*)&clientAddr, &clientAddrLen);
                
                if (clientFd < 0) continue;

                setNonBlocking(clientFd);

                Connection* conn = new Connection();
                conn->clientFd = clientFd;
                conn->proxyFd = connectToProxy();
                
                if (conn->proxyFd < 0) {
                    delete conn;
                    close(clientFd);
                    continue;
                }

                conn->crypto.init(key, AES_KEY_SIZE);
                conn->connected = true;

                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = clientFd;
                epoll_ctl(epollFd, EPOLL_CTL_ADD, clientFd, &ev);

                ev.data.fd = conn->proxyFd;
                epoll_ctl(epollFd, EPOLL_CTL_ADD, conn->proxyFd, &ev);

                connections[clientFd] = conn;
                connections[conn->proxyFd] = conn;
            } else {
                auto it = connections.find(currentFd);
                if (it == connections.end()) continue;

                Connection* conn = it->second;
                if (currentFd == conn->clientFd) {
                    // 从客户端（wget）收到数据，传入 epollFd
                    forwardData(conn, conn->clientFd, conn->proxyFd, true, epollFd);
                } else {
                    // 从代理收到数据，传入 epollFd
                    forwardData(conn, conn->proxyFd, conn->clientFd, false, epollFd);
                }
            }
        }
    }

    close(listenFd);
    return 0;
} 