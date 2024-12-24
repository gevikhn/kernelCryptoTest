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
#include <getopt.h>
#include <netinet/tcp.h>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 65535
#define CLIENT_PORT 10800
#define PROXY_PORT 8888
#define BLOCK_SIZE 16

// 在 Logger 类定义之前添加颜色代码定义
#define COLOR_RESET   "\033[0m"
#define COLOR_ERROR   "\033[1;31m"      // 亮红色
#define COLOR_WARN    "\033[1;33m"      // 亮黄色
#define COLOR_INFO    "\033[1;32m"      // 亮绿色
#define COLOR_DEBUG   "\033[1;36m"      // 亮青色

// 全局变量声明
std::string proxy_ip = "127.0.0.1";  // 默认值
int proxy_port = 8888;               // 默认值

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

// 定义静态成员
LogLevel Logger::currentLevel = LOG_INFO;

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [-l log_level] [-h] [-i proxy_ip] [-p proxy_port]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -l log_level   Set log level (default: 2)" << std::endl;
    std::cout << "    0 - ERROR only" << std::endl;
    std::cout << "    1 - ERROR and WARN" << std::endl;
    std::cout << "    2 - ERROR, WARN, and INFO" << std::endl;
    std::cout << "    3 - ERROR, WARN, INFO, and DEBUG" << std::endl;
    std::cout << "  -i proxy_ip    Set proxy server IP (default: 127.0.0.1)" << std::endl;
    std::cout << "  -p proxy_port  Set proxy server port (default: 8888)" << std::endl;
    std::cout << "  -h             Show this help message" << std::endl;
}

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

    // 添加TCP优化选项
    int flag = 1;
    setsockopt(proxyFd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    int sendbuf = 256 * 1024;
    int recvbuf = 256 * 1024;
    setsockopt(proxyFd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
    setsockopt(proxyFd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));
    
    struct sockaddr_in proxyAddr;
    memset(&proxyAddr, 0, sizeof(proxyAddr));
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(PROXY_PORT);
    inet_pton(AF_INET, proxy_ip.c_str(), &proxyAddr.sin_addr);

    if (connect(proxyFd, (struct sockaddr*)&proxyAddr, sizeof(proxyAddr)) < 0) {
        Logger::error("Failed to connect to proxy: " + std::string(strerror(errno)));
        close(proxyFd);
        return -1;
    }

    setNonBlocking(proxyFd);
    return proxyFd;
}

// 添加 sendAll 函数
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
                    Logger::error("Select error: " + std::string(strerror(errno)));
                    return -1;
                } else if (ready == 0) {
                    Logger::warn("Send timeout");
                    continue;
                }
                // socket 可写，继续发送
                continue;
            }
            Logger::error("Send error: " + std::string(strerror(errno)));
            return -1;
        }
        total_sent += sent;
    }
    return total_sent;
}

// 修改 forwardData 函数
void forwardData(Connection* conn, int fromFd, int toFd, bool encrypt, int epollFd) {
    char buffer[BUFFER_SIZE];
    
    while (true) {
        ssize_t n = read(fromFd, buffer, sizeof(buffer));
        
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;  // 等待下次事件
            }
            Logger::error("Read error: " + std::string(strerror(errno)));
            goto close_connection;
        } else if (n == 0) {
            goto close_connection;
        }

        Logger::debug("Read " + Logger::toString(n) + " bytes from fd " + Logger::toString(fromFd));

        if (encrypt) {
            // 加密数据

            // 添加填充
            std::vector<char> padded_data;
            ssize_t total_len = n;
            if (n % BLOCK_SIZE != 0) {
                size_t padding_len = BLOCK_SIZE - (n % BLOCK_SIZE);
                total_len += padding_len;
                padded_data.resize(total_len);
                memcpy(padded_data.data(), buffer, n);
                for (size_t i = n; i < n + padding_len; i++) {
                    padded_data[i] = padding_len;
                }
            }else{
                // 数据长度是BLOCK_SIZE的整数倍，填充16个16
                total_len += BLOCK_SIZE;
                padded_data.resize(total_len);
                memcpy(padded_data.data(), buffer, n);
                for (size_t i = n; i < total_len; i++) {
                    padded_data[i] = BLOCK_SIZE;
                }   
            }

            int pipefd[2];
            if (pipe(pipefd) < 0) {
                Logger::error("Failed to create pipe");
                goto close_connection;
            }

            ssize_t written = write(pipefd[1], padded_data.data(), total_len);
            close(pipefd[1]);

            if (written != total_len) {
                Logger::error("Failed to write to pipe");
                close(pipefd[0]);
                goto close_connection;
            }

            int outpipefd[2];
            if (pipe(outpipefd) < 0) {
                Logger::error("Failed to create output pipe");
                close(pipefd[0]);
                goto close_connection;
            }

            conn->crypto.encrypt(pipefd[0], outpipefd[1], total_len);
            close(pipefd[0]);
            close(outpipefd[1]);

            char encrypted[BUFFER_SIZE * 2];
            ssize_t enc_len = read(outpipefd[0], encrypted, BUFFER_SIZE * 2);
            close(outpipefd[0]);

            if (enc_len > 0) {
                ssize_t sent = sendAll(toFd, encrypted, enc_len);  // 使用 sendAll 替代 write
                if (sent < 0) {
                    Logger::error("Send failed");
                    goto close_connection;
                }
                Logger::debug("Sent " + Logger::toString(sent) + " encrypted bytes");
            }
        } else {
            // 解密数据，先将数据添加到缓冲区
            conn->remaining_data.insert(conn->remaining_data.end(), buffer, buffer + n);
            
            // 处理完整的数据块
            while (conn->remaining_data.size() >= BLOCK_SIZE) {
                // 计算可以处理的数据大小（必须是BLOCK_SIZE的整数倍）
                size_t process_size = (conn->remaining_data.size() / BLOCK_SIZE) * BLOCK_SIZE;
                
                int pipefd[2];
                if (pipe(pipefd) < 0) {
                    Logger::error("Failed to create pipe");
                    goto close_connection;
                }

                write(pipefd[1], conn->remaining_data.data(), process_size);
                close(pipefd[1]);

                int outpipefd[2];
                if (pipe(outpipefd) < 0) {
                    Logger::error("Failed to create output pipe");
                    close(pipefd[0]);
                    goto close_connection;
                }

                conn->crypto.decrypt(pipefd[0], outpipefd[1], process_size);
                close(pipefd[0]);
                close(outpipefd[1]);

                char decrypted[BUFFER_SIZE];
                ssize_t dec_len = read(outpipefd[0], decrypted, BUFFER_SIZE);
                close(outpipefd[0]);

                if (dec_len > 0) {
                    // 移除填充
                    size_t padding_len = decrypted[dec_len - 1];
                    if (padding_len <= BLOCK_SIZE && padding_len > 0) {
                        dec_len -= padding_len;
                    }

                    ssize_t sent = sendAll(toFd, decrypted, dec_len);  // 使用 sendAll 替代 write
                    if (sent < 0) {
                        Logger::error("Send failed");
                        goto close_connection;
                    }
                    Logger::debug("Sent " + Logger::toString(sent) + " decrypted bytes");
                }

                // 从缓冲区移除已处理的数据
                conn->remaining_data.erase(conn->remaining_data.begin(), 
                                        conn->remaining_data.begin() + process_size);
            }
        }
    }

close_connection:
    Logger::info("Closing connection");
    epoll_ctl(epollFd, EPOLL_CTL_DEL, conn->clientFd, NULL);
    epoll_ctl(epollFd, EPOLL_CTL_DEL, conn->proxyFd, NULL);
    close(conn->clientFd);
    close(conn->proxyFd);
    delete conn;
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
                        Logger::error("Invalid log level: " + std::to_string(level));
                        printUsage(argv[0]);
                        return 1;
                    }
                }
                break;
            case 'i':
                proxy_ip = optarg;
                break;
            case 'p':
                {
                    int port = std::atoi(optarg);
                    if (port > 0 && port < 65536) {
                        proxy_port = port;
                    } else {
                        Logger::error("Invalid port number: " + std::to_string(port));
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

    Logger::info("Starting client with proxy server: " + proxy_ip + ":" + Logger::toString(proxy_port));

    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    int socket_opt = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &socket_opt, sizeof(socket_opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(CLIENT_PORT);

    bind(listenFd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listenFd, SOMAXCONN);
    setNonBlocking(listenFd);

    Logger::info("Client listening on port " + Logger::toString(CLIENT_PORT));

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

                // 添加TCP优化选项
                int flag = 1;
                setsockopt(clientFd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
                int sendbuf = 256 * 1024;
                int recvbuf = 256 * 1024;
                setsockopt(clientFd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
                setsockopt(clientFd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));
                

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