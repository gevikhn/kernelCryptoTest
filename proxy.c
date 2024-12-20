#include <iostream>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <errno.h>
#include <signal.h>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 4096
#define PROXY_PORT 8888
#define TARGET_IP "127.0.0.1"
#define TARGET_PORT 9000
#define WORKER_COUNT 4  // 进程数量

// 设置套接字为非阻塞
void setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// 连接到目标服务器
int connectToServer() {
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, TARGET_IP, &serverAddr.sin_addr);

    setNonBlocking(serverFd);
    if (connect(serverFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        if (errno != EINPROGRESS) {
            perror("Connect to server failed");
            close(serverFd);
            return -1;
        }
    }
    return serverFd;
}

// 数据转发
void forwardData(int fromFd, int toFd) {
    char buffer[BUFFER_SIZE];
    ssize_t n = read(fromFd, buffer, sizeof(buffer));
    if (n > 0) {
        send(toFd, buffer, n, 0);
    } else if (n == 0 || (n < 0 && errno != EAGAIN)) {
        close(fromFd);
        close(toFd);
    }
}

// 子进程事件循环
void workerProcess(int listenFd) {
    int epollFd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];

    ev.events = EPOLLIN;
    ev.data.fd = listenFd;
    epoll_ctl(epollFd, EPOLL_CTL_ADD, listenFd, &ev);

    while (true) {
        int ready = epoll_wait(epollFd, events, MAX_EVENTS, -1);
        for (int i = 0; i < ready; i++) {
            int fd = events[i].data.fd;

            if (fd == listenFd) {
                // 接收新客户端连接
                int clientFd = accept(listenFd, NULL, NULL);
                setNonBlocking(clientFd);

                int serverFd = connectToServer();
                if (serverFd < 0) {
                    close(clientFd);
                    continue;
                }

                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = clientFd;
                epoll_ctl(epollFd, EPOLL_CTL_ADD, clientFd, &ev);

                ev.data.fd = serverFd;
                epoll_ctl(epollFd, EPOLL_CTL_ADD, serverFd, &ev);

                std::cout << "New connection: clientFd=" << clientFd << ", serverFd=" << serverFd << std::endl;
            } else {
                // 数据转发
                forwardData(fd, fd);  // 转发逻辑可优化
            }
        }
    }
}

int main() {
    signal(SIGCHLD, SIG_IGN);  // 避免僵尸进程

    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PROXY_PORT);

    bind(listenFd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listenFd, SOMAXCONN);
    setNonBlocking(listenFd);

    std::cout << "Proxy server listening on port " << PROXY_PORT << std::endl;

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
