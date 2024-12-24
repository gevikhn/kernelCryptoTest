#include <iostream>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <thread>
#include <vector>
#include <errno.h>

#define MAX_EVENTS 1024
#define THREAD_COUNT 4
#define BUFFER_SIZE 4096
#define PROXY_PORT 8888
#define TARGET_IP "127.0.0.1"
#define TARGET_PORT 9000

void setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int connectToServer() {
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr = {AF_INET, htons(TARGET_PORT)};
    inet_pton(AF_INET, TARGET_IP, &serverAddr.sin_addr);
    connect(serverFd, (sockaddr*)&serverAddr, sizeof(serverAddr));
    setNonBlocking(serverFd);
    return serverFd;
}

void workerThread(int listenFd) {
    int epollFd = epoll_create1(0);
    epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = listenFd;
    epoll_ctl(epollFd, EPOLL_CTL_ADD, listenFd, &ev);

    while (true) {
        int ready = epoll_wait(epollFd, events, MAX_EVENTS, -1);
        for (int i = 0; i < ready; i++) {
            int fd = events[i].data.fd;
            if (fd == listenFd) {
                int clientFd = accept(listenFd, NULL, NULL);
                int serverFd = connectToServer();
                setNonBlocking(clientFd);
                ev.data.fd = clientFd;
                epoll_ctl(epollFd, EPOLL_CTL_ADD, clientFd, &ev);
                ev.data.fd = serverFd;
                epoll_ctl(epollFd, EPOLL_CTL_ADD, serverFd, &ev);
            } else {
                char buffer[BUFFER_SIZE];
                int n = read(fd, buffer, sizeof(buffer));
                if (n > 0) write(fd, buffer, n);
                else close(fd);
            }
        }
    }
}

int main() {
    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr = {AF_INET, htons(PROXY_PORT), INADDR_ANY};
    bind(listenFd, (sockaddr*)&addr, sizeof(addr));
    listen(listenFd, SOMAXCONN);

    std::vector<std::thread> threads;
    for (int i = 0; i < THREAD_COUNT; i++)
        threads.emplace_back(workerThread, listenFd);

    for (auto& t : threads) t.join();
    close(listenFd);
    return 0;
}
