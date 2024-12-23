#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#define BUFFER_SIZE 4096
#define SERVER_PORT 9000

void print_hex(const char *label, const unsigned char *data, int len) {
    std::cout << label << ": ";
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    std::cout << std::endl;
}

int main() {
    signal(SIGPIPE, SIG_IGN);  // 忽略 SIGPIPE 信号

    // 创建服务器socket
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // 设置socket选项
    int opt = 1;
    if (setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        return -1;
    }

    // 绑定地址
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(SERVER_PORT);

    if (bind(serverFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind failed");
        return -1;
    }

    // 监听连接
    if (listen(serverFd, SOMAXCONN) < 0) {
        perror("Listen failed");
        return -1;
    }

    std::cout << "Echo server listening on port " << SERVER_PORT << std::endl;

    while (true) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        
        // 接受新连接
        int clientFd = accept(serverFd, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientFd < 0) {
            perror("Accept failed");
            continue;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        std::cout << "\nNew connection from " << clientIP << ":" << ntohs(clientAddr.sin_port) << std::endl;

        // 处理客户端数据
        while (true) {
            char buffer[BUFFER_SIZE];
            ssize_t received = recv(clientFd, buffer, sizeof(buffer) - 1, 0);
            
            if (received < 0) {
                perror("Receive failed");
                break;
            } else if (received == 0) {
                std::cout << "Client disconnected" << std::endl;
                break;
            }

            buffer[received] = '\0';
            print_hex("Received data", (const unsigned char*)buffer, received);
            std::cout << "Received message: " << buffer << std::endl;

            // 回显数据
            ssize_t sent = send(clientFd, buffer, received, 0);
            if (sent < 0) {
                perror("Send failed");
                break;
            }
            print_hex("Sent data", (const unsigned char*)buffer, sent);
        }

        close(clientFd);
    }

    close(serverFd);
    return 0;
} 