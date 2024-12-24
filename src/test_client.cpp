#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include "crypto.h"

#define BUFFER_SIZE 4096
#define PROXY_PORT 8888
#define PROXY_IP "127.0.0.1"
#define BLOCK_SIZE 16

// PKCS7填充
std::string pkcs7_padding(const std::string& data) {
    size_t padding_len = BLOCK_SIZE - (data.length() % BLOCK_SIZE);
    std::string padded = data;
    for (size_t i = 0; i < padding_len; i++) {
        padded.push_back(padding_len);
    }
    return padded;
}

// PKCS7去填充
std::string pkcs7_unpadding(const std::string& padded_data) {
    if (padded_data.empty()) return padded_data;
    
    unsigned char last_byte = padded_data[padded_data.length() - 1];
    if (last_byte > BLOCK_SIZE || last_byte == 0) return padded_data;
    
    for (int i = 0; i < last_byte; i++) {
        if (padded_data[padded_data.length() - 1 - i] != last_byte) {
            return padded_data;
        }
    }
    
    return padded_data.substr(0, padded_data.length() - last_byte);
}

void print_hex(const char *label, const unsigned char *data, int len) {
    std::cout << label << ": ";
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    std::cout << std::endl;
}

int main() {
    // 初始化加密上下文
    CryptoContext crypto;
    unsigned char key[AES_KEY_SIZE] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
                                     0x39,0x30,0x61,0x62,0x63,0x64,0x65,0x66};
    if (!crypto.init(key, AES_KEY_SIZE)) {
        std::cerr << "Failed to initialize crypto context" << std::endl;
        return -1;
    }

    // 创建socket
    int clientFd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientFd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // 设置代理服务器地址
    struct sockaddr_in proxyAddr;
    memset(&proxyAddr, 0, sizeof(proxyAddr));
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(PROXY_PORT);
    inet_pton(AF_INET, PROXY_IP, &proxyAddr.sin_addr);

    // 连接到代理服务器
    if (connect(clientFd, (struct sockaddr*)&proxyAddr, sizeof(proxyAddr)) < 0) {
        perror("Connection to proxy failed");
        close(clientFd);
        return -1;
    }

    std::cout << "Connected to proxy server" << std::endl;

    while (true) {
        // 从标准输入读取数据
        std::string input;
        std::cout << "\nEnter message (or 'quit' to exit): ";
        std::getline(std::cin, input);

        if (input == "quit") {
            break;
        }

        // PKCS7填充
        std::string padded_input = pkcs7_padding(input);
        print_hex("Original data", (const unsigned char*)input.c_str(), input.length());
        print_hex("Padded data", (const unsigned char*)padded_input.c_str(), padded_input.length());

        // 创建管道用于加密
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            perror("Pipe creation failed");
            break;
        }

        // 写入待加密数据
        write(pipefd[1], padded_input.c_str(), padded_input.length());
        close(pipefd[1]);

        // 创建管道用于存储加密后的数据
        int encpipefd[2];
        if (pipe(encpipefd) < 0) {
            perror("Encryption pipe creation failed");
            close(pipefd[0]);
            break;
        }

        // 加密数据
        crypto.encrypt(pipefd[0], encpipefd[1], padded_input.length());
        close(pipefd[0]);
        close(encpipefd[1]);

        // 读取加密后的数据
        char encrypted[BUFFER_SIZE];
        ssize_t enc_len = read(encpipefd[0], encrypted, BUFFER_SIZE);
        close(encpipefd[0]);

        // 发送加密后的数据
        ssize_t sent = send(clientFd, encrypted, enc_len, 0);
        if (sent < 0) {
            perror("Send failed");
            break;
        }
        print_hex("Encrypted sent data", (const unsigned char*)encrypted, enc_len);

        // 接收响应
        char buffer[BUFFER_SIZE];
        ssize_t received = recv(clientFd, buffer, sizeof(buffer), 0);
        
        if (received < 0) {
            perror("Receive failed");
            break;
        } else if (received == 0) {
            std::cout << "Server closed connection" << std::endl;
            break;
        }

        print_hex("Encrypted received data", (const unsigned char*)buffer, received);

        // 创建管道用于解密
        if (pipe(pipefd) < 0) {
            perror("Decryption pipe creation failed");
            break;
        }

        // 写入待解密数据
        write(pipefd[1], buffer, received);
        close(pipefd[1]);

        // 创建管道用于存储解密后的数据
        int decpipefd[2];
        if (pipe(decpipefd) < 0) {
            perror("Decryption output pipe creation failed");
            close(pipefd[0]);
            break;
        }

        // 解密数据
        crypto.decrypt(pipefd[0], decpipefd[1], received);
        close(pipefd[0]);
        close(decpipefd[1]);

        // 读取解密后的数据
        char decrypted[BUFFER_SIZE];
        ssize_t dec_len = read(decpipefd[0], decrypted, BUFFER_SIZE);
        close(decpipefd[0]);

        if (dec_len > 0) {
            std::string decrypted_str(decrypted, dec_len);
            std::string unpadded_str = pkcs7_unpadding(decrypted_str);
            print_hex("Decrypted data", (const unsigned char*)decrypted, dec_len);
            std::cout << "Received message: " << unpadded_str << std::endl;
        }
    }

    close(clientFd);
    return 0;
} 