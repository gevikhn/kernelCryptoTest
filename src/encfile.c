#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#define AES_KEY_SIZE 16
#define BLOCK_SIZE 16
#define BUFFER_SIZE (64 * 1024)  // 每次处理64KB

void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void encrypt_file_afalg(const char *input_file, const char *output_file, const unsigned char *key) {
    int tfmfd, opfd, in_fd, out_fd;
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "skcipher",
        .salg_name = "ecb(aes)"
    };

    unsigned char *input_buffer = malloc(BUFFER_SIZE);
    unsigned char *output_buffer = malloc(BUFFER_SIZE);
    if (!input_buffer || !output_buffer) {
        handle_error("Memory allocation failed");
    }

    // 打开输入和输出文件
    in_fd = open(input_file, O_RDONLY);
    if (in_fd < 0) handle_error("Open input file failed");
    out_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        close(in_fd);
        handle_error("Open output file failed");
    }

    // 创建 AF_ALG 套接字
    tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tfmfd < 0) handle_error("AF_ALG socket creation failed");

    if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(tfmfd);
        handle_error("Bind failed");
    }

    if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, AES_KEY_SIZE) < 0) {
        close(tfmfd);
        handle_error("Set key failed");
    }

    opfd = accept(tfmfd, NULL, 0);
    if (opfd < 0) {
        close(tfmfd);
        handle_error("Accept failed");
    }

    // 批量读取并加密
    ssize_t bytes_read, bytes_written;
    while ((bytes_read = read(in_fd, input_buffer, BUFFER_SIZE)) > 0) {
        // 如果最后一块不足 BLOCK_SIZE，则填充
        if (bytes_read % BLOCK_SIZE != 0) {
            int pad_len = BLOCK_SIZE - (bytes_read % BLOCK_SIZE);
            memset(input_buffer + bytes_read, pad_len, pad_len);
            bytes_read += pad_len;
        }

        struct iovec iov = {
            .iov_base = input_buffer,
            .iov_len = bytes_read
        };

        struct msghdr msg = {
            .msg_iov = &iov,
            .msg_iovlen = 1
        };

        if (sendmsg(opfd, &msg, 0) < 0) {
            handle_error("sendmsg failed");
        }

        if ((bytes_written = read(opfd, output_buffer, bytes_read)) != bytes_read) {
            handle_error("read failed");
        }

        if (write(out_fd, output_buffer, bytes_written) != bytes_written) {
            handle_error("write failed");
        }
    }

    if (bytes_read < 0) handle_error("read failed");

    // 释放资源
    close(opfd);
    close(tfmfd);
    close(in_fd);
    close(out_fd);
    free(input_buffer);
    free(output_buffer);
}

int main() {
    unsigned char key[AES_KEY_SIZE] = "1234567890abcdef";
    encrypt_file_afalg("test.bin", "output.bin", key);
    printf("Encryption completed with AF_ALG.\n");
    return 0;
}
