#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include <string.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define AES_KEY_SIZE 16
#define BLOCK_SIZE 16

void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    int opfd, tfmfd;
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "skcipher",
        .salg_name = "ecb(aes)"
    };

    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(4)] = {0};

    struct iovec iov;
    unsigned char plaintext[BLOCK_SIZE] = "hello world!!!!!"; // 明文数据（16字节）
    unsigned char ciphertext[BLOCK_SIZE] = {0};             // 用于存储密文
    unsigned char key[AES_KEY_SIZE] = "1234567890abcdef";   // 16字节AES密钥

    // 1. 创建AF_ALG套接字
    tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tfmfd < 0) {
        perror("socket");
        return -1;
    }

    // 2. 绑定算法到套接字
    if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(tfmfd);
        return -1;
    }

    // 3. 设置AES密钥
    if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, AES_KEY_SIZE) < 0) {
        perror("setsockopt");
        close(tfmfd);
        return -1;
    }

    // 4. 接收操作套接字
    opfd = accept(tfmfd, NULL, 0);
    if (opfd < 0) {
        perror("accept");
        close(tfmfd);
        return -1;
    }

    // 5. 使用 ALG_SET_OP 控制消息设置为加密
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(4);
    *(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

    // 6. 设置输入数据
    iov.iov_base = plaintext;
    iov.iov_len = BLOCK_SIZE;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // 7. 发送明文数据并读取加密结果
    if (sendmsg(opfd, &msg, 0) < 0) {
        perror("sendmsg");
        close(opfd);
        close(tfmfd);
        return -1;
    }

    if (read(opfd, ciphertext, BLOCK_SIZE) < 0) {
        perror("read");
        close(opfd);
        close(tfmfd);
        return -1;
    }

    // 8. 输出明文和密文
    print_hex("Plaintext", plaintext, BLOCK_SIZE);
    print_hex("Ciphertext", ciphertext, BLOCK_SIZE);

    // 9. 关闭套接字
    close(opfd);
    close(tfmfd);

    return 0;
}
