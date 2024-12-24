#ifndef CRYPTO_H
#define CRYPTO_H

#include <linux/if_alg.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define AES_KEY_SIZE 16
#define BLOCK_SIZE 16

class CryptoContext {
public:
    CryptoContext();
    ~CryptoContext();
    
    bool init(const unsigned char* key, size_t key_size);
    ssize_t encrypt(int in_fd, int out_fd, size_t len);
    ssize_t decrypt(int in_fd, int out_fd, size_t len);

private:
    int tfmfd_;
    int encrypt_opfd_;
    int decrypt_opfd_;
    bool setupOperation(int& opfd, __u32 op);
};

#endif 