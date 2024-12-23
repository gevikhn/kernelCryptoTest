#include "crypto.h"
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE    (0x01)
#endif
#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE    (0x04)
#endif

CryptoContext::CryptoContext() : tfmfd_(-1), encrypt_opfd_(-1), decrypt_opfd_(-1) {}

CryptoContext::~CryptoContext() {
    if (encrypt_opfd_ >= 0) close(encrypt_opfd_);
    if (decrypt_opfd_ >= 0) close(decrypt_opfd_);
    if (tfmfd_ >= 0) close(tfmfd_);
}

bool CryptoContext::init(const unsigned char* key, size_t key_size) {
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "skcipher",
        .salg_name = "ecb(aes)"
    };

    tfmfd_ = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tfmfd_ < 0) return false;

    if (bind(tfmfd_, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(tfmfd_);
        return false;
    }

    if (setsockopt(tfmfd_, SOL_ALG, ALG_SET_KEY, key, key_size) < 0) {
        close(tfmfd_);
        return false;
    }

    return setupOperation(encrypt_opfd_, ALG_OP_ENCRYPT) && 
           setupOperation(decrypt_opfd_, ALG_OP_DECRYPT);
}

bool CryptoContext::setupOperation(int& opfd, __u32 op) {
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(4)] = {0};
    
    opfd = accept(tfmfd_, NULL, 0);
    if (opfd < 0) return false;

    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(4);
    *(__u32 *)CMSG_DATA(cmsg) = op;

    if (sendmsg(opfd, &msg, MSG_MORE) < 0) {
        close(opfd);
        return false;
    }

    return true;
}

ssize_t CryptoContext::encrypt(int in_fd, int out_fd, size_t len) {
    return splice(in_fd, NULL, encrypt_opfd_, NULL, len, SPLICE_F_MORE | SPLICE_F_MOVE) &&
           splice(encrypt_opfd_, NULL, out_fd, NULL, len, SPLICE_F_MORE | SPLICE_F_MOVE);
}

ssize_t CryptoContext::decrypt(int in_fd, int out_fd, size_t len) {
    return splice(in_fd, NULL, decrypt_opfd_, NULL, len, SPLICE_F_MORE | SPLICE_F_MOVE) &&
           splice(decrypt_opfd_, NULL, out_fd, NULL, len, SPLICE_F_MORE | SPLICE_F_MOVE);
} 