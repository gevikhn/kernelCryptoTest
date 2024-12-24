#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include <string.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

int main(void)
{
  int opfd;
  int tfmfd;
  struct sockaddr_alg sa = {
    .salg_family = AF_ALG,
    .salg_type = "skcipher",
    .salg_name = "ecb(aes)"
  };
  struct msghdr msg = {};
  struct cmsghdr *cmsg;
  char cbuf[CMSG_SPACE(4)] = {0};
  char buf[16];

  struct iovec iov;
  int i;

  tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

  bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));

  setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY,
       "1234567890abcdef", 16);

  opfd = accept(tfmfd, NULL, 0);

  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_ALG;
  cmsg->cmsg_type = ALG_SET_OP;
  cmsg->cmsg_len = CMSG_LEN(4);
  *(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

  iov.iov_base = "hello world!!!!!";
  iov.iov_len = 16;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  sendmsg(opfd, &msg, 0);
  read(opfd, buf, 16);

  for (i = 0; i < 16; i++) {
    printf("%02x", (unsigned char)buf[i]);
  }
  printf("\n");

  close(opfd);
  close(tfmfd);

  return 0;
}