#include "csiebox_common.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bsd/md5.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

void md5(const char* str, size_t len, uint8_t digest[MD5_DIGEST_LENGTH]) {
  MD5_CTX ctx;
  MD5Init(&ctx);
  MD5Update(&ctx, (const uint8_t*)str, len);
  MD5Final(digest, &ctx);
}

int md5_file(const char* path, uint8_t digest[MD5_DIGEST_LENGTH], int fd) {
  if (fd < 0) {
    return 0;
  }
  char buf[4096];
  size_t len;
  MD5_CTX ctx;
  MD5Init(&ctx);
  while ((len = read(fd, buf, 4096)) > 0) {
    MD5Update(&ctx, (const uint8_t*)buf, len);
  }
  MD5Final(digest, &ctx);
  return 1;
}

int recv_message(int conn_fd, void* message, size_t len) {
  if (len == 0) {
    return 0;
  }
  return recv(conn_fd, message, len, MSG_WAITALL) == len;
}

int complete_message_with_header(
  int conn_fd, csiebox_protocol_header* header, void* result) {
  memcpy(result, header->bytes, sizeof(csiebox_protocol_header));
  return recv(conn_fd,
              result + sizeof(csiebox_protocol_header),
              header->req.datalen,
              MSG_WAITALL) == header->req.datalen;
}

int send_message(int conn_fd, void* message, size_t len) {
  if (len == 0) {
    return 0;
  }
  return send(conn_fd, message, len, 0) == len;
}

int get_hash_code(const char* path) {
  struct stat file_stat;
  memset(&file_stat, 0, sizeof(file_stat));
  if (lstat(path, &file_stat) < 0) {
    return 0;
  }
  return (int)file_stat.st_ino;
}
