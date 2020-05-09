#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <sys/time.h>

#define UNIX_UDP_SOCKET_PATH "/run/log.socket"
#define INET_TCP_SOCKET_PORT 3301

#define MAX_TAG_LEN 20
#define MAX_LINE_LEN 1024

typedef struct __attribute__((packed)) {
    struct timeval timestamp;
    char tag[MAX_TAG_LEN + 1];
    char line[MAX_LINE_LEN + 1];
} logger_message_t;

#endif
