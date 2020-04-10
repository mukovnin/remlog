#include "common.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s TAG\n", argv[0]);
        return EXIT_FAILURE;
    }

    int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy_safe(addr.sun_path, UNIX_UDP_SOCKET_PATH, sizeof(addr.sun_path));
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect");
        return EXIT_FAILURE;
    }

    logger_message_t msg;
    strcpy_safe(msg.tag, argv[1], sizeof(msg.tag));

    int i = 0;
    while (1) {
        int c = getchar();
        if (c != EOF && c != '\n')
            msg.line[i++] = c;
        if (c == EOF || c == '\n' || i == sizeof(msg.line) - 1) {
            if (i) {
                msg.line[i]   = '\0';
                msg.timestamp = current_time_us();
                int ret, len = sizeof(msg) - sizeof(msg.line) + i + 1;
                if ((ret = write(sockfd, &msg, len)) != len) {
                    perror(ret == -1 ? "failed write" : "partial write");
                    close(sockfd);
                    return EXIT_FAILURE;
                }
            }
            if (c == EOF)
                break;
            i = 0;
        }
    }

    close(sockfd);
    return EXIT_SUCCESS;
}
