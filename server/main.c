#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "logbuf.h"
#include "utils.h"

#define MAX_LOGS_COUNT 1000
#define LOG_INITIAL_CAPACITY 1024
#define DEFAULT_LOG_MAX_SIZE 10240
#define MAX_CLIENT_MSG_SIZE 1024
#define RULES_FILE "/etc/logserver.conf"

#define SYSLOG_PERROR(s)                                                       \
    syslog(LOG_ERR, "%s:%d %s: %s", __FUNCTION__, __LINE__, (s),               \
           strerror(errno))

typedef struct rule_t {
    char tag[MAX_TAG_LEN + 1];
    size_t size_limit;
    struct rule_t *next;
} rule_t;

// linked list of rules
static rule_t *rules = NULL;

static void init_rules()
{
    size_t bufsize = 0;
    char *buf      = NULL;
    FILE *f        = fopen(RULES_FILE, "r");
    if (f) {
        char fmt[20];
        snprintf(fmt, sizeof(fmt), "%%%us %%zu", MAX_TAG_LEN);
        while (getline(&buf, &bufsize, f) != -1) {
            rule_t *r = (rule_t *)malloc(sizeof(rule_t));
            if (r) {
                if (sscanf(buf, fmt, &r->tag, &r->size_limit) == 2) {
                    r->next = rules;
                    rules   = r;
                } else {
                    free(r);
                }
            }
        }
        fclose(f);
        free(buf);
    }
}

static const rule_t *find_rule(const char *tag)
{
    rule_t *r = rules;
    while (r) {
        if (strcmp(tag, r->tag) == 0)
            return r;
        r = r->next;
    }
    return NULL;
}

// array of log buffers sorted by tags
static log_buffer_t *logs[MAX_LOGS_COUNT];
static size_t logs_count = 0;

static log_buffer_t *add_log(const char *tag)
{
    if (logs_count == MAX_LOGS_COUNT)
        return NULL;
    const rule_t *rule = find_rule(tag);
    size_t max_size    = rule ? MAX(rule->size_limit, LOG_INITIAL_CAPACITY)
                           : DEFAULT_LOG_MAX_SIZE;
    log_buffer_t *log = log_buffer_create(max_size, LOG_INITIAL_CAPACITY, tag);
    if (!log)
        return NULL;
    size_t i = 0;
    while (i < logs_count && strcmp(log_buffer_tag(logs[i]), tag) < 0)
        ++i;
    if (i < logs_count)
        memmove(logs + i + 1, logs + i, (logs_count - i) * sizeof(logs[0]));
    ++logs_count;
    return (logs[i] = log);
}

static log_buffer_t *find_log(const char *tag)
{
    ssize_t l = 0, r = logs_count - 1, i = -1;
    while (l <= r) {
        ssize_t m = (l + r) / 2;
        int cmp   = strcmp(tag, log_buffer_tag(logs[m]));
        if (cmp < 0) {
            r = m - 1;
        } else if (cmp > 0) {
            l = m + 1;
        } else {
            i = m;
            break;
        }
    }
    return i == -1 ? NULL : logs[i];
}

typedef struct client_t {
    int fd;
    bool subscribed;
    char host[NI_MAXHOST];
    char cmd[MAX_CLIENT_MSG_SIZE];
    char **masks;
    size_t pos, masks_count;
    struct client_t *prev, *next;
} client_t;

// double-linked list of connected clients
static client_t *clients = NULL;

static client_t *add_client(int fd)
{
    client_t *ret = calloc(1, sizeof(client_t));
    if (ret) {
        ret->fd = fd;
        if (clients)
            clients->prev = ret;
        ret->next = clients;
        clients   = ret;
    }
    return ret;
}

static void remove_client(client_t *c)
{
    client_t *prev = c->prev, *next = c->next;
    if (prev)
        prev->next = next;
    if (next)
        next->prev = prev;
    if (!prev)
        clients = next;
    for (size_t i = 0; i < c->masks_count; ++i)
        free(c->masks[i]);
    free(c->masks);
    free(c);
}

static bool matches_any_mask(const client_t *c, const char *tag)
{
    for (size_t i = 0; i < c->masks_count; ++i)
        if (matches_mask(tag, c->masks[i]))
            return true;
    return false;
}

static bool send_whole_buffer(int sockfd, const char *buf, size_t bufsize)
{
    while (bufsize) {
        ssize_t res = write(sockfd, buf, bufsize);
        if (res < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                SYSLOG_PERROR("write");
                return false;
            }
            continue;
        }
        bufsize -= res;
        buf += res;
    }
    return true;
}

static bool send_log_message(int sockfd, const struct timeval *time,
                             const char *tag, const char *msg)
{
    char buf[MAX_TAG_LEN + MAX_LINE_LEN + 50];
    struct tm *tm = gmtime(&time->tv_sec);
    if (tm) {
        size_t n = strftime(buf, 20, "%d.%m.%Y %H:%M:%S", tm);
        if (n > 0 && n < sizeof(buf)) {
            int r =
                snprintf(buf + n, sizeof(buf) - n, ".%06lu  |  %20s  |  %s\r\n",
                         time->tv_usec, tag, msg);
            return r > 0 && send_whole_buffer(sockfd, buf, (size_t)(n + r + 1));
        }
    }
    return false;
}

static void send_buffered_logs(client_t *c, struct timeval *since)
{
    struct {
        log_buffer_t *b;
        log_buffer_entry_t *e;
    } filtered_logs[MAX_LOGS_COUNT];
    size_t f_count = 0;
    for (size_t i = 0; i < logs_count; ++i) {
        log_buffer_t *log = logs[i];
        if (matches_any_mask(c, log_buffer_tag(log))) {
            filtered_logs[f_count].b = log;
            filtered_logs[f_count].e = log_buffer_oldest_entry(log, since);
            ++f_count;
        }
    }
    while (1) {
        ssize_t oldest = -1;
        for (size_t i = 0; i < f_count; ++i) {
            log_buffer_entry_t *e = filtered_logs[i].e;
            if (e &&
                (oldest == -1 ||
                 timercmp(log_entry_timestamp(e),
                          log_entry_timestamp(filtered_logs[oldest].e), <)))
                oldest = i;
        }
        if (oldest == -1)
            break;
        log_buffer_t *b       = filtered_logs[oldest].b;
        log_buffer_entry_t *e = filtered_logs[oldest].e;
        send_log_message(c->fd, log_entry_timestamp(e), log_buffer_tag(b),
                         log_entry_message(e));
        filtered_logs[oldest].e = log_buffer_next_entry(b, e);
    };
}

static void process_log_messages(int sock)
{
    logger_message_t msg;
    while (recv(sock, &msg, sizeof(msg), 0) != -1) {
        log_buffer_t *log;
        struct timeval t = msg.timestamp;
        const char *tag = msg.tag, *line = msg.line;
        if ((log = find_log(tag)) || (log = add_log(tag)))
            log_buffer_add(log, &t, line);
        for (client_t *c = clients; c; c = c->next)
            if (c->subscribed && matches_any_mask(c, tag))
                send_log_message(c->fd, &t, tag, line);
    }
}

static void process_pending_connections(int sock, int epollfd)
{
    const char *hello = "Type 'help' to list available commands.\r\n";
    int fd;
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    while ((fd = accept(sock, (struct sockaddr *)&addr, &addr_len)) != -1) {
        int f = fcntl(fd, F_GETFL);
        if (f != -1 && fcntl(fd, F_SETFL, f | O_NONBLOCK) != -1) {
            client_t *c = add_client(fd);
            if (c) {
                struct epoll_event ev;
                ev.data.ptr = c;
                ev.events   = EPOLLIN | EPOLLRDHUP | EPOLLET;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
                    SYSLOG_PERROR("epoll_ctl");
                    remove_client(c);
                    close(fd);
                } else {
                    if (getnameinfo((struct sockaddr *)&addr, addr_len, c->host,
                                    sizeof(c->host), NULL, 0,
                                    NI_NUMERICHOST) == -1)
                        strcpy_safe(c->host, "[unknown]", sizeof(c->host));
                    syslog(LOG_INFO, "accept connection: %s", c->host);
                    send_whole_buffer(fd, hello, strlen(hello) + 1);
                }
            } else {
                close(fd);
            }
        } else {
            SYSLOG_PERROR("fcntl");
            close(fd);
        }
    }
}

static void process_current_command(client_t *c)
{
    const char *help =
        "AVAILABLE COMMANDS:\r\n"
        " help\r\n"
        " list\r\n"
        " get SERVICES [TIME]\r\n"
        " subscribe SERVICES [TIME]\r\n"
        " unsubscribe\r\n"
        "where SERVICES is a comma separated list of names (masks)\r\n"
        "      TIME has the form HH:MM:SS (i.e. 2:0:0 means 'last 2 hours')\r\n"
        "EXAMPLES:\r\n"
        " get *api*,redis 0:10:0\r\n"
        " subscribe wpa_supplicant,connman 0:5:0\r\n"
        " subscribe *\r\n";
    const char *error = "[error]\r\n";
    const char *delim = " \r\n";
    char *tokens[4]   = {strtok(c->cmd, delim)};
    for (size_t i = 1; i < sizeof(tokens) / sizeof(tokens[0]); ++i)
        tokens[i] = strtok(NULL, delim);
    if (!tokens[0])
        return;
    if (strcmp(tokens[0], "help") == 0) {
        if (tokens[1])
            goto err;
        send_whole_buffer(c->fd, help, strlen(help) + 1);
    } else if (strcmp(tokens[0], "list") == 0) {
        if (tokens[1])
            goto err;
        for (size_t i = 0; i < logs_count; ++i) {
            char buf[MAX_TAG_LEN + 2];
            int r =
                snprintf(buf, sizeof(buf), "%s\r\n", log_buffer_tag(logs[i]));
            if (r > 0 && r < sizeof(buf))
                send_whole_buffer(c->fd, buf, (size_t)r + 1);
        }
    } else if (strcmp(tokens[0], "get") == 0 ||
               strcmp(tokens[0], "subscribe") == 0) {
        if (!tokens[1] || tokens[3])
            goto err;
        for (size_t i = 0; i < c->masks_count; ++i)
            free(c->masks[i]);
        free(c->masks);
        c->masks_count   = 0;
        c->masks         = NULL;
        const char *mask = strtok(tokens[1], ",");
        while (mask) {
            c->masks =
                realloc(c->masks, (++c->masks_count) * sizeof(c->masks[0]));
            c->masks[c->masks_count - 1] = strdup(mask);
            mask                         = strtok(NULL, ",");
        }
        if (!c->masks)
            goto err;
        struct timeval since = {0, 0};
        if (tokens[2]) {
            struct tm diff;
            if (!strptime(tokens[2], "%T", &diff))
                goto err;
            struct timeval now = {0, 0};
            gettimeofday(&now, NULL);
            struct tm *tm = localtime(&now.tv_sec);
            if (!tm)
                goto err;
            tm->tm_hour -= diff.tm_hour;
            tm->tm_min -= diff.tm_min;
            tm->tm_sec -= diff.tm_sec;
            time_t t = mktime(tm);
            if (t == (time_t)-1)
                goto err;
            since = (struct timeval){t, now.tv_usec};
        }
        send_buffered_logs(c, &since);
        c->subscribed = tokens[0][0] == 's';
    } else if (strcmp(tokens[0], "unsubscribe") == 0) {
        if (tokens[1])
            goto err;
        c->subscribed = false;
    } else {
        goto err;
    }
    return;
err:
    send_whole_buffer(c->fd, error, strlen(error) + 1);
}

static bool process_commands(client_t *c)
{
    while (c->pos < sizeof(c->cmd)) {
        char ch;
        ssize_t ret = read(c->fd, &ch, 1);
        if (ret > 0) {
            if (ch == '\n')
                ch = '\0';
            c->cmd[c->pos++] = ch;
            if (!ch) {
                c->pos = 0;
                process_current_command(c);
                return true;
            }
        } else if (!(ret == -1 && errno == EINTR)) {
            return (ret == -1 && errno == EWOULDBLOCK);
        }
    }
    return false;
}

static void free_memory()
{
    while (clients)
        remove_client(clients);
    rule_t *r = rules;
    while (r) {
        rule_t *t = r->next;
        free(r);
        r = t;
    }
    for (size_t i = 0; i < logs_count; ++i)
        log_buffer_free(logs[i]);
}

static int unix_udp_socket()
{
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd == -1) {
        SYSLOG_PERROR("socket");
        return -1;
    }
    if (remove(UNIX_UDP_SOCKET_PATH) == -1 && errno != ENOENT) {
        SYSLOG_PERROR("remove");
        close(fd);
        return -2;
    }
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy_safe(addr.sun_path, UNIX_UDP_SOCKET_PATH, sizeof(addr.sun_path));
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        SYSLOG_PERROR("bind");
        close(fd);
        return -3;
    }
    return fd;
}

static int inet_tcp_socket()
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd == -1) {
        SYSLOG_PERROR("socket");
        return -1;
    }
    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(INET_TCP_SOCKET_PORT);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        SYSLOG_PERROR("bind");
        close(fd);
        return -2;
    }
    if (listen(fd, 10) == -1) {
        SYSLOG_PERROR("listen");
        close(fd);
        return -3;
    }
    return fd;
}

static bool running = true;

static void sighandler(int signum)
{
    running = false;
}

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;

    if (signal(SIGINT, sighandler) == SIG_ERR ||
        signal(SIGTERM, sighandler) == SIG_ERR) {
        perror("signal");
        return ret;
    }

    if (daemon(0, 0) == -1) {
        perror("daemon");
        return ret;
    }

    openlog(argv[0], LOG_NDELAY | LOG_PID, LOG_DAEMON);

    int unix_udp_sock = unix_udp_socket();
    if (unix_udp_sock < 0)
        goto close_udp;
    int inet_tcp_sock = inet_tcp_socket();
    if (inet_tcp_sock < 0)
        goto close_tcp;

    int efd = epoll_create1(0);
    if (efd == -1) {
        SYSLOG_PERROR("epoll_create1");
        goto close_tcp;
    }

    struct epoll_event ev;

    ev.data.ptr = &unix_udp_sock;
    ev.events   = EPOLLIN | EPOLLET;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, unix_udp_sock, &ev) == -1) {
        SYSLOG_PERROR("epoll_ctl");
        goto close_epoll;
    }

    ev.data.ptr = &inet_tcp_sock;
    ev.events   = EPOLLIN | EPOLLET;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, inet_tcp_sock, &ev) == -1) {
        SYSLOG_PERROR("epoll_ctl");
        goto close_epoll;
    }

    init_rules();

    syslog(LOG_INFO, "server started");

    while (running) {
        struct epoll_event events[100];
        int ev_count =
            epoll_wait(efd, events, sizeof(events) / sizeof(events[0]), -1);
        if (ev_count == -1 && errno != EINTR) {
            SYSLOG_PERROR("epoll_wait");
            goto free_mem;
        }
        for (int i = 0; i < ev_count; ++i) {
            ev = events[i];
            if (ev.data.ptr == &unix_udp_sock) {
                if (ev.events == EPOLLIN) {
                    process_log_messages(unix_udp_sock);
                } else {
                    syslog(LOG_ERR,
                           "unexpected epoll events (unix socket): 0x%x",
                           ev.events);
                    goto free_mem;
                }
            } else if (ev.data.ptr == &inet_tcp_sock) {
                if (ev.events == EPOLLIN) {
                    process_pending_connections(inet_tcp_sock, efd);
                } else {
                    syslog(LOG_ERR,
                           "unexpected epoll events (inet tcp socket): 0x%x",
                           ev.events);
                    goto free_mem;
                }
            } else {
                client_t *c = (client_t *)ev.data.ptr;
                if (ev.events != EPOLLIN || !process_commands(c)) {
                    if (epoll_ctl(efd, EPOLL_CTL_DEL, c->fd, NULL) == -1)
                        SYSLOG_PERROR("epoll_ctl");
                    syslog(LOG_INFO, "remove connection: %s", c->host);
                    close(c->fd);
                    remove_client(c);
                }
            }
        }
    }

    if (!running)
        syslog(LOG_INFO, "terminated by a signal");

    ret = EXIT_SUCCESS;

free_mem:
    free_memory();
close_epoll:
    close(efd);
close_tcp:
    close(inet_tcp_sock);
close_udp:
    close(unix_udp_sock);

    syslog(LOG_INFO, "exit");

    closelog();

    return ret;
}
