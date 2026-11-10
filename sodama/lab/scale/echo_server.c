/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
 * Copyright (C) 2026 sodama contributors
 */

// M4 规模夹具：epoll 单线程 TCP 回显（支撑 1 万+ 并发空闲/小包连接）。
// 用法：echo_server <port>
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_EV 1024
#define BUF 4096

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 8080;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) || listen(lfd, 4096)) {
        perror("bind/listen");
        return 1;
    }
    set_nonblock(lfd);
    int ep = epoll_create1(0);
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = lfd;
    epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev);
    fprintf(stderr, "echo on :%d\n", port);
    struct epoll_event evs[MAX_EV];

    for (;;) {
        int n = epoll_wait(ep, evs, MAX_EV, -1);
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == lfd) {
                for (;;) {
                    int c = accept4(lfd, NULL, NULL, SOCK_NONBLOCK);
                    if (c < 0) break;
                    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
                    struct epoll_event ce;
                    ce.events = EPOLLIN;
                    ce.data.fd = c;
                    epoll_ctl(ep, EPOLL_CTL_ADD, c, &ce);
                }
                continue;
            }
            char buf[BUF];
            int dead = 0;
            for (;;) {
                ssize_t r = read(fd, buf, sizeof buf);
                if (r > 0) {
                    ssize_t off = 0;
                    while (off < r && !dead) {
                        ssize_t w = write(fd, buf + off, r - off);
                        if (w > 0) {
                            off += w;
                        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            // 回显缓冲满（仅大包场景）：等可写，最多 200ms
                            struct pollfd p = {fd, POLLOUT, 0};
                            if (poll(&p, 1, 200) > 0 && (p.revents & POLLOUT)) continue;
                            dead = 1;
                        } else {
                            dead = 1;
                        }
                    }
                } else if (r == 0) {
                    dead = 1;
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    dead = 1;
                } else {
                    break;
                }
                if (dead) break;
            }
            if (dead) {
                epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
            }
        }
    }
}
