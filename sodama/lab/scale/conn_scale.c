/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
 * Copyright (C) 2026 sodama contributors
 */

// M4 规模基准客户端：并发持有（hold）与连接风暴（churn）。
//
// 用法：
//   conn_scale hold  <host> <port> <n> <seconds>
//   conn_scale churn <host> <port> <seconds>
//
// hold：建立 n 条连接，每条发一次 32B ping 并等待回显（确认 relay 已全链路建立），
//       然后保持 n 秒（期间由外部脚本采样 sodama RSS/线程），最后全部关闭。
// churn：限时循环 connect→ping→echo→close，报完成连接数/秒。
//
// 输出（stdout，单行）：
//   hold ok=<n> fail=<n> setup_s=<..> hold_s=<..>
//   churn conns=<n> wall_s=<..> conn_per_s=<..>
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int connect_to(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// ping→echo：32B 往返，带 5s 超时；成功返回 0
static int ping_echo(int fd) {
    unsigned char out[32], in[32];
    for (int i = 0; i < 32; i++) out[i] = (unsigned char)(i * 7 + 1);
    ssize_t w = write(fd, out, sizeof out);
    if (w != (ssize_t)sizeof out) return -1;
    size_t got = 0;
    double t0 = now_s();
    while (got < sizeof in) {
        struct pollfd p = {fd, POLLIN, 0};
        int pr = poll(&p, 1, 5000);
        if (pr <= 0) return -1;
        ssize_t r = read(fd, in + got, sizeof in - got);
        if (r <= 0) return -1;
        got += (size_t)r;
        if (now_s() - t0 > 5.0) return -1;
    }
    return memcmp(out, in, sizeof out) == 0 ? 0 : -1;
}

static int cmd_hold(const char *host, int port, long n, double hold_secs) {
    int *fds = calloc((size_t)n, sizeof(int));
    if (!fds) return 1;
    long ok = 0, fail = 0;
    double t0 = now_s();
    for (long i = 0; i < n; i++) {
        int fd = connect_to(host, port);
        if (fd < 0 || ping_echo(fd) != 0) {
            if (fd >= 0) close(fd);
            fail++;
            if (fail <= 5) fprintf(stderr, "conn %ld 失败（errno=%d）\n", i, errno);
            continue;
        }
        fds[ok++] = fd;
    }
    double setup = now_s() - t0;
    fprintf(stderr, "setup 完成：ok=%ld fail=%ld %.2fs（%.0f conn/s）\n", ok, fail, setup,
            setup > 0 ? ok / setup : 0);
    double h0 = now_s();
    while (now_s() - h0 < hold_secs) usleep(100000);
    for (long i = 0; i < ok; i++) {
        shutdown(fds[i], SHUT_RDWR);
        close(fds[i]);
    }
    printf("hold ok=%ld fail=%ld setup_s=%.2f hold_s=%.2f\n", ok, fail, setup, hold_secs);
    fflush(stdout);
    free(fds);
    return ok > 0 ? 0 : 1;
}

struct churn_arg {
    const char *host;
    int port;
    double deadline;
    long conns;
    long fail;
};

static void *churn_worker(void *arg) {
    struct churn_arg *a = arg;
    while (now_s() < a->deadline) {
        for (int i = 0; i < 16; i++) {
            int fd = connect_to(a->host, a->port);
            if (fd < 0 || ping_echo(fd) != 0) {
                if (fd >= 0) close(fd);
                a->fail++;
                continue;
            }
            close(fd);
            a->conns++;
        }
    }
    return NULL;
}

static int cmd_churn(const char *host, int port, double secs) {
    enum { NW = 8 };
    pthread_t th[NW];
    struct churn_arg args[NW];
    double t0 = now_s();
    for (int i = 0; i < NW; i++) {
        args[i] = (struct churn_arg){host, port, t0 + secs, 0, 0};
        pthread_create(&th[i], NULL, churn_worker, &args[i]);
    }
    long conns = 0, fail = 0;
    for (int i = 0; i < NW; i++) {
        pthread_join(th[i], NULL);
        conns += args[i].conns;
        fail += args[i].fail;
    }
    double wall = now_s() - t0;
    printf("churn conns=%ld fail=%ld wall_s=%.2f conn_per_s=%.0f\n", conns, fail, wall,
           wall > 0 ? conns / wall : 0);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: conn_scale hold|churn ...\n");
        return 2;
    }
    if (!strcmp(argv[1], "hold") && argc >= 6) {
        return cmd_hold(argv[2], atoi(argv[3]), atol(argv[4]), atof(argv[5]));
    }
    if (!strcmp(argv[1], "churn") && argc >= 5) {
        return cmd_churn(argv[2], atoi(argv[3]), atof(argv[4]));
    }
    fprintf(stderr, "bad args\n");
    return 2;
}
