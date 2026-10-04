// relay 内环 A/B：epoll+splice vs io_uring splice（单流 64MB，多轮取中位）。
// 拓扑：producer --TCP--> relay(in) --(被测内环)--> relay(out) --TCP--> sink
// 只统计 relay 线程 CPU（CLOCK_THREAD_CPUTIME_ID）与墙钟。
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BUF_SZ (1 << 20)
static char buf[BUF_SZ];

static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
static double thread_cpu_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int tcp_listen(int *port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = 0};
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    listen(fd, 1);
    socklen_t sl = sizeof(sa);
    getsockname(fd, (struct sockaddr *)&sa, &sl);
    *port_out = ntohs(sa.sin_port);
    return fd;
}
static int tcp_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    while (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 && errno == EINTR) {}
    return fd;
}

struct io_arg { int fd; size_t total; size_t got; };
static void *producer(void *p) {
    struct io_arg *a = p;
    while (a->got < a->total) {
        size_t want = a->total - a->got < BUF_SZ ? a->total - a->got : BUF_SZ;
        ssize_t n = write(a->fd, buf, want);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; break; }
        a->got += n;
    }
    shutdown(a->fd, SHUT_WR);
    return NULL;
}
static void *sinkf(void *p) {
    struct io_arg *a = p;
    while (a->got < a->total) {
        ssize_t n = read(a->fd, buf, BUF_SZ);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; break; }
        a->got += n;
    }
    return NULL;
}

static size_t relay_epoll(int in, int out, size_t total, int pipe_sz) {
    int p[2];
    if (pipe(p) != 0) return 0;
    fcntl(p[0], F_SETPIPE_SZ, pipe_sz);
    fcntl(p[1], F_SETPIPE_SZ, pipe_sz);
    int cap = fcntl(p[0], F_GETPIPE_SZ);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = in};
    epoll_ctl(ep, EPOLL_CTL_ADD, in, &ev);
    ev.events = 0; ev.data.fd = out;
    epoll_ctl(ep, EPOLL_CTL_ADD, out, &ev);
    size_t done = 0, pend = 0;
    int in_eof = 0;
    while (done < total) {
        if (pend > 0) {
            ssize_t n = splice(p[0], NULL, out, NULL, pend, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
            if (n > 0) { pend -= (size_t)n; done += (size_t)n; continue; }
            if (n < 0 && !(errno == EAGAIN || errno == EINTR)) break;
        }
        if (!in_eof && pend < (size_t)cap) {
            ssize_t n = splice(in, NULL, p[1], NULL, cap - pend, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
            if (n > 0) { pend += (size_t)n; continue; }
            if (n == 0) { in_eof = 1; }
            else if (n < 0 && !(errno == EAGAIN || errno == EINTR)) break;
        }
        if (in_eof && pend == 0) break;
        if (pend > 0) {
            ev.events = EPOLLOUT; ev.data.fd = out;
            epoll_ctl(ep, EPOLL_CTL_MOD, out, &ev);
        }
        if (!in_eof && pend < (size_t)cap) {
            ev.events = EPOLLIN; ev.data.fd = in;
            epoll_ctl(ep, EPOLL_CTL_MOD, in, &ev);
        }
        epoll_wait(ep, &ev, 1, 1000);
    }
    close(ep); close(p[0]); close(p[1]);
    return done;
}

static size_t relay_uring(int in, int out, size_t total, int pipe_sz, int sqpoll) {
    int p[2];
    if (pipe(p) != 0) return 0;
    fcntl(p[0], F_SETPIPE_SZ, pipe_sz);
    fcntl(p[1], F_SETPIPE_SZ, pipe_sz);
    int cap = fcntl(p[0], F_GETPIPE_SZ);
    struct io_uring ring;
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    if (sqpoll) params.flags |= IORING_SETUP_SQPOLL;
    if (io_uring_queue_init_params(8, &ring, &params) != 0) { fprintf(stderr, "uring init fail\n"); return 0; }
    size_t done = 0;
    while (done < total) {
        struct io_uring_sqe *s1 = io_uring_get_sqe(&ring);
        struct io_uring_sqe *s2 = io_uring_get_sqe(&ring);
        io_uring_prep_splice(s1, in, -1, p[1], -1, cap, 0);
        s1->user_data = 1;

        io_uring_prep_splice(s2, p[0], -1, out, -1, cap, 0);
        s2->user_data = 2;
        io_uring_submit(&ring);
        ssize_t r1 = 0, r2 = 0;
        struct io_uring_cqe *cqe;
        for (int k = 0; k < 2; k++) {
            if (io_uring_wait_cqe(&ring, &cqe) != 0) { done = 0; goto out; }
            if (cqe->user_data == 1) r1 = cqe->res; else r2 = cqe->res;
            io_uring_cqe_seen(&ring, cqe);
        }
        if (r1 <= 0) { fprintf(stderr, "uring r1=%zd errno=%d done=%zu\n", r1, errno, done); break; }
        if (r2 <= 0) { fprintf(stderr, "uring r1=%zd r2=%zd errno=%d done=%zu\n", r1, r2, errno, done); break; }
        done += (size_t)r2;
    }
out:
    io_uring_queue_exit(&ring);
    close(p[0]); close(p[1]);
    return done;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "epoll";
    size_t mb = argc > 2 ? (size_t)atoi(argv[2]) : 64;
    int runs = argc > 3 ? atoi(argv[3]) : 5;
    size_t total = mb << 20;
    memset(buf, 'A', sizeof(buf));
    for (int r = 0; r < runs; r++) {
        int p1, p2;
        int l1 = tcp_listen(&p1), l2 = tcp_listen(&p2);
        int in = tcp_connect(p1), out = tcp_connect(p2);
        int pfd = accept(l1, NULL, NULL), sfd = accept(l2, NULL, NULL);
        close(l1); close(l2);
        if (strcmp(mode, "epoll") == 0 || strcmp(mode, "epoll64k") == 0) {
            fcntl(in, F_SETFL, fcntl(in, F_GETFL) | O_NONBLOCK);
            fcntl(out, F_SETFL, fcntl(out, F_GETFL) | O_NONBLOCK);
        }
        struct io_arg pa = {.fd = pfd}, sa = {.fd = sfd, .got = 0};
        sa.total = total; pa.total = total;
        pthread_t tp, ts;
        double c0 = thread_cpu_s();
        long long t0 = now_ns();
        pthread_create(&tp, NULL, producer, &pa);
        pthread_create(&ts, NULL, sinkf, &sa);
        size_t done = 0;
        if (strcmp(mode, "epoll") == 0) done = relay_epoll(in, out, total, 1 << 20);
        else if (strcmp(mode, "epoll64k") == 0) done = relay_epoll(in, out, total, 64 << 10);
        else if (strcmp(mode, "uring") == 0) done = relay_uring(in, out, total, 1 << 20, 0);
        else if (strcmp(mode, "uring64k") == 0) done = relay_uring(in, out, total, 64 << 10, 0);
        else if (strcmp(mode, "uring-poll") == 0) done = relay_uring(in, out, total, 1 << 20, 1);
        else { fprintf(stderr, "mode? %s\n", mode); return 2; }
        long long t1 = now_ns();
        double c1 = thread_cpu_s();
        pthread_join(tp, NULL);
        pthread_join(ts, NULL);
        double secs = (t1 - t0) / 1e9;
        printf("%s run=%d done=%zu MB %.3fs %.2f GB/s relay_cpu=%.3fs cpu_per_GB=%.4fs\n",
               mode, r, done >> 20, secs, (double)done / secs / 1e9, c1 - c0,
               (c1 - c0) / ((double)done / 1e9));
        close(in); close(out); close(pfd); close(sfd);
    }
    return 0;
}
