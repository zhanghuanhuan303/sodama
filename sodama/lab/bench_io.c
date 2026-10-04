/* P7 基准端点：TCP/UDP echo 服务端 + 客户端工作负载。
 *
 * Python 探针（client_probe/stream_probe/wan_echo）作为端点会先于 sodama
 * 成为瓶颈，无法比较路径吞吐；这里用 C 实现热路径端点（零逐包分配）。
 *
 * 服务端为**全双工 echo**（预分配 ring；BENCH_RING_MB 可调，默认 64MB）：
 * 读线程按序写入 ring、写线程按序回放。单线程 read→write 的半双工实现
 * 会在多跳大缓冲管道中与上游形成「都在写、都不读」的环形依赖（实测偶发
 * 60s 级假死），fixture 不应成为死锁参与者。
 *
 * 用法：
 *   bench_io serve <tcp_ports_csv> [udp_port]
 *   bench_io client <host> <port> <mb_per_stream> <streams>   # echo 回显校验
 *   bench_io lat <host> <port> <count>                        # 小包 ping-pong RTT
 *   bench_io udpclient <host> <port> <count> <size>           # 逐包 echo RTT
 *   bench_io udpblast <host> <port> <count> <size>            # 单向洪峰 + 回包计数
 *
 * 输出（stdout 单行，供 bench.sh 解析）：
 *   tcp-ok streams=4 mb_sent=128 mb_recv=128 wall_s=1.234 oneway_mbps=829.8 verify=ok
 *   lat-ok count=500 avg_us=210.3 p50_us=187.0 p99_us=421.0
 *   udp-ok sent=2000 recv=2000 loss=0 avg_us=85.1 p50_us=80.0 p99_us=120.0
 *   udpblast-ok sent=50000 recv=49997 loss=3 wall_s=0.812 mbps=15.7
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define BUF_SZ (256 * 1024)
#define SOCK_BUF (4 * 1024 * 1024)
#define IO_TIMEOUT_S 60

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000LL;
}

static int cmp_ll(const void *a, const void *b) {
    long long x = *(const long long *)a, y = *(const long long *)b;
    return (x > y) - (x < y);
}

static void print_stats(const char *tag, long long *v, long long n) {
    if (n <= 0) {
        printf(" %savg_us=0 p50_us=0 p99_us=0", tag);
        return;
    }
    qsort(v, (size_t)n, sizeof v[0], cmp_ll);
    long long sum = 0;
    for (long long i = 0; i < n; i++) sum += v[i];
    printf(" %savg_us=%.1f p50_us=%lld p99_us=%lld", tag,
           (double)sum / (double)n, v[n / 2], v[(n * 99) / 100]);
}

static unsigned char pattern_at(long long pos) {
    return (unsigned char)(pos & 0xff);
}

static int send_all(int fd, const unsigned char *buf, size_t n) {
    while (n) {
        ssize_t w = send(fd, buf, n, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        buf += w;
        n -= (size_t)w;
    }
    return 0;
}

static int read_exact(int fd, unsigned char *buf, size_t n) {
    while (n) {
        ssize_t r = recv(fd, buf, n, 0);
        if (r <= 0) return -1;
        buf += r;
        n -= (size_t)r;
    }
    return 0;
}

static int dial_tcp(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    int sb = SOCK_BUF;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sb, sizeof sb);
    struct timeval tv = {IO_TIMEOUT_S, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return fd;
}

/* ---------------------------------------------------------------- server */

/* 全双工 echo：读线程把收到的数据按序写入预分配 ring，写线程按序回放。
 * 原来的单线程 read→write 在半双工下会与上游实现的大缓冲管道形成
 * 「双方都在写、都不读」的环形依赖，fixture 不应成为死锁参与者。
 * ring 容量默认 64MB（BENCH_RING_MB 可调）；内存预分配，无逐包分配。 */
#define RING_CHUNK (1u << 20)
struct echo_conn {
    int fd;
    unsigned char *ring;
    size_t cap;
    size_t read_off;  /* 绝对偏移；读线程写、均在 mu 下 */
    size_t write_off; /* 绝对偏移；写线程写、均在 mu 下 */
    int eof;
    pthread_mutex_t mu;
    pthread_cond_t cv;
};

static size_t ring_cap(void) {
    const char *e = getenv("BENCH_RING_MB");
    long mb = e ? atol(e) : 64;
    if (mb < 1) mb = 1;
    return (size_t)mb << 20;
}

static void *echo_reader(void *arg) {
    struct echo_conn *c = arg;
    for (;;) {
        pthread_mutex_lock(&c->mu);
        while (c->read_off - c->write_off >= c->cap && !c->eof)
            pthread_cond_wait(&c->cv, &c->mu);
        size_t space = c->cap - (c->read_off - c->write_off);
        int eof = c->eof;
        pthread_mutex_unlock(&c->mu);
        if (eof) break;
        size_t start = c->read_off % c->cap;
        size_t n1 = (space < c->cap - start) ? space : (c->cap - start);
        size_t n2 = space - n1;
        struct iovec iov[2] = {{c->ring + start, n1}, {c->ring, n2}};
        ssize_t n = readv(c->fd, iov, n2 ? 2 : 1);
        if (n <= 0) break;
        pthread_mutex_lock(&c->mu);
        c->read_off += (size_t)n;
        pthread_cond_signal(&c->cv);
        pthread_mutex_unlock(&c->mu);
    }
    pthread_mutex_lock(&c->mu);
    c->eof = 1;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
    return NULL;
}

static void *tcp_conn(void *arg) {
    int fd = (int)(intptr_t)arg;
    struct echo_conn c = {.fd = fd, .cap = ring_cap(), .read_off = 0, .write_off = 0, .eof = 0};
    c.ring = malloc(c.cap);
    if (!c.ring) {
        close(fd);
        return NULL;
    }
    pthread_mutex_init(&c.mu, NULL);
    pthread_cond_init(&c.cv, NULL);
    pthread_t th;
    if (pthread_create(&th, NULL, echo_reader, &c) != 0) {
        free(c.ring);
        close(fd);
        return NULL;
    }
    size_t w = 0;
    for (;;) {
        pthread_mutex_lock(&c.mu);
        while (w >= c.read_off && !c.eof) pthread_cond_wait(&c.cv, &c.mu);
        size_t r = c.read_off;
        int eof = c.eof;
        pthread_mutex_unlock(&c.mu);
        while (w < r) {
            size_t start = w % c.cap;
            size_t n1 = (r - w < c.cap - start) ? (r - w) : (c.cap - start);
            size_t n2 = (r - w) - n1;
            struct iovec iov[2] = {{c.ring + start, n1}, {c.ring, n2}};
            ssize_t n = writev(c.fd, iov, n2 ? 2 : 1);
            if (n <= 0) goto done;
            w += (size_t)n;
            pthread_mutex_lock(&c.mu);
            c.write_off = w;
            pthread_mutex_unlock(&c.mu);
        }
        if (eof && w >= r) break;
    }
done:
    shutdown(fd, SHUT_RDWR);
    pthread_join(th, NULL);
    pthread_mutex_destroy(&c.mu);
    pthread_cond_destroy(&c.cv);
    free(c.ring);
    close(fd);
    return NULL;
}

static void *tcp_listener(void *arg) {
    long port = (long)(intptr_t)arg;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return NULL;
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(lfd, 128) != 0) {
        fprintf(stderr, "tcp bind/listen :%ld 失败: %s\n", port, strerror(errno));
        close(lfd);
        return NULL;
    }
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        int sb = SOCK_BUF;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sb, sizeof sb);
        pthread_t th;
        if (pthread_create(&th, NULL, tcp_conn, (void *)(intptr_t)fd) == 0) {
            pthread_detach(th);
        } else {
            close(fd);
        }
    }
    close(lfd);
    return NULL;
}

static void *udp_echo(void *arg) {
    long port = (long)(intptr_t)arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return NULL;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        fprintf(stderr, "udp bind :%ld 失败: %s\n", port, strerror(errno));
        close(fd);
        return NULL;
    }
    unsigned char buf[65536];
    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&peer, &plen);
        if (n <= 0) continue;
        sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&peer, plen);
    }
}

static int cmd_serve(int argc, char **argv) {
    if (argc < 1) {
        fprintf(stderr, "用法: bench_io serve <tcp_ports_csv> [udp_port]\n");
        return 2;
    }
    char *csv = strdup(argv[0]);
    for (char *tok = strtok(csv, ","); tok; tok = strtok(NULL, ",")) {
        long port = strtol(tok, NULL, 10);
        pthread_t th;
        pthread_create(&th, NULL, tcp_listener, (void *)(intptr_t)port);
        pthread_detach(th);
    }
    free(csv);
    if (argc >= 2) {
        long uport = strtol(argv[1], NULL, 10);
        pthread_t th;
        pthread_create(&th, NULL, udp_echo, (void *)(intptr_t)uport);
        pthread_detach(th);
    }
    printf("bench-io ready\n");
    fflush(stdout);
    for (;;) pause();
}

/* ---------------------------------------------------------------- TCP client */

struct stream {
    const char *host;
    int port;
    long long bytes;
    int fd;
    int idx;
    long long sent, recvd, bad;
    int err;
    double wall_s;
    pthread_t writer;
};

static void *stream_writer(void *arg) {
    struct stream *st = arg;
    unsigned char *buf = malloc(BUF_SZ);
    if (!buf) {
        st->err = 1;
        return NULL;
    }
    long long off = 0;
    while (off < st->bytes) {
        size_t n = (size_t)(st->bytes - off < BUF_SZ ? st->bytes - off : BUF_SZ);
        for (size_t i = 0; i < n; i++) buf[i] = pattern_at(off + (long long)i);
        if (send_all(st->fd, buf, n) != 0) {
            st->err = 1;
            fprintf(stderr, "stream %d: send 错误: %s（已发 %lld 字节）\n", st->idx,
                    strerror(errno), off);
            break;
        }
        off += (long long)n;
    }
    st->sent = off;
    free(buf);
    /* 设置 BENCH_NOSHUT=1 跳过半关闭：跨实现吞吐对比时避免把各家半关闭
     * 语义差异混入结果（半关闭语义由 stream_probe / 各协议专项覆盖）。 */
    if (!getenv("BENCH_NOSHUT")) {
        shutdown(st->fd, SHUT_WR);
    }
    return NULL;
}

static void *stream_main(void *arg) {
    struct stream *st = arg;
    double t0 = now_s();
    st->fd = dial_tcp(st->host, st->port);
    if (st->fd < 0) {
        st->err = 1;
        st->wall_s = now_s() - t0;
        fprintf(stderr, "stream %d: 连接失败: %s\n", st->idx, strerror(errno));
        return NULL;
    }
    st->idx = st->idx; /* 保留字段供上层打印 */
    pthread_create(&st->writer, NULL, stream_writer, st);
    unsigned char *buf = malloc(BUF_SZ);
    if (!buf) {
        st->err = 1;
        st->wall_s = now_s() - t0;
        return NULL;
    }
    long long got = 0;
    for (;;) {
        ssize_t n = recv(st->fd, buf, BUF_SZ, 0);
        if (n < 0) {
            st->err = 1;
            fprintf(stderr, "stream %d: recv 错误: %s（已收 %lld 字节）\n", st->idx,
                    strerror(errno), got);
            break;
        }
        if (n == 0) break;
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] != pattern_at(got + i)) st->bad++;
        }
        got += n;
        if (got > st->bytes) {
            st->bad++;
            break;
        }
        /* 收满即停：吞吐只计数据面，不等 EOF（半关闭语义由专用用例覆盖）。 */
        if (got == st->bytes) break;
    }
    st->recvd = got;
    st->wall_s = now_s() - t0;
    pthread_join(st->writer, NULL);
    close(st->fd);
    free(buf);
    if (st->sent != st->bytes || st->recvd != st->bytes) st->err = 1;
    return NULL;
}

static int cmd_client(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "用法: bench_io client <host> <port> <mb_per_stream> <streams>\n");
        return 2;
    }
    const char *host = argv[0];
    int port = atoi(argv[1]);
    long long mb = atoll(argv[2]);
    int streams = atoi(argv[3]);
    if (streams < 1 || streams > 64 || mb < 1 || mb > 65536) return 2;
    struct stream *sts = calloc((size_t)streams, sizeof *sts);
    pthread_t *th = calloc((size_t)streams, sizeof *th);
    for (int i = 0; i < streams; i++) {
        sts[i].host = host;
        sts[i].port = port;
        sts[i].bytes = mb * 1024 * 1024;
        sts[i].idx = i;
        pthread_create(&th[i], NULL, stream_main, &sts[i]);
    }
    long long sent = 0, recvd = 0, bad = 0;
    int err = 0;
    double wall = 0;
    for (int i = 0; i < streams; i++) {
        pthread_join(th[i], NULL);
        if (sts[i].err || sts[i].sent != sts[i].bytes || sts[i].recvd != sts[i].bytes) {
            fprintf(stderr, "stream %d: sent=%lld recv=%lld bad=%lld wall_s=%.3f\n", i,
                    sts[i].sent, sts[i].recvd, sts[i].bad, sts[i].wall_s);
        }
        sent += sts[i].sent;
        recvd += sts[i].recvd;
        bad += sts[i].bad;
        err |= sts[i].err;
        if (sts[i].wall_s > wall) wall = sts[i].wall_s;
    }
    double oneway_mbps = wall > 0 ? (double)recvd * 8.0 / wall / 1e6 : 0;
    printf("tcp-%s streams=%d mb_sent=%lld mb_recv=%lld wall_s=%.3f oneway_mbps=%.1f verify=%s\n",
           err || bad ? "fail" : "ok", streams, sent >> 20, recvd >> 20, wall,
           oneway_mbps, bad ? "bad" : "ok");
    free(sts);
    free(th);
    return err || bad ? 1 : 0;
}

/* ---------------------------------------------------------------- latency */

static int cmd_lat(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "用法: bench_io lat <host> <port> <count>\n");
        return 2;
    }
    const char *host = argv[0];
    int port = atoi(argv[1]);
    int count = atoi(argv[2]);
    int fd = dial_tcp(host, port);
    if (fd < 0) {
        printf("lat-fail 连接失败\n");
        return 1;
    }
    long long *rtt = calloc((size_t)count, sizeof *rtt);
    int ok = 0, bad = 0;
    unsigned char out[16], in[16];
    for (int i = 0; i < 16; i++) out[i] = pattern_at(i);
    for (int i = 0; i < count; i++) {
        long long t0 = now_us();
        if (send_all(fd, out, sizeof out) != 0 || read_exact(fd, in, sizeof in) != 0) {
            bad++;
            break;
        }
        rtt[ok++] = now_us() - t0;
        if (memcmp(out, in, sizeof out) != 0) bad++;
    }
    close(fd);
    if (bad || ok != count) {
        printf("lat-fail count=%d ok=%d bad=%d\n", count, ok, bad);
        free(rtt);
        return 1;
    }
    printf("lat-ok count=%d", ok);
    print_stats("", rtt, ok);
    printf("\n");
    free(rtt);
    return 0;
}

/* ---------------------------------------------------------------- UDP client */

static int cmd_udpclient(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "用法: bench_io udpclient <host> <port> <count> <size>\n");
        return 2;
    }
    const char *host = argv[0];
    int port = atoi(argv[1]);
    int count = atoi(argv[2]);
    int size = atoi(argv[3]);
    if (size < 8 || size > 60000) return 2;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int sb = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sb, sizeof sb);

    unsigned char *pkt = malloc((size_t)size);
    unsigned char *in = malloc((size_t)size);
    long long *rtt = calloc((size_t)count, sizeof *rtt);
    int recv_n = 0, loss = 0;
    for (int i = 0; i < count; i++) {
        uint32_t seq = (uint32_t)htonl((uint32_t)i);
        memcpy(pkt, &seq, 4);
        for (int j = 4; j < size; j++) pkt[j] = pattern_at(j);
        long long t0 = now_us();
        if (sendto(fd, pkt, (size_t)size, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
            loss++;
            continue;
        }
        ssize_t n = recv(fd, in, (size_t)size, 0);
        if (n < 4) {
            loss++;
            continue;
        }
        uint32_t got;
        memcpy(&got, in, 4);
        if (ntohl(got) != (uint32_t)i) {
            loss++;
            continue;
        }
        rtt[recv_n++] = now_us() - t0;
    }
    printf("udp-ok sent=%d recv=%d loss=%d", count, recv_n, loss);
    print_stats("", rtt, recv_n);
    printf("\n");
    free(pkt);
    free(in);
    free(rtt);
    close(fd);
    return 0;
}

static int cmd_udpblast(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "用法: bench_io udpblast <host> <port> <count> <size>\n");
        return 2;
    }
    const char *host = argv[0];
    int port = atoi(argv[1]);
    int count = atoi(argv[2]);
    int size = atoi(argv[3]);
    if (size < 8 || size > 60000) return 2;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    int sb = 8 << 20;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sb, sizeof sb);

    unsigned char *pkt = malloc((size_t)size);
    unsigned char in[65536];
    double t0 = now_s();
    int sent = 0;
    for (int i = 0; i < count; i++) {
        uint32_t seq = (uint32_t)htonl((uint32_t)i);
        memcpy(pkt, &seq, 4);
        if (sendto(fd, pkt, (size_t)size, 0, (struct sockaddr *)&sa, sizeof sa) < 0) break;
        sent++;
    }
    struct timeval tv = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int recv_n = 0;
    for (;;) {
        ssize_t n = recv(fd, in, sizeof in, 0);
        if (n <= 0) break;
        recv_n++;
    }
    double wall = now_s() - t0;
    double mbps = wall > 0 ? (double)recv_n * (double)size * 8.0 / wall / 1e6 : 0;
    printf("udpblast-ok sent=%d recv=%d loss=%d wall_s=%.3f mbps=%.1f\n", sent, recv_n,
           sent - recv_n, wall, mbps);
    free(pkt);
    close(fd);
    return 0;
}

/* ---------------------------------------------------------------- main */

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2) {
        fprintf(stderr,
                "用法: bench_io serve <tcp_ports_csv> [udp_port]\n"
                "       bench_io client <host> <port> <mb> <streams>\n"
                "       bench_io lat <host> <port> <count>\n"
                "       bench_io udpclient <host> <port> <count> <size>\n"
                "       bench_io udpblast <host> <port> <count> <size>\n");
        return 2;
    }
    if (strcmp(argv[1], "serve") == 0) return cmd_serve(argc - 2, argv + 2);
    if (strcmp(argv[1], "client") == 0) return cmd_client(argc - 2, argv + 2);
    if (strcmp(argv[1], "lat") == 0) return cmd_lat(argc - 2, argv + 2);
    if (strcmp(argv[1], "udpclient") == 0) return cmd_udpclient(argc - 2, argv + 2);
    if (strcmp(argv[1], "udpblast") == 0) return cmd_udpblast(argc - 2, argv + 2);
    fprintf(stderr, "未知子命令: %s\n", argv[1]);
    return 2;
}
