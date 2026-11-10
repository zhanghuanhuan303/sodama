// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

// P26：DoH over HTTP/3 参考服务端（Go + quic-go fork http3；ALPN=h3）。
//
// 用途：lab 里验证 loader 的 DoH h3 上游真的走 HTTP/3。收到 POST 的
// application/dns-message 后，转发原始 DNS 报文到 -upstream（UDP），把应答原样返回；
// 每个请求写一行日志（proto/from），每个新 QUIC 连接也写一行（供连接复用断言）。
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	quic "github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
)

func main() {
	port := flag.String("port", "8955", "listen UDP port")
	cert := flag.String("cert", "", "TLS cert")
	key := flag.String("key", "", "TLS key")
	upstream := flag.String("upstream", "127.0.0.1:5353", "UDP DNS upstream")
	logPath := flag.String("log", "", "request log file")
	flag.Parse()

	var logf *os.File
	if *logPath != "" {
		var err error
		logf, err = os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("open log: %v", err)
		}
		defer logf.Close()
	}
	logLine := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		if logf != nil {
			fmt.Fprintln(logf, line)
		}
		fmt.Println(line)
	}

	certPair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatalf("load cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		logLine("H3 request proto=%s method=%s from=%s", r.Proto, r.Method, r.RemoteAddr)
		if r.ProtoMajor != 3 {
			http.Error(w, "HTTP/3 required", http.StatusHTTPVersionNotSupported)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c, err := net.Dial("udp", *upstream)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(buf[:n])
	})

	p, err := strconv.Atoi(*port)
	if err != nil {
		log.Fatalf("bad port %q", *port)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	srv := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certPair},
			NextProtos:   []string{http3.NextProtoH3},
			MinVersion:   tls.VersionTLS13,
		},
		QUICConfig: &quic.Config{MaxIdleTimeout: 60 * time.Second},
		Handler:    mux,
		ConnContext: func(ctx context.Context, c quic.Connection) context.Context {
			logLine("H3 new conn from=%s", c.RemoteAddr())
			return ctx
		},
	}
	logLine("doh-h3-server listening on 127.0.0.1:%s (udp/h3, upstream=%s)", *port, *upstream)
	log.Fatal(srv.Serve(conn))
}
