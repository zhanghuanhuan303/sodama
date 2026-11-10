// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

// P25：naive（HTTP/2 CONNECT）参考服务端（Go 标准库；TLS 自动协商 h2）。
//
// 用途：lab 里验证 loader 的 naive 出站——h2 CONNECT + Basic 认证 + 双向流。
// 仅接受 HTTP/2；非 CONNECT/认证失败分别 405/407（客户端须能从响应头读状态）。
// 认证通过后拨号 CONNECT 目标，双向拷贝（客户端 r.Body ↔ 上游）。
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// 上游 socket 必须打 SO_MARK：否则被 sodama 数据面（wan_egress）再抓一次成环
// （与 lab 的 Python 夹具一致；SO_MARK=36，标记 0x233）。
const (
	soMark = 36
	mark   = 0x233
)

func markedDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMark, mark)
			}); err != nil {
				return err
			}
			return serr
		},
	}
}

func main() {
	port := flag.String("port", "8663", "listen port")
	cert := flag.String("cert", "", "TLS cert")
	key := flag.String("key", "", "TLS key")
	user := flag.String("user", "user", "basic auth user")
	pass := flag.String("pass", "pass", "basic auth password")
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

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(*user+":"+*pass))

	// 注意：CONNECT 的 URL.Path 为空，ServeMux 路由会 404，直接绑 Handler。
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alpn := ""
		if r.TLS != nil {
			alpn = r.TLS.NegotiatedProtocol
		}
		if r.Method != http.MethodConnect {
			logLine("NAIVE reject method=%s proto=%s", r.Method, r.Proto)
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		if r.ProtoMajor != 2 {
			http.Error(w, "HTTP/2 required", http.StatusHTTPVersionNotSupported)
			return
		}
		if r.Header.Get("Proxy-Authorization") != want {
			logLine("NAIVE auth-fail from=%s", r.RemoteAddr)
			w.Header().Set("Proxy-Authenticate", `Basic realm="naive"`)
			http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
			return
		}
		target := r.Host
		if target == "" {
			target = r.URL.Host
		}
		if target == "" {
			target = r.RequestURI
		}
		logLine("NAIVE connect target=%s alpn=%q proto=%s from=%s", target, alpn, r.Proto, r.RemoteAddr)
		up, err := markedDialer().Dial("tcp", target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer up.Close()
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		done := make(chan struct{})
		go func() {
			n, err := io.Copy(up, r.Body)
			logLine("NAIVE client->upstream bytes=%d err=%v", n, err)
			if tc, ok := up.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			close(done)
		}()
		// 每个上行块写后立即 Flush：Go h2 响应写入是带缓冲的，不 flush 会在 handler
		// 返回时一次性发出（交互式隧道会“卡到连接关闭”）。真实 naive 立即 flush。
		var total int64
		buf := make([]byte, 32*1024)
		for {
			n, rerr := up.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					logLine("NAIVE upstream->client write err=%v", werr)
					break
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				total += int64(n)
			}
			if rerr != nil {
				break
			}
		}
		logLine("NAIVE upstream->client bytes=%d", total)
		<-done
	})

	srv := &http.Server{Addr: "127.0.0.1:" + *port, Handler: handler}
	logLine("naive-server listening on 127.0.0.1:%s", *port)
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}
