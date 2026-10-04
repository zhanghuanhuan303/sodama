// P23：DoH over HTTP/2 参考服务端（Go 标准库；TLS 自动协商 h2）。
//
// 用途：lab 里验证 loader 的 DoH 客户端真的走 HTTP/2（RFC 8484 要求 h2/h3）。
// 只接受 HTTP/2 请求，HTTP/1.1 请求回 505（这样 H1 回退路径会显式失败，测试
// 不会误判）。收到 POST 的 application/dns-message 后，转发原始 DNS 报文到
// -upstream（UDP），把应答原样返回；每个请求写一行日志（proto/alpn/from）。
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	port := flag.String("port", "8954", "listen port")
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

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		alpn := ""
		if r.TLS != nil {
			alpn = r.TLS.NegotiatedProtocol
		}
		logLine("H2 request proto=%s alpn=%q method=%s from=%s", r.Proto, alpn, r.Method, r.RemoteAddr)
		if r.ProtoMajor != 2 {
			http.Error(w, "HTTP/2 required", http.StatusHTTPVersionNotSupported)
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

	srv := &http.Server{Addr: "127.0.0.1:" + *port, Handler: mux}
	logLine("doh-h2-server listening on 127.0.0.1:%s (upstream=%s)", *port, *upstream)
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}
