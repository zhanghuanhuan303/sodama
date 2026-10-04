// P26：naive over HTTP/3 参考服务端（Go + quic-go fork http3；ALPN=h3）。
//
// 用途：lab 里验证 loader 的 naive+quic 出站——HTTP/3 CONNECT + Basic 认证 + 双向流。
// 仅接受 CONNECT；认证失败 407、非 CONNECT 405（客户端须能从响应头读状态）。
// 认证通过后拨号 CONNECT 目标，双向拷贝（客户端 r.Body ↔ 上游），逐块 Flush。
//
// 上游 socket 必须打 SO_MARK：否则被 sodama 数据面（wan_egress）再抓一次成环。
package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	quic "github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
)

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
	port := flag.String("port", "8664", "listen UDP port")
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

	certPair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatalf("load cert: %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(*user+":"+*pass))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			logLine("NAIVE-H3 reject method=%s proto=%s", r.Method, r.Proto)
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Proxy-Authorization") != want {
			logLine("NAIVE-H3 auth-fail from=%s", r.RemoteAddr)
			w.Header().Set("Proxy-Authenticate", `Basic realm="naive"`)
			http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
			return
		}
		target := r.Host
		logLine("NAIVE-H3 connect target=%s proto=%s from=%s", target, r.Proto, r.RemoteAddr)
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
			logLine("NAIVE-H3 client->upstream bytes=%d err=%v", n, err)
			if tc, ok := up.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			close(done)
		}()
		var total int64
		buf := make([]byte, 32*1024)
		for {
			n, rerr := up.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					logLine("NAIVE-H3 upstream->client write err=%v", werr)
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
		logLine("NAIVE-H3 upstream->client bytes=%d", total)
		<-done
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
		Handler:    handler,
	}
	logLine("naive-h3-server listening on 127.0.0.1:%s (udp/h3)", *port)
	log.Fatal(srv.Serve(conn))
}
