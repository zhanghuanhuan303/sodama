// shadow-tls 服务端参考夹具——lab 跨实现测试对端（P31 shadow-tls 客户端
// 配套）。基于 sing-shadowtls v0.2.0 的 Service，支持三种版本：
//
//	v1：无认证，仅与伪装站完成一次 TLS 握手，之后转为裸 TCP 转发；
//	v2：password + 首个 app-data 帧前置 8 字节 HMAC-SHA1 校验；
//	v3：password + ClientHello session_id HMAC + 后续帧 HMAC 链。
//
// 伪装握手目标（Handshake.Server）是本进程内起的临时 TLS 1.2/1.3 服务器：
// 自签名证书（DNS SAN 含 -host，有效期 1 年），只完成握手，之后排空/丢弃
// 数据。v2/v3 客户端走 TLS 1.3；v1 客户端（rustls 强制 MaxVersion=TLS1.2，
// 与 olicesx/outbound 的 Go 客户端一致）协商 TLS 1.2——sing-shadowtls 的
// v1 握手完成判定只认 TLS ≤1.2 的明文 Finished 记录。认证成功后的内层连接
// 交给 relayHandler，双向转发到 -backend。
//
// 只实现 TCP；只监听 127.0.0.1（lab 本机访问）。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	logMu   sync.Mutex
	logFile *os.File
)

// logLine 追加写 -log 文件（带时间戳），同时回显到 stdout。
func logLine(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		fmt.Fprintf(logFile, "%s %s\n", time.Now().Format("2006-01-02T15:04:05.000"), line)
	}
	fmt.Println(line)
}

// serviceLogger 是 logger.ContextLogger 的最小实现：只把 Service 内部的
// warn/trace 事件转写到夹具日志，其余级别沿用 NOP。
type serviceLogger struct {
	logger.ContextLogger
}

func (l serviceLogger) TraceContext(ctx context.Context, args ...any) {
	logLine("STLS trace: %s", fmt.Sprint(args...))
}

func (l serviceLogger) WarnContext(ctx context.Context, args ...any) {
	logLine("STLS warn: %s", fmt.Sprint(args...))
}

func (l serviceLogger) ErrorContext(ctx context.Context, args ...any) {
	logLine("STLS error: %s", fmt.Sprint(args...))
}

// selfSignedCert 生成 ECDSA P-256 自签证书：DNS SAN 含 host，有效期 1 年。
func selfSignedCert(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// handshakeServer 是进程内的伪装站：TLS 1.3-only，完成握手后只排空数据。
type handshakeServer struct {
	ln   net.Listener
	addr string
}

func startHandshakeServer(host string) (*handshakeServer, error) {
	cert, err := selfSignedCert(host)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	hs := &handshakeServer{ln: ln, addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn := tls.Server(conn, config)
				if err := tlsConn.Handshake(); err != nil {
					logLine("STLS handshake server: handshake from=%s err=%v", conn.RemoteAddr(), err)
					return
				}
				// 伪装站不承载真实业务：排空/丢弃后续数据直到对端关闭。
				_, _ = io.Copy(io.Discard, tlsConn)
			}()
		}
	}()
	return hs, nil
}

// relayHandler 实现 N.TCPConnectionHandlerEx：认证成功后将内层连接与
// -backend 建 TCP 并双向转发。
type relayHandler struct {
	backend string
}

func (h *relayHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	logLine("STLS handler conn backend=%s", h.backend)

	var once sync.Once
	finish := func(err error) {
		once.Do(func() {
			_ = conn.Close()
			if onClose != nil {
				onClose(err)
			}
		})
	}

	upstream, err := net.DialTimeout("tcp", h.backend, 10*time.Second)
	if err != nil {
		logLine("STLS handler dial backend=%s err=%v", h.backend, err)
		finish(err)
		return
	}

	var wg sync.WaitGroup
	var upBytes, downBytes int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		upBytes, _ = io.Copy(upstream, conn)
		// 客户端 FIN → 半关后端写侧，让后端完成剩余输出。
		if !closeWrite(upstream) {
			_ = upstream.Close()
		}
	}()
	go func() {
		defer wg.Done()
		downBytes, _ = io.Copy(conn, upstream)
		// 后端 EOF → 半关客户端写侧；包装连接不支持时整连接关闭以唤醒另一向。
		if !closeWrite(conn) {
			_ = conn.Close()
		}
	}()
	wg.Wait()
	_ = upstream.Close()
	logLine("STLS relay close up=%d down=%d", upBytes, downBytes)
	finish(nil)
}

// closeWrite 尽力对底层 TCP 连接做半关闭。sing 的连接包装（CachedConn /
// verifiedConn）只通过 Upstream() 暴露底层连接，不转发 CloseWrite。
func closeWrite(conn net.Conn) bool {
	for i := 0; i < 8; i++ {
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			return cw.CloseWrite() == nil
		}
		unwrapper, ok := conn.(interface{ Upstream() any })
		if !ok {
			return false
		}
		next, ok := unwrapper.Upstream().(net.Conn)
		if !ok || next == conn {
			return false
		}
		conn = next
	}
	return false
}

func serveConn(service *shadowtls.Service, conn net.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	onClose := func(err error) {
		_ = conn.Close()
		cancel()
		if err != nil {
			logLine("STLS conn close from=%s err=%v", conn.RemoteAddr(), err)
		}
	}
	source := M.SocksaddrFromNet(conn.RemoteAddr())
	if err := service.NewConnection(ctx, conn, source, M.Socksaddr{}, onClose); err != nil {
		logLine("STLS conn error from=%s: %v", conn.RemoteAddr(), err)
		_ = conn.Close()
		cancel()
	}
}

func main() {
	port := flag.Int("port", 8399, "listen TCP port")
	version := flag.Int("version", 3, "shadow-tls protocol version (1, 2 or 3)")
	password := flag.String("password", "testpass", "shadow-tls password (v2/v3)")
	host := flag.String("host", "localhost", "camouflage server name (SNI / certificate DNS SAN)")
	backend := flag.String("backend", "127.0.0.1:8388", "inner TCP backend after authentication")
	logPath := flag.String("log", "", "append log file path")
	flag.Parse()

	if *version < 1 || *version > 3 {
		log.Fatalf("bad version %d (want 1, 2 or 3)", *version)
	}
	if *backend == "" {
		log.Fatalf("missing -backend")
	}
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("open log: %v", err)
		}
		defer f.Close()
		logFile = f
	}

	handshake, err := startHandshakeServer(*host)
	if err != nil {
		log.Fatalf("start handshake server: %v", err)
	}

	serviceConfig := shadowtls.ServiceConfig{
		Version:  *version,
		Password: *password,
		Handshake: shadowtls.HandshakeConfig{
			Server: M.ParseSocksaddr(handshake.addr),
			Dialer: N.SystemDialer,
		},
		Handler: &relayHandler{backend: *backend},
		Logger:  serviceLogger{ContextLogger: logger.NOP()},
	}
	if *version == 3 {
		serviceConfig.Users = []shadowtls.User{{Name: "default", Password: *password}}
	}
	service, err := shadowtls.NewService(serviceConfig)
	if err != nil {
		log.Fatalf("new service: %v", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port
	logLine("STLS server version=%d port=%d handshake=%s backend=%s", *version, actualPort, handshake.addr, *backend)

	for {
		conn, err := ln.Accept()
		if err != nil {
			logLine("STLS accept error: %v", err)
			return
		}
		logLine("STLS accept from=%s", conn.RemoteAddr())
		go serveConn(service, conn)
	}
}
