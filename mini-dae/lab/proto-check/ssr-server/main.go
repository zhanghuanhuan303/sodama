// SSR（shadowsocksr-stream，origin proto + plain obfs）参考服务端——lab 跨实现
// 测试对端（P30 SSR 客户端配套夹具）。
//
// 线格式与 olicesx/outbound 的 protocol/shadowsocks_stream 一致；origin 协议与
// plain obfs 都是恒等变换，不引入额外握手字节：
//
//	客户端 → 服务端：IV（InfoIVLen() 字节）+ 流密码密文；
//	  明文首段是 SOCKS5 风格目标地址（ATYP 1=IPv4(4B) / 3=域名(1B len+str)
//	  / 4=IPv6(16B)，后接 2B 大端端口），其后为 payload；
//	服务端 → 客户端：新 IV + 流密码密文（首个回包数据之前发送 IV，此后所有
//	  回包沿用同一加密流状态）。
//
// 上游 dial 打 SO_MARK=0x233，否则 lab 里会被 mini-dae 数据面（wan_egress）
// 二次捕获成环；无权限（非 root）时降级为不打标继续，仅告警一次。
//
// 只实现 TCP（SSR origin/plain 的 UDP 走另一条线，lab 不需要）。
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
)

const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	soMark = 36    // SO_MARK（linux）
	mark   = 0x233 // lab 数据面标记
)

// decryptReader 把 conn 上读到的密文原地解密。流密码有状态，必须严格按读入
// 顺序解密；bufio 的预读也经由这里，顺序仍然正确。
type decryptReader struct {
	conn net.Conn
	dec  *ciphers.StreamCipher
}

func (r *decryptReader) Read(p []byte) (int, error) {
	n, err := r.conn.Read(p)
	if n > 0 {
		r.dec.Decrypt(p[:n], p[:n])
	}
	return n, err
}

// encryptWriter 首次写时调用 InitEncrypt() 生成新 IV 并先行发送，之后再加密
// 数据；后续写沿用同一流状态。
type encryptWriter struct {
	conn net.Conn
	enc  *ciphers.StreamCipher
	mu   sync.Mutex
}

func (w *encryptWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.enc.EncryptInited() {
		iv, err := w.enc.InitEncrypt()
		if err != nil {
			return 0, err
		}
		buf := make([]byte, 0, len(iv)+len(p))
		buf = append(buf, iv...)
		buf = append(buf, p...)
		w.enc.Encrypt(buf[len(iv):], buf[len(iv):])
		if err := writeFull(w.conn, buf); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	w.enc.Encrypt(buf, buf)
	if err := writeFull(w.conn, buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// readTarget 从解密流里解析 SOCKS5 风格目标地址；地址可能跨多次读，bufio 负责
// 缓冲与按需解密。
func readTarget(br *bufio.Reader) (host string, port uint16, err error) {
	atyp, err := br.ReadByte()
	if err != nil {
		return "", 0, err
	}
	switch atyp {
	case atypIPv4:
		var b [6]byte
		if _, err = io.ReadFull(br, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[:4]).String(), binary.BigEndian.Uint16(b[4:]), nil
	case atypIPv6:
		var b [18]byte
		if _, err = io.ReadFull(br, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[:16]).String(), binary.BigEndian.Uint16(b[16:]), nil
	case atypDomain:
		l, err := br.ReadByte()
		if err != nil {
			return "", 0, err
		}
		b := make([]byte, int(l)+2)
		if _, err = io.ReadFull(br, b); err != nil {
			return "", 0, err
		}
		return string(b[:l]), binary.BigEndian.Uint16(b[l:]), nil
	default:
		return "", 0, fmt.Errorf("unsupported ATYP %#x", atyp)
	}
}

type server struct {
	method   string
	password string
	dialer   *net.Dialer
	logLine  func(format string, args ...any)
}

func (s *server) handleConn(client net.Conn) {
	defer client.Close()
	from := client.RemoteAddr().String()

	ciph, err := ciphers.NewStreamCipher(s.method, s.password)
	if err != nil {
		s.logLine("SSR cipher error from=%s: %v", from, err)
		return
	}

	// 1. IV：必须读满 InfoIVLen() 字节（TCP 可能分多次到达）。
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
	iv := make([]byte, ciph.InfoIVLen())
	if _, err := io.ReadFull(client, iv); err != nil {
		s.logLine("SSR read iv from=%s: %v", from, err)
		return
	}
	if err := ciph.InitDecrypt(iv); err != nil {
		s.logLine("SSR init decrypt from=%s: %v", from, err)
		return
	}

	// 2. 解密流内解析目标地址，剩余明文即 payload 前缀。
	br := bufio.NewReaderSize(&decryptReader{conn: client, dec: ciph}, 16<<10)
	host, port, err := readTarget(br)
	if err != nil {
		s.logLine("SSR read target from=%s: %v", from, err)
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	_ = client.SetReadDeadline(time.Time{})

	// 3. 连目标（SO_MARK dialer；非 root 已在 main 里降级）。
	up, err := s.dialer.Dial("tcp", target)
	if err != nil {
		s.logLine("SSR dial target=%s from=%s err=%v", target, from, err)
		return
	}
	defer up.Close()
	s.logLine("SSR connect target=%s from=%s", target, from)

	// 4/5. 双向转发与半关闭。
	enc := &encryptWriter{conn: client, enc: ciph}
	var wg sync.WaitGroup
	var c2u, u2c int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		c2u, _ = io.Copy(up, br)
		// client FIN → target CloseWrite，让目标完成剩余输出。
		if tcp, ok := up.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		u2c, _ = io.Copy(enc, up)
		// target EOF → 关连接，唤醒 client→target 方向。
		_ = client.Close()
	}()
	wg.Wait()
	s.logLine("SSR client->upstream bytes=%d", c2u)
	s.logLine("SSR upstream->client bytes=%d", u2c)
}

func main() {
	port := flag.String("port", "8389", "listen TCP port")
	method := flag.String("method", "aes-256-cfb", "stream cipher method")
	password := flag.String("password", "testpass", "password")
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

	// 提前校验 method/password，坏配置直接退出（空密码会被 ciphers 拒绝）。
	probe, err := ciphers.NewStreamCipher(*method, *password)
	if err != nil {
		log.Fatalf("cipher: %v", err)
	}

	p, err := strconv.Atoi(*port)
	if err != nil || p < 0 || p > 65535 {
		log.Fatalf("bad port %q", *port)
	}

	var markWarn sync.Once
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMark, mark)
			}); err != nil {
				return err
			}
			if serr != nil {
				markWarn.Do(func() {
					logLine("SSR warn: SO_MARK 0x%x unavailable (%v)，降级为不打标", mark, serr)
				})
			}
			return nil
		},
	}

	s := &server{method: *method, password: *password, dialer: d, logLine: logLine}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	logLine("ssr-server listening on %s method=%s ivLen=%d", ln.Addr(), *method, probe.InfoIVLen())
	for {
		conn, err := ln.Accept()
		if err != nil {
			logLine("SSR accept error: %v", err)
			return
		}
		go s.handleConn(conn)
	}
}
