// P27：juicity v0 参考服务端（Go + quic-go fork；ALPN=h3）。
//
// 从 olicesx/outbound 的 protocol/juicity/e2e_test.go 的服务端移植为独立进程
// （与 hy2-server 同一模式）：协议常量就地从规范重述，保持独立实现。
//
// 协议：
//   - 认证（客户端单向流，50B，客户端保持打开）：[00][00][uuid16][token32]；
//     token = TLS.ExportKeyingMaterial(label=uuid 裸字节, context=password)[32]；
//   - TCP（双向流）：[01][TYPE ADDR PORT] + 裸字节；
//   - UDP（双向流）：[03][会话元数据]，之后每帧 [目标元数据][len u16][payload]，
//     回包 [来源元数据][len u16][payload]；元数据类型：1/4=IP、3=域名、2=命令。
//
// lab 拓扑要点：上游 TCP/UDP socket 必须打 SO_MARK（0x233），否则被 mini-dae
// 数据面（wan_egress）二次捕获成环；无 CONNECT 状态帧，目标不可达 = 流 reset。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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

	quic "github.com/olicesx/quic-go"
)

const (
	ver0            byte = 0x00
	cmdAuthenticate byte = 0x00
	networkTCP      byte = 0x01
	networkUDP      byte = 0x03
	atypIPv4        byte = 1
	atypMsg         byte = 2
	atypDomain      byte = 3
	atypIPv6        byte = 4

	authFailedCode  = quic.ApplicationErrorCode(0xfffffff1)
	authTimeoutCode = quic.ApplicationErrorCode(0xfffffff2)
	badCommandCode  = quic.ApplicationErrorCode(0xfffffff3)

	soMark = 36
	mark   = 0x233
)

func setMarkControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMark, mark)
	}); err != nil {
		return err
	}
	return serr
}

func readMetadata(r *bufio.Reader) (host string, port uint16, err error) {
	typ, err := r.ReadByte()
	if err != nil {
		return "", 0, err
	}
	switch typ {
	case atypIPv4:
		var raw [6]byte
		if _, err = io.ReadFull(r, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:4]).String(), binary.BigEndian.Uint16(raw[4:]), nil
	case atypIPv6:
		var raw [18]byte
		if _, err = io.ReadFull(r, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:16]).String(), binary.BigEndian.Uint16(raw[16:]), nil
	case atypDomain:
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		raw := make([]byte, int(l[0])+2)
		if _, err = io.ReadFull(r, raw); err != nil {
			return "", 0, err
		}
		return string(raw[:l[0]]), binary.BigEndian.Uint16(raw[l[0]:]), nil
	case atypMsg:
		var cmd [1]byte
		if _, err = io.ReadFull(r, cmd[:]); err != nil {
			return "", 0, err
		}
		return "", 0, nil
	default:
		return "", 0, fmt.Errorf("unsupported metadata type %#x", typ)
	}
}

func buildDatagramFrame(data []byte, from *net.UDPAddr) []byte {
	frame := make([]byte, 0, 21+len(data))
	if ip := from.IP.To4(); ip != nil {
		frame = append(frame, atypIPv4)
		frame = append(frame, ip...)
	} else {
		frame = append(frame, atypIPv6)
		frame = append(frame, from.IP.To16()...)
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(from.Port))
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(data)))
	return append(frame, data...)
}

type server struct {
	password string
	logLine  func(format string, args ...any)
}

func (s *server) serveConn(conn quic.Connection) {
	authOK := make(chan struct{})
	var authOnce sync.Once
	go s.serveUniStreams(conn, authOK, &authOnce)
	s.serveRelayStreams(conn, authOK)
}

func (s *server) serveUniStreams(conn quic.Connection, authOK chan struct{}, authOnce *sync.Once) {
	for {
		stream, err := conn.AcceptUniStream(conn.Context())
		if err != nil {
			return
		}
		s.handleAuthStream(conn, stream, authOK, authOnce)
	}
}

func (s *server) handleAuthStream(conn quic.Connection, stream quic.ReceiveStream, authOK chan struct{}, authOnce *sync.Once) {
	defer stream.CancelRead(0)
	reader := bufio.NewReaderSize(stream, 16<<10)
	ver, err := reader.ReadByte()
	if err != nil {
		return
	}
	if ver != ver0 {
		_ = conn.CloseWithError(badCommandCode, fmt.Sprintf("bad version %#x", ver))
		return
	}
	typ, err := reader.ReadByte()
	if err != nil {
		return
	}
	if typ != cmdAuthenticate {
		_ = conn.CloseWithError(badCommandCode, fmt.Sprintf("unexpected uni command %#x", typ))
		return
	}
	var uuidBytes [16]byte
	var token [32]byte
	if _, err := io.ReadFull(reader, uuidBytes[:]); err != nil {
		_ = conn.CloseWithError(badCommandCode, fmt.Sprintf("read uuid: %v", err))
		return
	}
	if _, err := io.ReadFull(reader, token[:]); err != nil {
		_ = conn.CloseWithError(badCommandCode, fmt.Sprintf("read token: %v", err))
		return
	}
	authOnce.Do(func() {
		tlsState := conn.ConnectionState().TLS
		expected, err := tlsState.ExportKeyingMaterial(string(uuidBytes[:]), []byte(s.password), 32)
		if err != nil || !bytes.Equal(token[:], expected) {
			s.logLine("JUICITY auth-fail from=%s", conn.RemoteAddr())
			_ = conn.CloseWithError(authFailedCode, "invalid credentials")
			return
		}
		s.logLine("JUICITY auth ok from=%s", conn.RemoteAddr())
		close(authOK)
	})
	// 排空后续 underlay 记录（IV||PSK + 元数据）；不做 full-cone，读到 EOF 为止。
	for {
		var ivpsk [64]byte
		if _, err := io.ReadFull(reader, ivpsk[:]); err != nil {
			return
		}
		if _, _, err := readMetadata(reader); err != nil {
			return
		}
	}
}

func (s *server) serveRelayStreams(conn quic.Connection, authOK chan struct{}) {
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		go s.handleRelayStream(conn, stream, authOK)
	}
}

func (s *server) handleRelayStream(conn quic.Connection, stream quic.Stream, authOK chan struct{}) {
	reader := bufio.NewReaderSize(stream, 16<<10)
	network, err := reader.ReadByte()
	if err != nil {
		stream.CancelRead(0)
		return
	}
	if network != networkTCP && network != networkUDP {
		_ = conn.CloseWithError(badCommandCode, fmt.Sprintf("unexpected stream network %#x", network))
		return
	}
	select {
	case <-authOK:
	case <-conn.Context().Done():
		return
	case <-time.After(10 * time.Second):
		_ = conn.CloseWithError(authTimeoutCode, "authentication timeout")
		return
	}
	host, port, err := readMetadata(reader)
	if err != nil {
		_ = conn.CloseWithError(badCommandCode, fmt.Sprintf("read session metadata: %v", err))
		return
	}
	if network == networkTCP {
		s.logLine("JUICITY tcp target=%s", net.JoinHostPort(host, strconv.Itoa(int(port))))
		s.relayTCP(stream, reader, host, port)
		return
	}
	s.logLine("JUICITY udp session target=%s", net.JoinHostPort(host, strconv.Itoa(int(port))))
	s.relayUDP(conn, stream, reader)
}

func (s *server) relayTCP(stream quic.Stream, reader *bufio.Reader, host string, port uint16) {
	d := net.Dialer{Timeout: 10 * time.Second, Control: setMarkControl}
	target, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		// juicity 无 CONNECT 状态帧：双向 reset，客户端读/写报错。
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}
	defer target.Close()
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		_, _ = io.Copy(target, reader)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	_, _ = io.Copy(stream, target)
	_ = stream.Close()
	<-upstreamDone
	stream.CancelRead(0)
}

func (s *server) relayUDP(conn quic.Connection, stream quic.Stream, reader *bufio.Reader) {
	_ = conn
	// 上游 UDP socket 绑 wildcard（要发往 WAN 侧目标；绑 127.0.0.1 会导致
	// sendto 非回环地址 EINVAL）。
	lc := net.ListenConfig{Control: setMarkControl}
	pc, err := lc.ListenPacket(context.Background(), "udp", "0.0.0.0:0")
	if err != nil {
		s.logLine("JUICITY udp listen err: %v", err)
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}
	udp := pc.(*net.UDPConn)
	defer udp.Close()
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		buf := make([]byte, 65535)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			frame := buildDatagramFrame(buf[:n], from)
			if _, err := stream.Write(frame); err != nil {
				return
			}
		}
	}()
	for {
		host, port, err := readMetadata(reader)
		if err != nil {
			s.logLine("JUICITY udp frame meta err: %v", err)
			break
		}
		var lenBuf [2]byte
		if _, err = io.ReadFull(reader, lenBuf[:]); err != nil {
			s.logLine("JUICITY udp frame len err: %v", err)
			break
		}
		length := int(binary.BigEndian.Uint16(lenBuf[:]))
		payload := make([]byte, length)
		if _, err = io.ReadFull(reader, payload); err != nil {
			s.logLine("JUICITY udp frame payload err: %v", err)
			break
		}
		ra, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			s.logLine("JUICITY udp resolve err: %v", err)
			break
		}
		if _, err := udp.WriteToUDP(payload, ra); err != nil {
			s.logLine("JUICITY udp write err: %v", err)
			break
		}
	}
	stream.CancelRead(0)
	_ = udp.Close()
	<-pumpDone
	_ = stream.Close()
}

func main() {
	port := flag.String("port", "18964", "listen UDP port")
	password := flag.String("password", "testpass", "juicity password")
	cert := flag.String("cert", "", "TLS cert")
	key := flag.String("key", "", "TLS key")
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
	p, err := strconv.Atoi(*port)
	if err != nil {
		log.Fatalf("bad port %q", *port)
	}
	listener, err := quic.ListenAddr(fmt.Sprintf("127.0.0.1:%d", p), &tls.Config{
		Certificates: []tls.Certificate{certPair},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{
		EnableDatagrams: false,
		MaxIdleTimeout:  30 * time.Second,
	})
	if err != nil {
		log.Fatalf("quic listen: %v", err)
	}
	s := &server{password: *password, logLine: logLine}
	logLine("juicity-server listening on %s (udp/h3)", listener.Addr())
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		go s.serveConn(conn)
	}
}
