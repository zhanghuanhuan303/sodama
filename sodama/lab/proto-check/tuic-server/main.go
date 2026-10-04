// tuic-server：TUIC v5 独立参考服务端（P5-G3，lab 用；quic-go）。
//
// 按 docs/modules/tuic-v5-client-spec.md 独立实现（不复用 outbound 库的代码），
// 用于与 sodama 的 Rust/quinn 客户端做跨实现验证。上游 TCP/UDP socket 打
// SO_MARK=0x233，避免 lab 拓扑里被 sodama 数据面二次捕获。
//
// 用法： tuic-server -port 18543 -uuid <uuid> -password <pass> \
//          -cert <cert.pem> -key <key.pem> -log <logfile>
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	quic "github.com/olicesx/quic-go"
)

const (
	ver5          = 0x05
	cmdAuth       = 0x00
	cmdConnect    = 0x01
	cmdPacket     = 0x02
	cmdDissociate = 0x03
	cmdHeartbeat  = 0x04

	atypV4   = 0x01
	atypV6   = 0x02
	atypNone = 0xff

	authFailedCode = 0xfffffff1
	authTimeout    = 0xfffffff2
	badCommand     = 0xfffffff3

	soMark = 36
	mark   = 0x233
)

var (
	cfgUUID     [16]byte
	cfgPassword string
	logFile     *os.File
	logMu       sync.Mutex
)

func logLine(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintf(logFile, format+"\n", args...)
}

func setMarkControl(_ string, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMark, mark)
	}); err != nil {
		return err
	}
	// lab 以 root 运行；非 root（本机 cargo test 跨实现单测）降级为告警，无数据面即无自环。
	if serr == syscall.EPERM {
		logLine("WARN: SO_MARK 失败（非 root？）")
		return nil
	}
	return serr
}

func dialTCP(addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, Control: setMarkControl}
	return d.Dial("tcp", addr)
}

func listenUDP() (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: setMarkControl}
	pc, err := lc.ListenPacket(context.Background(), "udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// ---- wire 解析/构造 ----

func readCommandHead(r *bufio.Reader) (ver, typ byte, err error) {
	head := make([]byte, 2)
	if _, err = io.ReadFull(r, head); err != nil {
		return 0, 0, err
	}
	return head[0], head[1], nil
}

func readAddress(r *bufio.Reader) (string, uint16, error) {
	atyp, err := r.ReadByte()
	if err != nil {
		return "", 0, err
	}
	var host string
	switch atyp {
	case atypV4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case atypV6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 0x00:
		l, err := r.ReadByte()
		if err != nil {
			return "", 0, err
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("bad atyp %#x", atyp)
	}
	portRaw := make([]byte, 2)
	if _, err := io.ReadFull(r, portRaw); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(portRaw), nil
}

func appendAddress(dst []byte, host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, atypV4)
			dst = append(dst, v4...)
		} else {
			dst = append(dst, atypV6)
			dst = append(dst, ip.To16()...)
		}
	} else {
		dst = append(dst, 0x00, byte(len(host)))
		dst = append(dst, host...)
	}
	return binary.BigEndian.AppendUint16(dst, port)
}

type packet struct {
	assoc     uint16
	pktID     uint16
	fragTotal byte
	fragID    byte
	host      string
	port      uint16
	hasAddr   bool
	data      []byte
}

func parsePacket(b []byte) (*packet, error) {
	if len(b) < 10 || b[0] != ver5 || b[1] != cmdPacket {
		return nil, fmt.Errorf("bad packet head")
	}
	p := &packet{
		assoc:     binary.BigEndian.Uint16(b[2:4]),
		pktID:     binary.BigEndian.Uint16(b[4:6]),
		fragTotal: b[6],
		fragID:    b[7],
	}
	size := int(binary.BigEndian.Uint16(b[8:10]))
	off := 10
	if len(b) > off && b[off] == atypNone {
		off++
	} else {
		if len(b) <= off {
			return nil, fmt.Errorf("truncated addr")
		}
		atyp := b[off]
		off++
		switch atyp {
		case atypV4:
			if len(b) < off+6 {
				return nil, fmt.Errorf("truncated v4")
			}
			p.host = net.IP(b[off : off+4]).String()
			off += 4
		case atypV6:
			if len(b) < off+18 {
				return nil, fmt.Errorf("truncated v6")
			}
			p.host = net.IP(b[off : off+16]).String()
			off += 16
		case 0x00:
			l := int(b[off])
			off++
			if len(b) < off+l+2 {
				return nil, fmt.Errorf("truncated domain")
			}
			p.host = string(b[off : off+l])
			off += l
		default:
			return nil, fmt.Errorf("bad atyp %#x", atyp)
		}
		p.port = binary.BigEndian.Uint16(b[off : off+2])
		off += 2
		p.hasAddr = true
	}
	if len(b) < off+size {
		return nil, fmt.Errorf("truncated data")
	}
	p.data = append([]byte(nil), b[off:off+size]...)
	return p, nil
}

func buildPacket(assoc, pktID uint16, fragTotal, fragID byte, host string, port uint16, data []byte) []byte {
	out := make([]byte, 0, 12+len(data))
	out = append(out, ver5, cmdPacket)
	out = binary.BigEndian.AppendUint16(out, assoc)
	out = binary.BigEndian.AppendUint16(out, pktID)
	out = append(out, fragTotal, fragID)
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	if host == "" {
		out = append(out, atypNone)
	} else {
		out = appendAddress(out, host, port)
	}
	return append(out, data...)
}

// ---- 会话 ----

type assocState struct {
	conn quic.Connection
	uc   *net.UDPConn
}

// server 持有单个 QUIC 连接的 UDP 关联表与分片重组状态。
type server struct {
	conn quic.Connection

	mu     sync.Mutex
	assocs map[uint16]*assocState

	fragMu    sync.Mutex
	fragID    uint16
	fragTotal byte
	fragSlots map[byte][]byte
	fragAddr  string
	fragPort  uint16
	fragHas   bool
}

func newServer(conn quic.Connection) *server {
	return &server{conn: conn, assocs: map[uint16]*assocState{}, fragSlots: map[byte][]byte{}}
}

func (s *server) serve(authOK chan struct{}, once *sync.Once) {
	go s.serveUni(authOK, once)
	go s.serveConnect(authOK)
	s.serveDatagram(authOK)
}

func (s *server) serveUni(authOK chan struct{}, once *sync.Once) {
	conn := s.conn
	for {
		stream, err := conn.AcceptUniStream(conn.Context())
		if err != nil {
			return
		}
		go func(stream quic.ReceiveStream) {
			defer stream.CancelRead(0)
			r := bufio.NewReaderSize(stream, 16<<10)
			ver, typ, err := readCommandHead(r)
			if err != nil {
				return
			}
			if ver != ver5 {
				_ = conn.CloseWithError(badCommand, "bad version")
				return
			}
			switch typ {
			case cmdAuth:
				var uuidBytes [16]byte
				var token [32]byte
				if _, err := io.ReadFull(r, uuidBytes[:]); err != nil {
					_ = conn.CloseWithError(badCommand, "read uuid")
					return
				}
				if _, err := io.ReadFull(r, token[:]); err != nil {
					_ = conn.CloseWithError(badCommand, "read token")
					return
				}
				tlsState := conn.ConnectionState().TLS
				expected, err := tlsState.ExportKeyingMaterial(
					string(uuidBytes[:]), []byte(cfgPassword), 32)
				if err != nil || uuidBytes != cfgUUID || !equalBytes(token[:], expected) {
					logLine("AUTH-FAIL")
					_ = conn.CloseWithError(authFailedCode, "invalid credentials")
					return
				}
				once.Do(func() { close(authOK) })
			case cmdDissociate:
				raw := make([]byte, 2)
				if _, err := io.ReadFull(r, raw); err != nil {
					return
				}
				id := binary.BigEndian.Uint16(raw)
				s.mu.Lock()
				if a, ok := s.assocs[id]; ok {
					_ = a.uc.Close()
					delete(s.assocs, id)
				}
				s.mu.Unlock()
			default:
				_ = conn.CloseWithError(badCommand, fmt.Sprintf("unexpected uni cmd %#x", typ))
			}
		}(stream)
	}
}

func (s *server) serveConnect(authOK chan struct{}) {
	conn := s.conn
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		go func(stream quic.Stream) {
			r := bufio.NewReaderSize(stream, 16<<10)
			ver, typ, err := readCommandHead(r)
			if err != nil {
				stream.CancelRead(0)
				return
			}
			if ver != ver5 || typ != cmdConnect {
				_ = conn.CloseWithError(badCommand, "unexpected stream cmd")
				return
			}
			host, port, err := readAddress(r)
			if err != nil {
				_ = conn.CloseWithError(badCommand, err.Error())
				return
			}
			select {
			case <-authOK:
			case <-conn.Context().Done():
				return
			case <-time.After(10 * time.Second):
				_ = conn.CloseWithError(authTimeout, "auth timeout")
				return
			}
			target, err := dialTCP(net.JoinHostPort(host, fmt.Sprint(port)))
			if err != nil {
				logLine("CONNECT-FAIL %s:%d %v", host, port, err)
				stream.CancelRead(0)
				stream.CancelWrite(0)
				return
			}
			logLine("TCP target=%s:%d", host, port)
			defer target.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = io.Copy(target, r)
				if tcp, ok := target.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
			}()
			_, _ = io.Copy(stream, target)
			_ = stream.Close()
			<-done
			stream.CancelRead(0)
		}(stream)
	}
}

func (s *server) serveDatagram(authOK chan struct{}) {
	conn := s.conn
	for {
		msg, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}
		func(msg []byte) {
			defer conn.ReleaseDatagram(msg)
			if len(msg) < 2 || msg[0] != ver5 {
				return
			}
			if msg[1] == cmdHeartbeat {
				return
			}
			if msg[1] != cmdPacket {
				return
			}
			p, err := parsePacket(msg)
			if err != nil {
				return
			}
			select {
			case <-authOK:
			case <-conn.Context().Done():
				return
			case <-time.After(10 * time.Second):
				_ = conn.CloseWithError(authTimeout, "auth timeout")
				return
			}
			data, host, port, ok := s.reassemble(p)
			if !ok || host == "" {
				return
			}
			a := s.assoc(p.assoc)
			if a == nil {
				return
			}
			ra, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
			if err != nil {
				return
			}
			if _, err := a.uc.WriteToUDP(data, ra); err != nil {
				return
			}
			logLine("UDP target=%s:%d", host, port)
		}(msg)
	}
}

func (s *server) assoc(id uint16) *assocState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.assocs[id]; ok {
		return a
	}
	uc, err := listenUDP()
	if err != nil {
		return nil
	}
	a := &assocState{conn: s.conn, uc: uc}
	s.assocs[id] = a
	go func() {
		buf := make([]byte, 65536)
		var pktID uint16
		for {
			n, src, err := uc.ReadFromUDP(buf)
			if err != nil {
				logLine("UDP-READ-END %v", err)
				return
			}
			if err := sendPacket(s.conn, id, src.IP.String(), uint16(src.Port), buf[:n]); err != nil {
				logLine("UDP-SEND-FAIL %v", err)
				return
			}
			_ = pktID
		}
	}()
	return a
}

func (s *server) reassemble(p *packet) (data []byte, host string, port uint16, ok bool) {
	if p.fragTotal <= 1 {
		if !p.hasAddr {
			return nil, "", 0, false
		}
		return p.data, p.host, p.port, true
	}
	s.fragMu.Lock()
	defer s.fragMu.Unlock()
	if p.pktID != s.fragID || p.fragTotal != s.fragTotal {
		s.fragID = p.pktID
		s.fragTotal = p.fragTotal
		s.fragSlots = map[byte][]byte{}
		s.fragHas = false
	}
	if p.fragID == 0 {
		if !p.hasAddr {
			return nil, "", 0, false
		}
		s.fragAddr, s.fragPort, s.fragHas = p.host, p.port, true
	}
	if _, dup := s.fragSlots[p.fragID]; dup {
		return nil, "", 0, false
	}
	s.fragSlots[p.fragID] = p.data
	if !s.fragHas || len(s.fragSlots) != int(s.fragTotal) {
		return nil, "", 0, false
	}
	var out []byte
	for i := byte(0); i < s.fragTotal; i++ {
		slot, okSlot := s.fragSlots[i]
		if !okSlot {
			return nil, "", 0, false
		}
		out = append(out, slot...)
	}
	s.fragSlots = map[byte][]byte{}
	s.fragHas = false
	return out, s.fragAddr, s.fragPort, true
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sendPacket 把回包发给客户端；超出 datagram 上限时按协议分片（首片带地址，
// 其余 ATYP=0xff），与 Go 客户端 frag.go 的规则一致。
func sendPacket(conn quic.Connection, assoc uint16, host string, port uint16, data []byte) error {
	attempt := buildPacket(assoc, 0, 1, 0, host, port, data)
	err := conn.SendDatagram(attempt)
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	// maxDataLen 是整帧预算；减去固定头（10B）+ 首片地址长度得到单片数据上限。
	addrLen := 1 + 2
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			addrLen += 4
		} else {
			addrLen += 16
		}
	} else {
		addrLen += 1 + len(host)
	}
	fragSize := int(tooLarge.MaxDataLen) - 10 - addrLen
	if fragSize <= 0 {
		return fmt.Errorf("fragment budget %d", fragSize)
	}
	total := (len(data) + fragSize - 1) / fragSize
	if total > 255 {
		return fmt.Errorf("too many fragments: %d", total)
	}
	pktID := uint16(1 + time.Now().UnixNano()%65534)
	for i := 0; i < total; i++ {
		end := (i + 1) * fragSize
		if end > len(data) {
			end = len(data)
		}
		var out []byte
		if i == 0 {
			out = buildPacket(assoc, pktID, byte(total), 0, host, port, data[:end])
		} else {
			out = buildPacket(assoc, pktID, byte(total), byte(i), "", 0, data[i*fragSize:end])
		}
		if err := conn.SendDatagram(out); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	port := flag.Int("port", 18543, "listen port")
	uuidStr := flag.String("uuid", "", "uuid")
	password := flag.String("password", "", "password")
	certPath := flag.String("cert", "", "cert pem")
	keyPath := flag.String("key", "", "key pem")
	logPath := flag.String("log", "/tmp/tuic-server.log", "log file")
	flag.Parse()

	cfgPassword = *password
	compact := strings.ReplaceAll(*uuidStr, "-", "")
	raw, err := hex.DecodeString(compact)
	if err != nil || len(raw) != 16 {
		fmt.Fprintf(os.Stderr, "bad uuid %q\n", *uuidStr)
		os.Exit(2)
	}
	copy(cfgUUID[:], raw)

	logFile, err = os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cert:", err)
		os.Exit(2)
	}
	listener, err := quic.ListenAddr(
		fmt.Sprintf("127.0.0.1:%d", *port),
		&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		&quic.Config{EnableDatagrams: true, Allow0RTT: true, MaxIdleTimeout: 30 * time.Second},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	logLine("tuic-server listening on 127.0.0.1:%d", *port)
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		authOK := make(chan struct{})
		once := &sync.Once{}
		go newServer(conn).serve(authOK, once)
	}
}
