// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

// hy2-server：hysteria2 独立参考服务端（P5-G3b，lab 用；quic-go fork + http3）。
//
// 从 olicesx/outbound 的 protocol/hysteria2/e2e_test.go 的服务端移植为独立进程：
//   - 认证：HTTP/3 POST /auth，校验 Hysteria-Auth，回 :status 233 + Hysteria-UDP: true；
//   - TCP：StreamHijacker 截获 0x401 双向流，解析地址帧、拨号、回 status 帧后裸转发；
//   - UDP：QUIC DATAGRAM（SessionID/PacketID/FragID/FragCount + 地址），按 1200 预算分片。
// 上游 TCP/UDP socket 打 SO_MARK=0x233（best-effort），避免 lab 拓扑里被 sodama
// 数据面二次捕获；本机非 root 运行时 EPERM 降级为告警。
//
// 用法： hy2-server -port 18753 -auth testpass -cert <pem> -key <pem> -log <logfile>
// P5-G3b+：-obfs-password <psk> 启用 salamander；-hop-ports <443,8443-8450> 多 socket
// mux（udphop 服务端侧：回复从该客户端最后一次来包的 socket 发出）。
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	obfs "github.com/daeuniverse/outbound/protocol/hysteria2/obfs"
	udphop "github.com/daeuniverse/outbound/protocol/hysteria2/udphop"
	quic "github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
)

const (
	hy2FrameTCPRequest uint64 = 0x401
	hy2StatusAuthOK           = 233

	hy2MaxAddressLength = 2048
	hy2MaxPaddingLength = 4096

	soMark = 36
	mark   = 0x233
)

var (
	cfgAuth string
	logFile *os.File
	logMu   sync.Mutex
)

func logLine(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintf(logFile, format+"\n", args...)
}

// setMarkControl 给拨号 socket 打 SO_MARK（非 root 降级）。
func setMarkControl(_ string, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMark, mark)
	}); err != nil {
		return err
	}
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

// ---- 多端口 mux（udphop 服务端侧） ----

// muxPacketConn 把多个 UDP socket 合成一个 net.PacketConn：读从任意 socket 入队，
// 写回复到「该客户端最后一次来包的 socket」——模拟端口范围转发/NAT 的行为。
type muxPacketConn struct {
	conns     []*net.UDPConn
	queue     chan muxPacket
	closed    chan struct{}
	closeOnce sync.Once

	mu        sync.Mutex
	lastLocal map[string]*net.UDPConn
	deadline  atomic.Value // time.Time

	local *net.UDPConn
}

type muxPacket struct {
	data  []byte
	addr  net.Addr
	local *net.UDPConn
	err   error
}

func newMuxPacketConn(conns []*net.UDPConn) *muxPacketConn {
	m := &muxPacketConn{
		conns:     conns,
		queue:     make(chan muxPacket, 256),
		closed:    make(chan struct{}),
		lastLocal: make(map[string]*net.UDPConn),
		local:     conns[0],
	}
	m.deadline.Store(time.Time{})
	for _, c := range conns {
		go m.recvLoop(c)
	}
	return m
}

func (m *muxPacketConn) recvLoop(c *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-m.closed:
				return
			default:
			}
			select {
			case m.queue <- muxPacket{err: err, local: c}:
			case <-m.closed:
			}
			return
		}
		data := append([]byte(nil), buf[:n]...)
		m.mu.Lock()
		m.lastLocal[addr.String()] = c
		m.mu.Unlock()
		select {
		case m.queue <- muxPacket{data: data, addr: addr, local: c}:
		case <-m.closed:
			return
		}
	}
}

func (m *muxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		d := m.deadline.Load().(time.Time)
		var timeout <-chan time.Time
		if !d.IsZero() {
			if time.Now().After(d) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(time.Until(d))
			defer t.Stop()
			timeout = t.C
		}
		select {
		case pkt := <-m.queue:
			if pkt.err != nil {
				return 0, nil, pkt.err
			}
			return copy(p, pkt.data), pkt.addr, nil
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-m.closed:
			return 0, nil, net.ErrClosed
		}
	}
}

func (m *muxPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	m.mu.Lock()
	c := m.lastLocal[addr.String()]
	m.mu.Unlock()
	if c == nil {
		c = m.local
	}
	return c.WriteTo(p, addr)
}

func (m *muxPacketConn) Close() error {
	m.closeOnce.Do(func() {
		close(m.closed)
		for _, c := range m.conns {
			_ = c.Close()
		}
	})
	return nil
}

func (m *muxPacketConn) LocalAddr() net.Addr { return m.local.LocalAddr() }

func (m *muxPacketConn) SetDeadline(t time.Time) error {
	_ = m.SetReadDeadline(t)
	return nil
}

func (m *muxPacketConn) SetReadDeadline(t time.Time) error {
	m.deadline.Store(t)
	return nil
}

func (m *muxPacketConn) SetWriteDeadline(time.Time) error { return nil }

// ---- wire 编解码（与 client/internal/protocol 对拍） ----

func hy2Varint(r io.Reader) (uint64, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	prefix := b[0] >> 6
	b[0] &= 0x3f
	val := uint64(b[0])
	for i := 0; i < (1<<prefix)-1; i++ {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		val = val<<8 | uint64(b[0])
	}
	return val, nil
}

func hy2SliceVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("varint: empty")
	}
	prefix := b[0] >> 6
	n := 1 << prefix
	if len(b) < n {
		return 0, 0, fmt.Errorf("varint: truncated")
	}
	val := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		val = val<<8 | uint64(b[i])
	}
	return val, n, nil
}

func hy2AppendVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v <= 1073741823:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

func readHy2TCPRequest(r io.Reader) (string, error) {
	addrLen, err := hy2Varint(r)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > hy2MaxAddressLength {
		return "", fmt.Errorf("invalid address length %d", addrLen)
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBuf); err != nil {
		return "", err
	}
	padLen, err := hy2Varint(r)
	if err != nil {
		return "", err
	}
	if padLen > hy2MaxPaddingLength {
		return "", fmt.Errorf("invalid padding length %d", padLen)
	}
	if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
		return "", err
	}
	return string(addrBuf), nil
}

func writeHy2TCPResponse(w io.Writer, ok bool, msg string, padLen int) error {
	if padLen < 0 || padLen > hy2MaxPaddingLength {
		return fmt.Errorf("invalid padding length %d", padLen)
	}
	buf := make([]byte, 0, 1+len(msg)+2*10+padLen)
	if ok {
		buf = append(buf, 0)
	} else {
		buf = append(buf, 1)
	}
	buf = hy2AppendVarint(buf, uint64(len(msg)))
	buf = append(buf, msg...)
	buf = hy2AppendVarint(buf, uint64(padLen))
	buf = append(buf, make([]byte, padLen)...)
	_, err := w.Write(buf)
	return err
}

const hy2UDPHeaderSize = 8

type hy2UDPMessage struct {
	SessionID uint32
	PacketID  uint16
	FragID    uint8
	FragCount uint8
	Addr      string
	Data      []byte
}

func (m *hy2UDPMessage) headerSize() int {
	return hy2UDPHeaderSize + 1 + len(m.Addr) + 1
}

func parseHy2UDPMessage(buf []byte) (*hy2UDPMessage, error) {
	if len(buf) < hy2UDPHeaderSize {
		return nil, fmt.Errorf("datagram header too short: %d", len(buf))
	}
	m := &hy2UDPMessage{
		SessionID: binary.BigEndian.Uint32(buf[0:4]),
		PacketID:  binary.BigEndian.Uint16(buf[4:6]),
		FragID:    buf[6],
		FragCount: buf[7],
	}
	addrLen, skip, err := hy2SliceVarint(buf[8:])
	if err != nil {
		return nil, err
	}
	if addrLen == 0 || addrLen > hy2MaxAddressLength {
		return nil, fmt.Errorf("invalid datagram address length %d", addrLen)
	}
	rest := buf[8+skip:]
	if len(rest) < int(addrLen) {
		return nil, fmt.Errorf("datagram address truncated")
	}
	m.Addr = string(rest[:addrLen])
	m.Data = rest[addrLen:]
	return m, nil
}

func serializeHy2UDPMessage(b []byte, m *hy2UDPMessage) []byte {
	b = binary.BigEndian.AppendUint32(b, m.SessionID)
	b = binary.BigEndian.AppendUint16(b, m.PacketID)
	b = append(b, m.FragID, m.FragCount)
	b = hy2AppendVarint(b, uint64(len(m.Addr)))
	b = append(b, m.Addr...)
	return append(b, m.Data...)
}

// ---- 服务端状态 ----

type hy2FragSet struct {
	count uint8
	got   uint8
	size  int
	parts [][]byte
}

type hy2UDPSession struct {
	sock *net.UDPConn
	// frag 保存客户端->服务端方向的部分分片（按 PacketID）。由 connState.mu 保护。
	frag map[uint16]*hy2FragSet
	// replyPktID 是服务端->客户端分片的 PacketID 计数器。由 connState.mu 保护。
	replyPktID uint32
	// logged 让每个会话只在首个数据报上打印一次目标，避免日志刷屏。
	logged bool
}

type hy2ConnState struct {
	srv  *hy2Server
	conn quic.Connection
	// authorized 在 auth handler 通过后置位；未通过连接的流/数据报全部拒绝。
	authorized atomic.Bool

	mu       sync.Mutex
	sessions map[uint32]*hy2UDPSession
}

func (st *hy2ConnState) pumpDatagrams() {
	for {
		buf, err := st.conn.ReceiveDatagram(context.Background())
		if err != nil {
			st.closeAllSessions()
			return
		}
		if !st.authorized.Load() {
			st.conn.ReleaseDatagram(buf)
			continue
		}
		msg, perr := parseHy2UDPMessage(buf)
		st.conn.ReleaseDatagram(buf)
		if perr != nil {
			continue
		}
		st.handleUDPMessage(msg)
	}
}

func (st *hy2ConnState) handleUDPMessage(msg *hy2UDPMessage) {
	sess := st.session(msg.SessionID)
	if sess == nil {
		return
	}
	if msg.FragCount > 1 {
		if data, ok := st.feedFragment(sess, msg); ok {
			st.sendToTarget(sess, msg.Addr, data)
		}
		return
	}
	st.sendToTarget(sess, msg.Addr, msg.Data)
}

func (st *hy2ConnState) sendToTarget(sess *hy2UDPSession, addr string, data []byte) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return
	}
	if !sess.logged {
		sess.logged = true
		logLine("UDP target=%s", addr)
	}
	udpAddr := &net.UDPAddr{IP: ap.Addr().AsSlice(), Port: int(ap.Port())}
	_, _ = sess.sock.WriteToUDP(data, udpAddr)
}

func (st *hy2ConnState) feedFragment(sess *hy2UDPSession, msg *hy2UDPMessage) ([]byte, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if sess.frag == nil {
		sess.frag = make(map[uint16]*hy2FragSet)
	}
	set, ok := sess.frag[msg.PacketID]
	if !ok || set.count != msg.FragCount {
		set = &hy2FragSet{count: msg.FragCount, parts: make([][]byte, msg.FragCount)}
		sess.frag[msg.PacketID] = set
	}
	if int(msg.FragID) >= len(set.parts) {
		return nil, false
	}
	if set.parts[msg.FragID] == nil {
		set.parts[msg.FragID] = append([]byte(nil), msg.Data...)
		set.got++
		set.size += len(msg.Data)
	}
	if int(set.got) != int(set.count) {
		return nil, false
	}
	data := make([]byte, 0, set.size)
	for _, part := range set.parts {
		data = append(data, part...)
	}
	delete(sess.frag, msg.PacketID)
	return data, true
}

func (st *hy2ConnState) session(id uint32) *hy2UDPSession {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.srv.closed.Load() {
		return nil
	}
	if sess, ok := st.sessions[id]; ok {
		return sess
	}
	sock, err := listenUDP()
	if err != nil {
		return nil
	}
	sess := &hy2UDPSession{sock: sock}
	st.sessions[id] = sess
	go st.pumpReplies(id, sess)
	return sess
}

func (st *hy2ConnState) pumpReplies(id uint32, sess *hy2UDPSession) {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := sess.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		st.sendReply(id, sess, raddr.String(), buf[:n])
	}
}

func (st *hy2ConnState) sendReply(id uint32, sess *hy2UDPSession, from string, data []byte) {
	msg := &hy2UDPMessage{SessionID: id, FragID: 0, FragCount: 1, Addr: from, Data: data}
	if err := st.conn.SendDatagram(serializeHy2UDPMessage(nil, msg)); err == nil {
		return
	}
	st.mu.Lock()
	sess.replyPktID++
	pktID := uint16(sess.replyPktID % 0xffff)
	if pktID == 0 {
		pktID = 1
	}
	st.mu.Unlock()
	budget := st.srv.datagramBudget()
	if budget <= msg.headerSize()+1 {
		return
	}
	maxPayload := budget - msg.headerSize()
	fragCount := uint8((len(data) + maxPayload - 1) / maxPayload)
	off := 0
	for fragID := uint8(0); fragID < fragCount; fragID++ {
		end := off + maxPayload
		if end > len(data) {
			end = len(data)
		}
		frag := &hy2UDPMessage{
			SessionID: id,
			PacketID:  pktID,
			FragID:    fragID,
			FragCount: fragCount,
			Addr:      from,
			Data:      data[off:end],
		}
		off = end
		if err := st.conn.SendDatagram(serializeHy2UDPMessage(nil, frag)); err != nil {
			return
		}
	}
}

func (st *hy2ConnState) closeAllSessions() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, sess := range st.sessions {
		_ = sess.sock.Close()
	}
	st.sessions = nil
}

type hy2Server struct {
	password string
	closed   atomic.Bool

	mu    sync.Mutex
	conns map[quic.ConnectionTracingID]*hy2ConnState

	srv *http3.Server
}

func (s *hy2Server) datagramBudget() int { return 1200 }

func (s *hy2Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	st, ok := r.Context().Value(hy2ConnStateKey{}).(*hy2ConnState)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Hysteria-UDP", "true")
	w.Header().Set("Hysteria-CC-RX", "0")
	if r.Header.Get("Hysteria-Auth") != s.password {
		logLine("AUTH-FAIL %s", r.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	st.authorized.Store(true)
	logLine("AUTH-OK %s", r.RemoteAddr)
	w.WriteHeader(hy2StatusAuthOK)
}

func (s *hy2Server) serveTCPRequest(stream quic.Stream) {
	defer stream.Close()
	deadline := time.Now().Add(60 * time.Second)
	_ = stream.SetDeadline(deadline)
	addr, err := readHy2TCPRequest(stream)
	if err != nil {
		logLine("TCP-REQ-FAIL %v", err)
		return
	}
	target, err := dialTCP(addr)
	if err != nil {
		logLine("CONNECT-FAIL %s %v", addr, err)
		_ = writeHy2TCPResponse(stream, false, err.Error(), 128)
		return
	}
	logLine("TCP target=%s", addr)
	defer target.Close()
	_ = target.SetDeadline(deadline)
	if err := writeHy2TCPResponse(stream, true, "", 128); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(target, stream)
		if tc, ok := target.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	_, _ = io.Copy(stream, target)
}

type hy2ConnStateKey struct{}

func (s *hy2Server) registerConn(ctx context.Context, c quic.Connection) *hy2ConnState {
	st := &hy2ConnState{srv: s, conn: c, sessions: make(map[uint32]*hy2UDPSession)}
	    if id, ok := ctx.Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID); ok {
		s.mu.Lock()
		s.conns[id] = st
		s.mu.Unlock()
		context.AfterFunc(ctx, func() { s.dropConn(id) })
		context.AfterFunc(ctx, func() {
			logLine("CONN-CLOSED %v", c.Context().Err())
		})
	}
	go st.pumpDatagrams()
	return st
}

func (s *hy2Server) connState(id quic.ConnectionTracingID) *hy2ConnState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns[id]
}

func (s *hy2Server) dropConn(id quic.ConnectionTracingID) {
	s.mu.Lock()
	st := s.conns[id]
	delete(s.conns, id)
	s.mu.Unlock()
	if st != nil {
		st.closeAllSessions()
	}
}

func main() {
	port := flag.Int("port", 18753, "listen port")
	auth := flag.String("auth", "", "auth password")
	certPath := flag.String("cert", "", "cert pem")
	keyPath := flag.String("key", "", "key pem")
	logPath := flag.String("log", "/tmp/hy2-server.log", "log file")
	obfsPassword := flag.String("obfs-password", "", "salamander PSK (empty = no obfs)")
	hopPorts := flag.String("hop-ports", "", "additional UDP ports for udphop, e.g. 18754,18755-18756")
	flag.Parse()

	var err error
	logFile, err = os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	cfgAuth = *auth
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cert:", err)
		os.Exit(2)
	}
	addr := "127.0.0.1:" + strconv.Itoa(*port)
	mainConn, err := net.ListenUDP("udp", mustResolveUDP(addr))
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	conns := []*net.UDPConn{mainConn}
	if *hopPorts != "" {
		pu := udphop.ParsePortUnion(*hopPorts)
		if pu == nil {
			fmt.Fprintln(os.Stderr, "bad hop-ports:", *hopPorts)
			os.Exit(2)
		}
		for _, p := range pu.Ports() {
			c, err := net.ListenUDP("udp", mustResolveUDP("127.0.0.1:"+strconv.Itoa(int(p))))
			if err != nil {
				fmt.Fprintln(os.Stderr, "listen hop:", p, err)
				os.Exit(1)
			}
			conns = append(conns, c)
		}
	}
	var pkt net.PacketConn
	if len(conns) == 1 {
		pkt = conns[0]
	} else {
		pkt = newMuxPacketConn(conns)
		logLine("udphop mux on %d sockets (ports %s)", len(conns), *hopPorts)
	}
	if *obfsPassword != "" {
		wrapped, err := obfs.WrapPacketConnSalamander(pkt, []byte(*obfsPassword))
		if err != nil {
			fmt.Fprintln(os.Stderr, "obfs:", err)
			os.Exit(2)
		}
		pkt = wrapped
		logLine("salamander obfs enabled")
	}

	s := &hy2Server{password: *auth, conns: make(map[quic.ConnectionTracingID]*hy2ConnState)}
	s.srv = &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{http3.NextProtoH3},
			MinVersion:   tls.VersionTLS13,
		},
		// QUIC 层 datagram 必须开（UDP relay 走裸 QUIC datagram），但 HTTP/3 层的
		// H3_DATAGRAM 不能声明：fork 的 http3 客户端一看到就会启动 receiveDatagrams
		// 循环把裸 datagram 吃掉。真实 hysteria2 服务端同理。
		EnableDatagrams: false,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
			MaxIdleTimeout:  60 * time.Second,
		},
		Handler: http.HandlerFunc(s.handleAuth),
		// TCP 请求以 0x401 帧类型开头的裸双向流到达，由 StreamHijacker 接管。
		StreamHijacker: func(ft http3.FrameType, id quic.ConnectionTracingID, stream quic.Stream, herr error) (bool, error) {
			if herr != nil {
				return false, herr
			}
			if uint64(ft) != hy2FrameTCPRequest {
				return false, nil
			}
			st := s.connState(id)
			if st == nil || !st.authorized.Load() {
				stream.CancelRead(1)
				stream.CancelWrite(1)
				return true, nil
			}
			go s.serveTCPRequest(stream)
			return true, nil
		},
		ConnContext: func(ctx context.Context, c quic.Connection) context.Context {
			st := s.registerConn(ctx, c)
			return context.WithValue(ctx, hy2ConnStateKey{}, st)
		},
	}
	logLine("hy2-server listening on %s", addr)
	go func() { _ = s.srv.Serve(pkt) }()
	select {}
}

func mustResolveUDP(addr string) *net.UDPAddr {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve:", err)
		os.Exit(1)
	}
	return ua
}
