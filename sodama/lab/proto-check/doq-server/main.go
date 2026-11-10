// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

// doq-server：DoQ（RFC 9250）独立参考服务端（P18b，lab 用；quic-go）。
//
// 独立实现（不复用 dae/sodama 的代码），用于与 sodama 的 Rust/quinn DoQ 客户端
// 做跨实现验证：ALPN=doq，每查询一条双向流（2 字节长度分帧），转发到假 UDP DNS
// （127.0.0.1:5353）后原样回传；线上 DNS ID 保持 0（RFC 9250 §4.2.1）。
//
// 用法： doq-server -port 9053 -cert <cert.pem> -key <key.pem> \
//          -upstream 127.0.0.1:5353 -log <logfile>
//
// 日志（lab 断言用）：
//   DOQ-CONN                     新 QUIC 连接（连接复用：两次查询应只有 1 个 CONN）
//   DOQ-QUERY <qname> type=<n>   收到的查询
//   DOQ-ERR <msg>
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	quic "github.com/olicesx/quic-go"
)

var (
	port     = flag.Int("port", 9053, "listen port (127.0.0.1)")
	certFile = flag.String("cert", "", "cert.pem")
	keyFile  = flag.String("key", "", "key.pem")
	upstream = flag.String("upstream", "127.0.0.1:5353", "fake UDP DNS host:port")
	logFile  = flag.String("log", "/tmp/sodama-doq.txt", "query log")
)

var logMu sync.Mutex

func appendLog(line string) {
	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, line)
}

func parseQName(buf []byte) (string, uint16) {
	labels := []string{}
	off := 12
	for off < len(buf) && buf[off] != 0 {
		n := int(buf[off])
		if off+1+n > len(buf) {
			break
		}
		labels = append(labels, string(buf[off+1:off+1+n]))
		off += 1 + n
	}
	name := ""
	for i, l := range labels {
		if i > 0 {
			name += "."
		}
		name += l
	}
	if off+3 > len(buf) {
		return name, 0
	}
	return name, binary.BigEndian.Uint16(buf[off+1 : off+3])
}

func forward(query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", *upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func handleStream(s quic.Stream) {
	defer s.Close()
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	var lb [2]byte
	if _, err := io.ReadFull(s, lb[:]); err != nil {
		appendLog(fmt.Sprintf("DOQ-ERR 读长度: %v", err))
		return
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n == 0 || n > 65535 {
		appendLog(fmt.Sprintf("DOQ-ERR 长度非法: %d", n))
		return
	}
	query := make([]byte, n)
	if _, err := io.ReadFull(s, query); err != nil {
		appendLog(fmt.Sprintf("DOQ-ERR 读查询: %v", err))
		return
	}
	name, qtype := parseQName(query)
	appendLog(fmt.Sprintf("DOQ-QUERY %s type=%d", name, qtype))
	resp, err := forward(query)
	if err != nil {
		appendLog(fmt.Sprintf("DOQ-ERR 转发: %v", err))
		return
	}
	out := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
	copy(out[2:], resp)
	_ = s.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Write(out); err != nil {
		appendLog(fmt.Sprintf("DOQ-ERR 写应答: %v", err))
	}
}

func handleConn(conn quic.Connection) {
	defer conn.CloseWithError(0, "")
	appendLog("DOQ-CONN")
	ctx := context.Background()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go handleStream(stream)
	}
}

func main() {
	flag.Parse()
	if *certFile == "" || *keyFile == "" {
		log.Fatal("需要 -cert/-key")
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
	}
	ln, err := quic.ListenAddr(fmt.Sprintf("127.0.0.1:%d", *port), tlsConf, &quic.Config{
		MaxIdleTimeout: 60 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("doq-server listening on 127.0.0.1:%d -> udp %s\n", *port, *upstream)
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		go handleConn(conn)
	}
}
