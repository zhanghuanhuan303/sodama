// zz_proto_check_test.go — P5 G2 生态兼容检查：用 dae 实际依赖的 outbound
// （olicesx fork）客户端，连 lab 的独立 Python 服务端，验证「不是只跟自家实现对得上」。
//
// 这个文件由 lab/proto-check/run.sh 同步进 parity 的 dae-work 副本里运行；
// 环境变量：PROTO_LINK（vless:// 或 vmess:// 分享链接）。
package protocheck

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	// 协议 dialer 在各自包的 init() 里注册（dae 侧也是这么接进来的）
	_ "github.com/daeuniverse/outbound/protocol/vless"
	_ "github.com/daeuniverse/outbound/protocol/vmess"
)

func newDialer(t *testing.T) netproxy.Dialer {
	t.Helper()
	link := os.Getenv("PROTO_LINK")
	if link == "" {
		t.Skip("PROTO_LINK 未设置")
	}
	d, _, err := v2ray.NewV2Ray(&dialer.ExtraOption{TlsImplementation: "tls"}, direct.SymmetricDirect, link)
	if err != nil {
		t.Fatalf("NewV2Ray(%s): %v", link, err)
	}
	return d
}

func TestProtoCheckTCP(t *testing.T) {
	d := newDialer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer conn.Close()
	payload := []byte("proto-check-tcp")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: %q", buf)
	}
	fmt.Println("TCP echo ok:", string(buf))
}

func TestProtoCheckUDP(t *testing.T) {
	d := newDialer(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], peer)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := []byte("proto-check-udp")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo mismatch: %q", buf[:n])
	}
	fmt.Println("UDP echo ok:", string(buf[:n]))
}
