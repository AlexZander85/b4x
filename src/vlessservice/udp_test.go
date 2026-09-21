package vlessservice

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/reserve"
	"github.com/daniellavrushin/b4/socks5"
)

func startUDPEcho(t *testing.T) string {
	t.Helper()
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], addr)
		}
	}()
	return echo.LocalAddr().String()
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestDialUDPThroughHelperSOCKS5(t *testing.T) {
	echoAddr := startUDPEcho(t)

	port := freeTCPPort(t)
	scfg := config.NewConfig()
	scfg.System.Socks5.Enabled = true
	scfg.System.Socks5.BindAddress = "127.0.0.1"
	scfg.System.Socks5.Port = port
	srv := socks5.NewServer(&scfg)
	if err := srv.Start(); err != nil {
		t.Fatalf("socks5 server: %v", err)
	}
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)

	cfg := config.NewConfig()
	off := false
	cfg.System.Vless.BundledSources = &off
	cfg.System.Vless.UDP = true
	cfg.System.Vless.SocksAddr = net.JoinHostPort("127.0.0.1", itoa(port))

	rt, err := Build(&cfg, Options{SocksDial: func(context.Context, string, string) (net.Conn, error) {
		return nil, nil // unused: UDP path builds its own ASSOCIATE
	}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !rt.SupportsUDP() {
		t.Fatal("supports_udp should be true (helper + udp)")
	}
	conn, err := rt.DialUDP(context.Background(), netip.MustParseAddrPort(echoAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()
	want := []byte("udp-hello-vless")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("udp echo = %q want %q", got, want)
	}
}

func TestSupportsUDPGating(t *testing.T) {
	// udp disabled -> false
	cfg := config.NewConfig()
	off := false
	cfg.System.Vless.BundledSources = &off
	rt, err := Build(&cfg, Options{SocksDial: func(context.Context, string, string) (net.Conn, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if rt.SupportsUDP() {
		t.Fatal("udp default must be false")
	}
	if _, err := rt.DialUDP(context.Background(), netip.MustParseAddrPort("1.1.1.1:443")); err != reserve.ErrCarrierNoUDP {
		t.Fatalf("DialUDP err=%v want ErrCarrierNoUDP", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [6]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
