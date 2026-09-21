package vlessservice

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/reserve"
)

// startEcho runs a TCP echo listener and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// startFakeSOCKS5 runs a minimal no-auth SOCKS5 CONNECT proxy (RFC 1928) so
// the real internal/socks dialer can be exercised without a network.
func startFakeSOCKS5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSOCKS5(c)
		}
	}()
	return ln.Addr().String()
}

func handleSOCKS5(c net.Conn) {
	defer c.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[1] != 0x01 { // only CONNECT
		_, _ = c.Write([]byte{0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(up, c) }()
	_, _ = io.Copy(c, up)
}

func TestDialStreamThroughFakeSOCKS5(t *testing.T) {
	echo := startEcho(t)
	socksAddr := startFakeSOCKS5(t)

	cfg := config.NewConfig()
	cfg.System.Vless.Enabled = true
	cfg.System.Vless.SocksAddr = socksAddr
	off := false
	cfg.System.Vless.BundledSources = &off // no network in tests
	rt, err := Build(&cfg, Options{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(rt.Stop)

	conn, err := rt.DialStream(context.Background(), netip.MustParseAddrPort(echo))
	if err != nil {
		t.Fatalf("dial through socks: %v", err)
	}
	defer conn.Close()
	want := []byte("hello-vless")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo = %q want %q", got, want)
	}
}

func TestCarrierContract(t *testing.T) {
	cfg := config.NewConfig()
	rt, err := Build(&cfg, Options{SocksDial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unused")
	}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rt.Kind() != reserve.KindVless {
		t.Fatalf("kind=%q", rt.Kind())
	}
	if rt.SupportsUDP() {
		t.Fatal("vless V1 is TCP-only")
	}
	if _, err := rt.DialUDP(context.Background(), netip.MustParseAddrPort("1.1.1.1:443")); !errors.Is(err, reserve.ErrCarrierNoUDP) {
		t.Fatalf("DialUDP err=%v want ErrCarrierNoUDP", err)
	}
	reserve.Reset()
	reserve.Register(rt)
	if _, ok := reserve.Lookup(reserve.KindVless); !ok {
		t.Fatal("registered kind=vless not found")
	}
	reserve.Reset()
}

// startFakeRawVLESS runs a minimal VLESS server: parse the version-0 header,
// answer with an empty response header, then echo.
func startFakeRawVLESS(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				head := make([]byte, 1+16+1)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				if n := int(head[17]); n > 0 {
					if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
						return
					}
				}
				rest := make([]byte, 1+2+1)
				if _, err := io.ReadFull(c, rest); err != nil {
					return
				}
				switch rest[3] {
				case 0x01:
					_, _ = io.ReadFull(c, make([]byte, 4))
				case 0x03:
					l := make([]byte, 1)
					_, _ = io.ReadFull(c, l)
					_, _ = io.ReadFull(c, make([]byte, int(l[0])))
				case 0x04:
					_, _ = io.ReadFull(c, make([]byte, 16))
				}
				_, _ = c.Write([]byte{0x00, 0x00})
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestInProcessDialStream(t *testing.T) {
	addr := startFakeRawVLESS(t)
	host, portStr, _ := net.SplitHostPort(addr)
	cfg := config.NewConfig()
	cfg.System.Vless.Enabled = true
	cfg.System.Vless.Client = "in-process"
	cfg.System.Vless.Nodes = []string{
		"vless://11111111-1111-1111-1111-111111111111@" + host + ":" + portStr + "?type=tcp&security=none#inproc",
	}
	rt, err := Build(&cfg, Options{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if st := rt.Status(); st.Client != "in-process" || st.ActiveNode == "" {
		t.Fatalf("status client=%q active=%q", st.Client, st.ActiveNode)
	}
	conn, err := rt.DialStream(context.Background(), netip.MustParseAddrPort("1.2.3.4:80"))
	if err != nil {
		t.Fatalf("in-process dial: %v", err)
	}
	defer conn.Close()
	want := []byte("inproc-echo")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo=%q want %q", got, want)
	}
}

func TestClientModeSelection(t *testing.T) {
	grpcNode := "vless://11111111-1111-1111-1111-111111111111@h.example.org:443?security=tls&type=grpc&serviceName=x&sni=www.microsoft.com#g"
	// auto with a non-in-process node falls back to the helper.
	cfg := config.NewConfig()
	off := false
	cfg.System.Vless.BundledSources = &off
	cfg.System.Vless.Subscriptions = nil
	cfg.System.Vless.Nodes = []string{grpcNode}
	rt, err := Build(&cfg, Options{SocksDial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unused")
	}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if st := rt.Status(); st.Client != "helper" {
		t.Fatalf("auto mode client=%q want helper", st.Client)
	}
	// explicit in-process without a capable node is a hard error.
	cfg.System.Vless.Client = "in-process"
	if _, err := Build(&cfg, Options{}); err == nil {
		t.Fatal("client=in-process without a capable node must error")
	}
}

func TestRefreshOncePopulatesNodesAndCache(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte(
		"vless://11111111-1111-1111-1111-111111111111@203.0.113.7:443?type=tcp&security=none#fetched"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, raw)
	}))
	defer srv.Close()

	cachePath := filepath.Join(t.TempDir(), "nodes.json")
	off := false
	cfg := config.NewConfig()
	cfg.System.Vless.BundledSources = &off
	cfg.System.Vless.Subscriptions = []string{srv.URL}
	cfg.System.Vless.NodeCachePath = cachePath
	inject := Options{
		SocksDial:  func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") },
		HTTPClient: srv.Client(),
	}
	rt, err := Build(&cfg, inject)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := rt.RefreshOnce(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if st := rt.Status(); st.NodeCount != 1 || st.LastError != "" {
		t.Fatalf("after refresh node_count=%d last_error=%q", st.NodeCount, st.LastError)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	// Offline restart: no sources, the cache alone provides the node.
	cfg.System.Vless.Subscriptions = nil
	rt2, err := Build(&cfg, Options{SocksDial: inject.SocksDial})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if st := rt2.Status(); st.NodeCount != 1 {
		t.Fatalf("offline cache node_count=%d want 1", st.NodeCount)
	}
}

func TestSelfLoopRefused(t *testing.T) {
	cfg := config.NewConfig()
	cfg.System.Vless.Nodes = []string{"vless://u@127.0.0.1:443?type=tcp#self"}
	dialed := false
	rt, err := Build(&cfg, Options{SocksDial: func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("must not dial")
	}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if st := rt.Status(); st.NodeCount != 1 {
		t.Fatalf("node_count=%d want 1", st.NodeCount)
	}
	if _, err := rt.DialStream(context.Background(), netip.MustParseAddrPort("127.0.0.1:8443")); !errors.Is(err, ErrVlessSelfLoop) {
		t.Fatalf("err=%v want ErrVlessSelfLoop", err)
	}
	if dialed {
		t.Fatal("self-loop must not reach the dialer")
	}
}
