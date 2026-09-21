package tor

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// verifyNoLeaks is the per-test goleak gate. The snowflake client library
// (with its process-lifetime kcp-go schedulers) lives in the separate
// torsnowflake package precisely so THIS package — imported by config —
// stays goroutine-clean by construction.
func verifyNoLeaks(t *testing.T) {
	t.Helper()
	goleak.VerifyNone(t)
}

// TT5 DoD (patch-plan §6): factory ParseArgs cases (all supported
// arguments + refusals), PT-proxy ACL (foreign target → 0x02, dead bridge
// → 0x04), pt-spec escaping (base64 '=' values), snowflake cache keys,
// connection limits, half-close; the fake-PTEndpoint unit stand replaces
// any end-to-end bridge; goleak.

// --- pt-spec stream codec ---

func TestParsePTArgsStream(t *testing.T) {
	// trailing NULs (tor pads the fields) + multi-token stream
	stream := "cert=abc==\x00\x00;iat-mode=1\x00"
	got := parsePTArgs(stream)
	if got["cert"] != "abc==" || got["iat-mode"] != "1" {
		t.Fatalf("args = %v", got)
	}
}

func TestParsePTArgsEscaping(t *testing.T) {
	// a value containing an escaped separator stays whole
	stream := `url=https\=x/;ver=a\;b`
	got := parsePTArgs(stream)
	if got["url"] != "https=x/" {
		t.Fatalf("url = %q", got["url"])
	}
	if got["ver"] != "a;b" {
		t.Fatalf("ver = %q", got["ver"])
	}
}

func TestPTStreamRoundtrip(t *testing.T) {
	args := map[string]string{
		"cert":     "QUJDREVGR0g==", // base64 padding survives
		"iat-mode": "1",
		"url":      "https://example.org/secret",
	}
	got := parsePTArgs(encodePTStream(args))
	if len(got) != len(args) {
		t.Fatalf("roundtrip lost entries: %v", got)
	}
	for k, v := range args {
		if got[k] != v {
			t.Fatalf("key %s: %q != %q", k, got[k], v)
		}
	}
}

// --- lyrebird factories: ParseArgs over the REAL libraries ---

func validObfs4Cert() string {
	// the bridge-line form: base64 with the trailing "==" stripped (the
	// lyrebird parser appends certSuffix before decoding)
	raw := make([]byte, 52)
	for i := range raw {
		raw[i] = byte(i)
	}
	return strings.TrimSuffix(base64.StdEncoding.EncodeToString(raw), "==")
}

func TestLyrebirdObfs4ParseArgs(t *testing.T) {
	r := NewPTRegistry(nil)
	f, ok := r.Get("obfs4")
	if !ok {
		t.Fatal("obfs4 factory missing")
	}
	if _, err := f.ParseArgs(map[string]string{"cert": validObfs4Cert(), "iat-mode": "0"}); err != nil {
		t.Fatalf("valid obfs4 args: %v", err)
	}
	if _, err := f.ParseArgs(map[string]string{"iat-mode": "0"}); err == nil {
		t.Fatal("obfs4 without cert must fail (fail-loud PT canon)")
	}
	if _, err := f.ParseArgs(map[string]string{"cert": "!!!not-base64!!!", "iat-mode": "0"}); err == nil {
		t.Fatal("garbage cert must fail")
	}
}

func TestLyrebirdWebtunnelParseArgs(t *testing.T) {
	r := NewPTRegistry(nil)
	f, ok := r.Get("webtunnel")
	if !ok {
		t.Fatal("webtunnel factory missing")
	}
	if _, err := f.ParseArgs(map[string]string{"url": "https://webtunnel.example/secret"}); err != nil {
		t.Fatalf("valid webtunnel args: %v", err)
	}
	if _, err := f.ParseArgs(map[string]string{"url": "ftp://bad.example/"}); err == nil {
		t.Fatal("non-http(s) url must fail")
	}
	// NOTE: lyrebird tolerates a missing url= at PARSE time (the failure
	// is loud at Dial); the b4x parser rejects a url-less webtunnel line
	// before it ever reaches this factory — see bridges_test.go.
}

func TestPTRegistryTransports(t *testing.T) {
	r := NewPTRegistry(nil)
	for _, name := range []string{"obfs4", "webtunnel", "meek_lite"} {
		if _, ok := r.Get(name); !ok {
			t.Fatalf("factory %q missing", name)
		}
	}
	if _, ok := r.Get("snowflake"); ok {
		t.Fatal("snowflake registered without an adapter")
	}
	r.Register(&fakeFactory{name: "snowflake"})
	if _, ok := r.Get("snowflake"); !ok {
		t.Fatal("snowflake registration failed")
	}
}

// --- snowflake adapter: config mapping + cache keys ---

// --- PT proxy: the fake-PTEndpoint unit stand ---

// fakeFactory records ParseArgs calls and returns scripted endpoints.
type fakeFactory struct {
	name     string
	endpoint PTEndpoint
	lastArgs map[string]string
	dialAddr string
}

func (f *fakeFactory) Name() string { return f.name }
func (f *fakeFactory) ParseArgs(args map[string]string) (PTEndpoint, error) {
	f.lastArgs = args
	return f.endpoint, nil
}

// fakeEndpoint dials a local echo listener through the injected dial func.
type fakeEndpoint struct {
	fail     bool
	lastDial string
	lastAddr string
}

func (e *fakeEndpoint) Dial(address string, dial func(addr string) (net.Conn, error)) (net.Conn, error) {
	e.lastAddr = address
	if e.fail {
		return nil, errors.New("dead bridge")
	}
	return dial("127.0.0.1:1")
}

func ptDialThrough(ln net.Listener) func(addr string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		var d net.Dialer
		return d.Dial("tcp", ln.Addr().String())
	}
}

// ptClient performs the raw PT SOCKS5 exchange (args in RFC 1929 fields).
func ptClientExchange(t *testing.T, addr, argStream, host string, port uint16) (byte, net.Conn, error) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return 0, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return 0, conn, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, conn, err
	}
	if resp[1] != 0x02 {
		return 0, conn, fmt.Errorf("method %#x", resp[1])
	}
	auth := []byte{0x01}
	login := argStream
	var pass string
	if len(login) > 255 {
		pass = login[255:]
		login = login[:255]
	}
	auth = append(auth, byte(len(login)))
	auth = append(auth, login...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := conn.Write(auth); err != nil {
		return 0, conn, err
	}
	aresp := make([]byte, 2)
	if _, err := io.ReadFull(conn, aresp); err != nil {
		return 0, conn, err
	}
	if aresp[1] != 0x00 {
		return 0, conn, fmt.Errorf("auth status %#x", aresp[1])
	}
	// CONNECT
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	var pb [2]byte
	pb[0] = byte(port >> 8)
	pb[1] = byte(port)
	req = append(req, pb[:]...)
	if _, err := conn.Write(req); err != nil {
		return 0, conn, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return 0, conn, err
	}
	// skip bound address
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return 0, conn, err
		}
		skip = int(l[0])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return 0, conn, err
	}
	_ = conn.SetDeadline(time.Time{})
	return head[1], conn, nil
}

func newPTTestProxy(t *testing.T, endpoint PTEndpoint, bridges []Bridge) (*PTProxy, *fakeFactory, func()) {
	t.Helper()
	echo := startDirectEcho(t)
	factory := &fakeFactory{name: "obfs4", endpoint: endpoint}
	registry := &PTRegistry{factories: map[string]TransportFactory{}}
	registry.Register(factory)
	dial := func(ctx context.Context, class ConnClass, host string, port uint16) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echo.Addr().String())
	}
	p, err := NewPTProxy(registry, func() []Bridge { return bridges }, dial)
	if err != nil {
		echo.Close()
		t.Fatalf("pt proxy: %v", err)
	}
	stop := func() {
		p.Stop()
		echo.Close()
	}
	return p, factory, stop
}

func TestPTProxyHappyPathCarriesArgs(t *testing.T) {
	defer verifyNoLeaks(t)
	endpoint := &fakeEndpoint{}
	bridges := []Bridge{{Transport: "obfs4", AddrPort: "45.66.35.35:443"}}
	p, factory, stop := newPTTestProxy(t, endpoint, bridges)
	defer stop()

	rep, conn, err := ptClientExchange(t, p.Addr(), "cert="+validObfs4Cert()+";iat-mode=0", "45.66.35.35", 443)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer conn.Close()
	if rep != 0x00 {
		t.Fatalf("reply = %#x, want 0", rep)
	}
	if factory.lastArgs["cert"] != validObfs4Cert() || factory.lastArgs["iat-mode"] != "0" {
		t.Fatalf("args through RFC1929 = %v", factory.lastArgs)
	}
	// The bridge endpoint must reach the transport factory: obfs4 dials
	// exactly this target (a "" address fails every handshake).
	if endpoint.lastAddr != "45.66.35.35:443" {
		t.Fatalf("bridge address to endpoint = %q, want 45.66.35.35:443", endpoint.lastAddr)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if string(buf) != "echo" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestPTProxyACLForeignTarget(t *testing.T) {
	defer verifyNoLeaks(t)
	endpoint := &fakeEndpoint{}
	bridges := []Bridge{{Transport: "obfs4", AddrPort: "45.66.35.35:443"}}
	p, _, stop := newPTTestProxy(t, endpoint, bridges)
	defer stop()

	// scenario 21: a target outside the active bridge set → 0x02, and
	// nothing leaves the process (the fake endpoint never dials).
	rep, conn, err := ptClientExchange(t, p.Addr(), "cert=x", "203.0.113.99", 443)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer conn.Close()
	if rep != 0x02 {
		t.Fatalf("reply = %#x, want 0x02 (ACL refusal)", rep)
	}
}

func TestPTProxyDeadBridgeReply04(t *testing.T) {
	defer verifyNoLeaks(t)
	endpoint := &fakeEndpoint{fail: true} // scenario 22: dead bridge
	bridges := []Bridge{{Transport: "obfs4", AddrPort: "45.66.35.35:443"}}
	p, _, stop := newPTTestProxy(t, endpoint, bridges)
	defer stop()

	rep, conn, err := ptClientExchange(t, p.Addr(), "cert=x", "45.66.35.35", 443)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer conn.Close()
	if rep != 0x04 {
		t.Fatalf("reply = %#x, want 0x04 (dial failure)", rep)
	}
}

func TestPTProxyHalfClose(t *testing.T) {
	defer verifyNoLeaks(t)
	// an echo server that half-closes after replying
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Write([]byte("bye"))
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()

	factory := &fakeFactory{name: "obfs4", endpoint: &fakeEndpoint{}}
	registry := &PTRegistry{factories: map[string]TransportFactory{}}
	registry.Register(factory)
	dial := func(ctx context.Context, class ConnClass, host string, port uint16) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}
	bridges := []Bridge{{Transport: "obfs4", AddrPort: "45.66.35.35:443"}}
	p, err := NewPTProxy(registry, func() []Bridge { return bridges }, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	rep, conn, err := ptClientExchange(t, p.Addr(), "cert=x", "45.66.35.35", 443)
	if err != nil || rep != 0x00 {
		t.Fatalf("exchange rep=%#x err=%v", rep, err)
	}
	defer conn.Close()
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "bye" {
		t.Fatalf("payload = %q", buf)
	}
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("post-half-close read = %v, want EOF propagated", err)
	}
}

func TestPTProxyTransportResolutionByTarget(t *testing.T) {
	defer verifyNoLeaks(t)
	// two transports, two bridges: the CONNECT target picks the factory.
	wtEndpoint := &fakeEndpoint{}
	obEndpoint := &fakeEndpoint{}
	registry := &PTRegistry{factories: map[string]TransportFactory{}}
	wtFactory := &fakeFactory{name: "webtunnel", endpoint: wtEndpoint}
	obFactory := &fakeFactory{name: "obfs4", endpoint: obEndpoint}
	registry.Register(wtFactory)
	registry.Register(obFactory)

	echo := startDirectEcho(t)
	defer echo.Close()
	dial := func(ctx context.Context, class ConnClass, host string, port uint16) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echo.Addr().String())
	}
	bridges := []Bridge{
		{Transport: "webtunnel", AddrPort: "2001:db8::1:443"},
		{Transport: "obfs4", AddrPort: "45.66.35.35:443"},
	}
	p, err := NewPTProxy(registry, func() []Bridge { return bridges }, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	rep, conn, err := ptClientExchange(t, p.Addr(), "url=https://x/", "2001:db8::1", 443)
	if err != nil || rep != 0x00 {
		t.Fatalf("webtunnel target: rep=%#x err=%v", rep, err)
	}
	_ = conn.Close()
	if wtFactory.lastArgs == nil {
		t.Fatal("webtunnel factory must receive the args")
	}
	if wtFactory.lastArgs["url"] != "https://x/" {
		t.Fatalf("webtunnel args = %v", wtFactory.lastArgs)
	}

	rep, conn, err = ptClientExchange(t, p.Addr(), "cert=y", "45.66.35.35", 443)
	if err != nil || rep != 0x00 {
		t.Fatalf("obfs4 target: rep=%#x err=%v", rep, err)
	}
	_ = conn.Close()
	if obFactory.lastArgs == nil || obFactory.lastArgs["cert"] != "y" {
		t.Fatalf("obfs4 args = %v", obFactory.lastArgs)
	}
}

// --- snowflake adapter: hooks + bounded client cache ---
