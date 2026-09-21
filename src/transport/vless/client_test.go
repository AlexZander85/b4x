package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

// startRawVLESS runs a fake VLESS server: it parses the version-0 request
// header, answers with an empty response header, then echoes every byte.
func startRawVLESS(t *testing.T, tlsCfg *tls.Config) (addr string, targets chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	targets = make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn := net.Conn(c)
				if tlsCfg != nil {
					tc := tls.Server(conn, tlsCfg)
					if err := tc.Handshake(); err != nil {
						_ = conn.Close()
						return
					}
					conn = tc
				}
				serveFakeVLESS(conn, targets)
			}()
		}
	}()
	return ln.Addr().String(), targets
}

func serveFakeVLESS(conn net.Conn, targets chan string) {
	defer conn.Close()
	target, err := readFakeRequest(conn)
	if err != nil {
		return
	}
	if targets != nil {
		targets <- target
	}
	_, _ = conn.Write([]byte{vlessVersion, 0x00}) // response header
	_, _ = io.Copy(conn, conn)
}

// readFakeRequest parses the VLESS request header and returns host:port.
func readFakeRequest(r io.Reader) (string, error) {
	head := make([]byte, 1+16+1)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", err
	}
	if head[0] != vlessVersion {
		return "", io.ErrUnexpectedEOF
	}
	addonLen := int(head[17])
	if addonLen > 0 {
		if _, err := io.ReadFull(r, make([]byte, addonLen)); err != nil {
			return "", err
		}
	}
	cmdPort := make([]byte, 1+2)
	if _, err := io.ReadFull(r, cmdPort); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(cmdPort[1:])
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case atypIPv4:
		b := make([]byte, 4)
		_, _ = io.ReadFull(r, b)
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		_, _ = io.ReadFull(r, b)
		host = net.IP(b).String()
	case atypDomain:
		l := make([]byte, 1)
		_, _ = io.ReadFull(r, l)
		b := make([]byte, int(l[0]))
		_, _ = io.ReadFull(r, b)
		host = string(b)
	}
	return net.JoinHostPort(host, itoa(int(port))), nil
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

// startWSVLESS runs a fake VLESS-over-websocket server.
func startWSVLESS(t *testing.T) (addr string, targets chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	targets = make(chan string, 8)
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_, first, err := ws.ReadMessage()
		if err != nil {
			return
		}
		target, err := readFakeRequest(bytesReader(first))
		if err == nil {
			targets <- target
		}
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte{vlessVersion, 0x00})
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if err := ws.WriteMessage(mt, data); err != nil {
				return
			}
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), targets
}

// ws messages carry the request in ONE write, but the header and the first
// payload may arrive as separate messages if written separately; readFakeRequest
// only needs the header, so buffer across messages if needed.
type multiReader struct {
	chunks [][]byte
	cur    []byte
}

func bytesReader(b []byte) *multiReader { return &multiReader{chunks: [][]byte{b}} }

func (m *multiReader) Read(p []byte) (int, error) {
	for len(m.cur) == 0 {
		if len(m.chunks) == 0 {
			return 0, io.EOF
		}
		m.cur = m.chunks[0]
		m.chunks = m.chunks[1:]
	}
	n := copy(p, m.cur)
	m.cur = m.cur[n:]
	return n, nil
}

func selfSignedCert(t *testing.T, name string) (*tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, pool
}

func echoRoundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	want := []byte("hello-in-process-vless")
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

func TestDialInProcessTCP(t *testing.T) {
	addr, targets := startRawVLESS(t, nil)
	_host, portStr, _ := net.SplitHostPort(addr)
	port := mustAtoi(t, portStr)
	node := Node{UUID: "11111111-1111-1111-1111-111111111111", Host: _host, Port: uint16(port), Security: SecurityNone, Transport: TransportTCP}
	d := &Dialer{Node: node}
	conn, err := d.Dial(context.Background(), netip.MustParseAddrPort("1.2.3.4:443"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	select {
	case got := <-targets:
		if got != "1.2.3.4:443" {
			t.Fatalf("server target = %q want 1.2.3.4:443", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive the request header")
	}
	echoRoundTrip(t, conn)
}

func TestDialInProcessTLS(t *testing.T) {
	cert, pool := selfSignedCert(t, "test.local")
	addr, _ := startRawVLESS(t, &tls.Config{Certificates: []tls.Certificate{*cert}})
	host, portStr, _ := net.SplitHostPort(addr)
	node := Node{
		UUID: "11111111-1111-1111-1111-111111111111", Host: host, Port: uint16(mustAtoi(t, portStr)),
		Security: SecurityTLS, SNI: "test.local", Transport: TransportTCP,
	}
	d := &Dialer{Node: node, RootCAs: pool}
	conn, err := d.Dial(context.Background(), netip.MustParseAddrPort("1.2.3.4:443"))
	if err != nil {
		t.Fatalf("dial tls: %v", err)
	}
	defer conn.Close()
	echoRoundTrip(t, conn)
}

func TestDialInProcessWebsocket(t *testing.T) {
	addr, targets := startWSVLESS(t)
	host, portStr, _ := net.SplitHostPort(addr)
	node := Node{
		UUID: "11111111-1111-1111-1111-111111111111", Host: host, Port: uint16(mustAtoi(t, portStr)),
		Security: SecurityNone, Transport: TransportWS, Path: "/ws",
	}
	d := &Dialer{Node: node}
	conn, err := d.Dial(context.Background(), netip.MustParseAddrPort("9.9.9.9:80"))
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer conn.Close()
	select {
	case got := <-targets:
		if got != "9.9.9.9:80" {
			t.Fatalf("server target = %q want 9.9.9.9:80", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ws server did not receive the request header")
	}
	echoRoundTrip(t, conn)
}

func TestRealityHelpers(t *testing.T) {
	if _, err := decodeShortID("0123abcd"); err != nil {
		t.Fatalf("valid shortId rejected: %v", err)
	}
	if _, err := decodeShortID("xyz"); err == nil {
		t.Fatal("odd/invalid shortId must error")
	}
	if _, err := parseRealityPublicKey("not-hex"); err == nil {
		t.Fatal("bad public key must error")
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if _, err := parseRealityPublicKey(hexEncode(key)); err != nil {
		t.Fatalf("valid x25519 key rejected: %v", err)
	}
}

func TestApplyRealityBuildsAuthBlock(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node := Node{
		UUID: "11111111-1111-1111-1111-111111111111", Host: "h.example.org", Port: 443,
		Security: SecurityReality, SNI: "www.microsoft.com", Fingerprint: "chrome",
		PublicKey: hexEncode(key.PublicKey().Bytes()), ShortID: "0123abcd", Transport: TransportTCP,
	}
	if err := node.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	uconn := utls.UClient(c1, &utls.Config{ServerName: node.SNI, InsecureSkipVerify: true}, clientHelloID(node.Fingerprint))
	authKey, err := applyReality(uconn, node)
	if err != nil {
		t.Fatalf("applyReality: %v", err)
	}
	if len(authKey) != 32 {
		t.Fatalf("authKey len=%d want 32", len(authKey))
	}
	hello := uconn.HandshakeState.Hello
	if len(hello.SessionId) != 32 {
		t.Fatalf("sessionId len=%d want 32", len(hello.SessionId))
	}
	if len(hello.Raw) < 39+32 {
		t.Fatalf("hello raw too short: %d", len(hello.Raw))
	}
	// The sealed block republished into Raw is the same 32 bytes as SessionId.
	if string(hello.Raw[39:71]) != string(hello.SessionId[:32]) {
		t.Fatal("session id was not republished into the client hello")
	}
}

func TestEncodeFlowAddon(t *testing.T) {
	if got := encodeFlowAddon(""); got != nil {
		t.Fatalf("empty flow addon = %v want nil", got)
	}
	got := encodeFlowAddon(FlowVision)
	want := append([]byte{0x0A, byte(len(FlowVision))}, []byte(FlowVision)...)
	if string(got) != string(want) {
		t.Fatalf("flow addon = %x want %x", got, want)
	}
	if got[0] != 0x0A {
		t.Fatalf("protobuf field tag = %x want 0x0a (field 1, wire type 2)", got[0])
	}
}

func TestSupportsInProcess(t *testing.T) {
	const tu = "11111111-1111-1111-1111-111111111111"
	cases := []struct {
		node Node
		want bool
	}{
		{Node{UUID: tu, Transport: TransportTCP, Security: SecurityNone}, true},
		{Node{UUID: tu, Transport: TransportTCP, Security: SecurityTLS}, true},
		{Node{UUID: tu, Transport: TransportTCP, Security: SecurityReality}, true},
		{Node{UUID: tu, Transport: TransportWS, Security: SecurityTLS}, true},
		{Node{UUID: tu, Transport: TransportHTTPUpgrade, Security: SecurityReality}, true},
		{Node{UUID: tu, Transport: TransportTCP, Security: SecurityReality, Flow: FlowVision}, true}, // vision framing implemented
		{Node{UUID: tu, Transport: TransportTCP, Security: SecurityReality, Flow: "xtls-rprx-other"}, false},
		{Node{UUID: tu, Transport: TransportGRPC, Security: SecurityTLS}, false},
		{Node{UUID: tu, Transport: TransportXHTTP, Security: SecurityTLS}, false},
		{Node{UUID: tu, Transport: TransportKCP, Security: SecurityTLS}, false},
		{Node{UUID: tu, Transport: TransportQUIC, Security: SecurityTLS}, false},
		// A non-UUID id (the corpus has 30-char logins) must stay on the helper.
		{Node{UUID: "some-30-char-login-id", Transport: TransportTCP, Security: SecurityTLS}, false},
	}
	for _, c := range cases {
		if got := SupportsInProcess(c.node); got != c.want {
			t.Fatalf("SupportsInProcess(%s/%s) = %v want %v", c.node.Transport, c.node.Security, got, c.want)
		}
	}
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexdigits[x>>4], hexdigits[x&0xf])
	}
	return string(out)
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			t.Fatalf("bad int %q", s)
		}
		n = n*10 + int(r-'0')
	}
	return n
}
