package tor

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// TT3 DoD: egress-bridge RFC 1929 cases (mandatory auth, wrong creds
// refused), correct creds connect through the dialer, class attribution
// (vanilla bridge vs relay-dir), half-close propagation, bounded conns.

// socksGreetUserPass performs the raw SOCKS5 exchange with explicit creds.
func socksConnectBridge(t *testing.T, conn net.Conn, user, pass, host string, port uint16) error {
	t.Helper()
	// method negotiation: offer none + user/pass
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return io.ErrUnexpectedEOF
	}
	if resp[1] == 0xFF {
		return errNoAcceptableAuth
	}
	if resp[1] != 0x02 {
		return errWrongMethod
	}
	// RFC 1929 subnegotiation
	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := conn.Write(auth); err != nil {
		return err
	}
	aresp := make([]byte, 2)
	if _, err := io.ReadFull(conn, aresp); err != nil {
		return err
	}
	if aresp[1] != 0x00 {
		return errAuthFailed
	}
	// CONNECT
	req := []byte{0x05, 0x01, 0x00, 0x01}
	ip := net.ParseIP(host)
	if ip == nil {
		req[3] = 0x03
		req = append(req, byte(len(host)))
		req = append(req, host...)
	} else if v4 := ip.To4(); v4 != nil {
		req = append(req, v4...)
	} else {
		req[3] = 0x04
		req = append(req, ip.To16()...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	req = append(req, pb[:]...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return errConnectRefused
	}
	// skip bound addr
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		skip = int(l[0])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return err
	}
	return nil
}

type testErr string

func (e testErr) Error() string { return string(e) }

const (
	errNoAcceptableAuth = testErr("no acceptable auth")
	errWrongMethod      = testErr("wrong method selected")
	errAuthFailed       = testErr("auth failed")
	errConnectRefused   = testErr("connect refused")
)

func newTestBridgeDialer(t *testing.T) *Dialer {
	t.Helper()
	d := NewDialer(EgressPolicy{Through: "none", Now: time.Now}, nil, nil, nil)
	d.markCtl = nil // sandbox: no CAP_NET_ADMIN
	return d
}

func TestEgressBridgeWrongCredsRefused(t *testing.T) {
	defer verifyNoLeaks(t)
	d := newTestBridgeDialer(t)
	b, err := NewEgressBridge(d, nil)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	defer b.Stop()

	conn, err := net.Dial("tcp", b.Addr())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	err = socksConnectBridge(t, conn, "intruder", "guess", "127.0.0.1", 1)
	if err != errAuthFailed {
		t.Fatalf("wrong creds err = %v, want auth failure", err)
	}
}

func TestEgressBridgeNoAuthRefused(t *testing.T) {
	defer verifyNoLeaks(t)
	d := newTestBridgeDialer(t)
	b, err := NewEgressBridge(d, nil)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	defer b.Stop()

	conn, err := net.Dial("tcp", b.Addr())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	// offer only auth-none
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read method select: %v", err)
	}
	if resp[1] != 0xFF {
		t.Fatalf("method = %#x, want 0xFF (RFC 1929 mandatory)", resp[1])
	}
}

func TestEgressBridgeConnectRelay(t *testing.T) {
	defer verifyNoLeaks(t)
	echo := startDirectEcho(t)
	defer echo.Close()
	port := uint16(srvPort(t, echo))

	d := newTestBridgeDialer(t)
	b, err := NewEgressBridge(d, nil)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	defer b.Stop()

	conn, err := net.Dial("tcp", b.Addr())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := socksConnectBridge(t, conn, b.Username(), b.Password(), "127.0.0.1", port); err != nil {
		t.Fatalf("connect through bridge: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "echo" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestEgressBridgeClassAttribution(t *testing.T) {
	defer verifyNoLeaks(t)
	echo := startDirectEcho(t)
	defer echo.Close()
	port := uint16(srvPort(t, echo))

	d := newTestBridgeDialer(t)
	targets := func() []string {
		return []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))}
	}
	b, err := NewEgressBridge(d, targets)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	defer b.Stop()

	// the echo server endpoint is listed as a vanilla bridge target
	got := b.classFor("127.0.0.1", port)
	if got != ClassBridgeVanilla {
		t.Fatalf("class = %s, want bridge-vanilla (target in active set)", got)
	}
	got = b.classFor("127.0.0.1", port+1)
	if got != ClassRelayDir {
		t.Fatalf("class = %s, want relay-dir (target not in set)", got)
	}
}

func TestEgressBridgeCredsRandomPerStart(t *testing.T) {
	defer verifyNoLeaks(t)
	d := newTestBridgeDialer(t)
	b1, err := NewEgressBridge(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b1.Stop()
	b2, err := NewEgressBridge(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Stop()
	if b1.Username() == b2.Username() || b1.Password() == b2.Password() {
		t.Fatal("credentials must be random per start (proxybridge canon)")
	}
	if len(b1.Username()) != 32 || len(b1.Password()) != 32 {
		t.Fatalf("creds length = %d/%d, want 32 hex chars", len(b1.Username()), len(b1.Password()))
	}
	if b1.Creds() != b1.Username()+":"+b1.Password() {
		t.Fatal("Creds renders user:pass")
	}
}

func TestEgressBridgeHalfClose(t *testing.T) {
	defer verifyNoLeaks(t)
	// a server that echoes then half-closes its write side
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
	port := uint16(srvPort(t, ln))

	d := newTestBridgeDialer(t)
	b, err := NewEgressBridge(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()

	conn, err := net.Dial("tcp", b.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := socksConnectBridge(t, conn, b.Username(), b.Password(), "127.0.0.1", port); err != nil {
		t.Fatalf("connect: %v", err)
	}
	// server wrote "bye" then half-closed: the EOF must propagate through
	// the bridge pipe while OUR write side stays open (half-close canon).
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "bye" {
		t.Fatalf("payload = %q", buf)
	}
	rest := make([]byte, 1)
	if _, err := conn.Read(rest); err != io.EOF {
		t.Fatalf("read after server half-close = %v/%q, want EOF", err, rest)
	}
}

func TestEgressBridgeDialFailure(t *testing.T) {
	defer verifyNoLeaks(t)
	d := newTestBridgeDialer(t)
	b, err := NewEgressBridge(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	conn, err := net.Dial("tcp", b.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	err = socksConnectBridge(t, conn, b.Username(), b.Password(), "127.0.0.1", 1) // nothing listens
	if err != errConnectRefused {
		t.Fatalf("dead target err = %v, want connect refused", err)
	}
}

func TestEgressBridgeLoopGuardIntegration(t *testing.T) {
	defer verifyNoLeaks(t)
	d := newTestBridgeDialer(t)
	loops := func() []string { return nil }
	d.loops = loops
	b, err := NewEgressBridge(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	// wire the bridge's own listener into the dialer's loop guard, then
	// try to CONNECT to it through the bridge: refused as self-loop.
	d.loops = func() []string { return []string{b.Addr()} }
	conn, err := net.Dial("tcp", b.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	err = socksConnectBridge(t, conn, b.Username(), b.Password(), "127.0.0.1", uint16(srvPort(t, b.listener)))
	if err != errConnectRefused {
		t.Fatalf("self-loop dial err = %v, want refused", err)
	}
}
