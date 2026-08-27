package transportwarp

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// tlsAbsorber is a raw TCP endpoint that accepts and then silently holds the
// connection open WITHOUT completing a TLS handshake. DialSession's handshake
// phase therefore times out, producing the cross-layer TLS-handshake timeout
// (M-02) rather than a connect-ip-timeout verdict.
type tlsAbsorber struct {
	ln net.Listener
}

func newTLSAbsorber(t *testing.T) *tlsAbsorber {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := &tlsAbsorber{ln: ln}
	go a.accept(t)
	return a
}

func (a *tlsAbsorber) addr() string { return a.ln.Addr().String() }

func (a *tlsAbsorber) accept(t *testing.T) {
	for {
		conn, err := a.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			// Hold the socket open; never answer the ClientHello.
			time.Sleep(5 * time.Second)
		}(conn)
	}
}

func (a *tlsAbsorber) close() { _ = a.ln.Close() }

// TestM02TLSTimeoutClassified confirms a handshake deadline maps to the
// TLS-layer timeout class (FailureTLSTimeout), NOT the generic connect-ip
// timeout. A TCP connect against the absorber succeeds instantly; only the
// pinned handshake phase stalls, so the verdict must name TLS.
func TestM02TLSTimeoutClassified(t *testing.T) {
	original := tlsHandshakeTimeout
	tlsHandshakeTimeout = 300 * time.Millisecond
	defer func() { tlsHandshakeTimeout = original }()

	ab := newTLSAbsorber(t)
	defer ab.close()

	// The absorber never handshakes, so pin verification never runs; any key
	// suffices to pass PrepareTLSConfig.
	key := newTestKey(t)
	cfg := cfgForServerAddr(t, ab.addr(), &key.PublicKey)
	cfg.HandshakeBudget = 5 * time.Second // keep the overall budget > handshake

	_, res, err := DialSession(context.Background(), cfg)
	if err == nil {
		t.Fatal("M-02: expected an error, dial succeeded against a no-TLS endpoint")
	}
	if res.FailureClass != FailureTLSTimeout {
		t.Fatalf("M-02: class=%q want %q (err=%v)", res.FailureClass, FailureTLSTimeout, err)
	}
}

// TestM02ClassifierSentinel drives the structural (non-string) classifier
// directly: an ErrTLSHandshakeTimeout-wrapped error must be read by
// classifyDialError as the TLS-layer timeout, regardless of outer text.
func TestM02ClassifierSentinel(t *testing.T) {
	inner := context.DeadlineExceeded
	wrapped := fmt.Errorf("%w: %v", ErrTLSHandshakeTimeout, inner)
	if got, want := classifyDialError(wrapped), FailureTLSTimeout; got != want {
		t.Fatalf("classifyDialError = %q want %q", got, want)
	}
	// A plain deadline (TCP connect phase) must still be the connect-ip class.
	if got, want := classifyDialError(inner), FailureTCPConnect; got != want {
		t.Fatalf("classifyDialError(plain ctx deadline) = %q want %q", got, want)
	}
}
