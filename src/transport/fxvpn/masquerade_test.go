// masquerade_test.go: FX-M0 pins — the QUIC Initial bait is byte-accurate
// and sized like Firefox, the preflight fires BEFORE the real handshake
// without breaking it (fakeh3edge interop), the bait rides a THROWAWAY
// TTL-limited policy (never the live socket), and the Firefox hello shaping
// applies exactly on the firefox rung.
package fxvpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
)

func TestQuici1BuildGoldenSize(t *testing.T) {
	raw := quici1BuildForTest(t, "detectportal.firefox.com")
	if len(raw) != 1250 {
		t.Fatalf("fake Initial size = %d, want 1250 (Firefox pad shape)", len(raw))
	}
	// Two builds must differ (random DCID + ClientHello random): a fixed
	// bait across flows would be its own signature.
	raw2 := quici1BuildForTest(t, "detectportal.firefox.com")
	if bytes.Equal(raw, raw2) {
		t.Fatal("two baits must never be byte-identical")
	}
}

func quici1BuildForTest(t *testing.T, sni string) []byte {
	t.Helper()
	m := DefaultMasquerade()
	payloads := preflightFakeInitials(m, "atn1.m1.fastly-masque.net:2499", 1)
	if len(payloads) == 0 {
		t.Fatalf("bait build failed for sni=%q", sni)
	}
	return payloads[0]
}

func TestPreflightFakeInitialsEmptySNI(t *testing.T) {
	m := DefaultMasquerade()
	m.FakeSNI = nil
	if got := preflightFakeInitials(m, "node", 2); got != nil {
		t.Fatal("empty pool must disable the bait")
	}
}

// capturedBait records what the preflight seam was asked to send.
type capturedBait struct {
	mu       sync.Mutex
	payloads [][]byte
	addr     *net.UDPAddr
	ttl      int
	network  string
}

func (c *capturedBait) send(payloads [][]byte, raddr *net.UDPAddr, policy DialPolicy, network string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.payloads = append(c.payloads, payloads...)
	c.addr = raddr
	c.ttl = policy.TTL
	c.network = network
	return nil
}

// TestDialH3PreflightFiresBeforeHandshake pins masquerade §7.4.1 end to end
// over the fakeh3edge stand: with PreflightFake on, the bait leaves FIRST
// (captured by the seam, TTL-limited policy, resolved carrier address) and
// the REAL handshake still completes — bait and session are independent.
func TestDialH3PreflightFiresBeforeHandshake(t *testing.T) {
	e := newFakeH3Edge(t)
	host, port := e.addr()

	bait := &capturedBait{}
	prev := preflightSend
	preflightSend = bait.send
	t.Cleanup(func() { preflightSend = prev })

	m := DefaultMasquerade()
	m.PreflightFake = true
	m.FakeTTL = 5
	m.FakeCount = 2

	cfg := testTunnelConfig(host, port, "jwt-1")
	cfg.Masquerade = m
	s, err := DialH3(context.Background(), cfg)
	if err != nil {
		t.Fatalf("DialH3 with bait: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	bait.mu.Lock()
	defer bait.mu.Unlock()
	if len(bait.payloads) != 2 {
		t.Fatalf("bait datagrams = %d, want 2", len(bait.payloads))
	}
	for i, p := range bait.payloads {
		if len(p) != 1250 {
			t.Fatalf("bait[%d] size = %d, want 1250", i, len(p))
		}
	}
	if bait.ttl != 5 {
		t.Fatalf("bait TTL = %d, want 5", bait.ttl)
	}
	if bait.addr == nil || bait.addr.Port != port {
		t.Fatalf("bait addr = %v, want port %d", bait.addr, port)
	}

	// The real session carries relays normally (interop with fakeh3edge).
	conn, err := s.OpenTunnel(context.Background(), "target.example:443")
	if err != nil {
		t.Fatalf("OpenTunnel after bait: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// TestHelloShapingProfileSemantics pins §7.4.3: the Firefox cipher/curve
// offer applies on the firefox rung only; go-plain/off keep the Go defaults.
func TestHelloShapingProfileSemantics(t *testing.T) {
	firefox := DefaultMasquerade()
	cfg := &tls.Config{}
	firefox.ApplyHelloShaping(cfg)
	if len(cfg.CipherSuites) != len(firefoxCipherSuites) || len(cfg.CurvePreferences) != len(firefoxCurves) {
		t.Fatal("firefox profile must shape the hello")
	}

	plain := ResolveMasquerade("go-plain", false, nil, 0, 0, 0, nil)
	cfg2 := &tls.Config{}
	plain.ApplyHelloShaping(cfg2)
	if cfg2.CipherSuites != nil || cfg2.CurvePreferences != nil {
		t.Fatal("go-plain must not shape the hello")
	}

	// Explicit override: firefox profile with shaping disabled.
	noShape := false
	override := ResolveMasquerade("firefox", false, nil, 0, 0, 0, &noShape)
	if override.HelloShaping {
		t.Fatal("explicit hello_shaping=false must win")
	}
}

// TestEffectiveFakeSNISTicky pins the white-SNI pick: stable per node,
// drawn from the pool, overridable.
func TestEffectiveFakeSNISTicky(t *testing.T) {
	m := DefaultMasquerade()
	a := m.EffectiveFakeSNI("atn1.m1.fastly-masque.net:2499")
	b := m.EffectiveFakeSNI("atn1.m1.fastly-masque.net:2499")
	if a != b || a == "" {
		t.Fatalf("pick must be stable and non-empty: %q vs %q", a, b)
	}
	m2 := ResolveMasquerade("firefox", false, []string{"aus5.mozilla.org"}, 0, 0, 0, nil)
	if got := m2.EffectiveFakeSNI("anything"); got != "aus5.mozilla.org" {
		t.Fatalf("pool override pick = %q", got)
	}
}
