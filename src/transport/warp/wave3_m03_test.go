package transportwarp

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestM03ALPNMismatchH2Negotiation covers M-03: when the pinned edge negotiates
// an ALPN other than h2 (or empty), DialSession must report FailureH2Negotiation,
// not the default FailureTCPConnect that ErrMalformedCapsule produced before.
func TestM03ALPNMismatchH2Negotiation(t *testing.T) {
	key := newTestKey(t)
	ab := newFakeServerALPN(t, key, []string{"http/1.1"})
	defer ab.close()

	cfg := cfgForServerAddr(t, ab.addr().String(), &key.PublicKey)
	cfg.HandshakeBudget = 5 * time.Second

	_, res, err := DialSession(context.Background(), cfg)
	if err == nil {
		t.Fatal("M-03: expected an ALPN-mismatch error, dial succeeded")
	}
	if res.FailureClass != FailureH2Negotiation {
		t.Fatalf("M-03: class=%q want %q (err=%v)", res.FailureClass, FailureH2Negotiation, err)
	}
}

// TestM03ClassifierH2ALPN drives the structural classifier directly: an
// ErrH2ALPN-wrapped error maps to FailureH2Negotiation.
func TestM03ClassifierH2ALPN(t *testing.T) {
	if got, want := classifyDialError(fmt.Errorf("%w: negotiated %q", ErrH2ALPN, "http/1.1")), FailureH2Negotiation; got != want {
		t.Fatalf("classifyDialError(ErrH2ALPN) = %q want %q", got, want)
	}
}
