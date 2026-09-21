package fxvpn

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// timeoutErr is a minimal net.Error with Timeout()==true (the shape a TCP
// dial timeout or a wrapped QUIC handshake timeout presents to the ladder).
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "dial tcp: i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

// TestClassifyDialErrorTimeout pins the b4x-3pmi fix: a dial that timed out
// (any wrapper) is the blackhole class, not "unclassified". Before the fix
// the type-only switch returned "" here, so the ladder never fell back H3->H2
// and the nest detector never armed.
func TestClassifyDialErrorTimeout(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"plain timeout", timeoutErr{}, "udp-egress-blocked"},
		{"wrapped timeout", fmt.Errorf("fxvpn: h2 dial node:2499: %w", timeoutErr{}), "udp-egress-blocked"},
		{"context deadline", context.DeadlineExceeded, "udp-egress-blocked"},
		{"wrapped deadline", fmt.Errorf("fxvpn: h3 dial: %w", context.DeadlineExceeded), "udp-egress-blocked"},
		{"sentinel wins", fmt.Errorf("x: %w", errUDPEgressBlocked), "udp-egress-blocked"},
		{"h2 sentinel", errH2Unavailable, "h2-unavailable"},
		{"no route to host", errors.New("dial tcp 23.235.42.39:2499: connect: no route to host"), "udp-egress-blocked"},
		{"network unreachable", errors.New("dial tcp: connect: network is unreachable"), "udp-egress-blocked"},
		{"connection refused", errors.New("dial tcp: connect: connection refused"), "udp-egress-blocked"},
		{"connection reset", errors.New("read: connection reset by peer"), "udp-egress-blocked"},
		{"opaque error stays unclassified", fmt.Errorf("some other failure"), ""},
	}
	for _, tc := range cases {
		if got := ClassifyDialError(tc.err); got != tc.want {
			t.Errorf("%s: ClassifyDialError = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestLadderSwitchesOnWrappedTimeout pins the ladder half of b4x-3pmi: the
// H3->H2 fallback must fire for a wrapped timeout, not only for the sentinel.
func TestLadderSwitchesOnWrappedTimeout(t *testing.T) {
	l := NewLadder(LadderConfig{PreferH3: true})
	next, switched := l.ObserveDialFailure(CarrierH3, fmt.Errorf("fxvpn: h3 dial edge:2499: %w", timeoutErr{}))
	if !switched || next != CarrierH2 {
		t.Fatalf("ObserveDialFailure(wrapped timeout) = (%q,%v), want (h2,true)", next, switched)
	}
}
