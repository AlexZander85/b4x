package fxvpservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// toErr is a minimal net.Error timeout.
type toErr struct{}

func (toErr) Error() string   { return "dial tcp: i/o timeout" }
func (toErr) Timeout() bool   { return true }
func (toErr) Temporary() bool { return false }

var _ net.Error = toErr{}

// TestPortBlockSuspicion pins the b4x-3pmi fix: the direct :2499 edge block
// surfaces as an ICMP unreachable (no route to host) in the field, which the
// old timeout/reset-only check ignored, so nesting never armed.
func TestPortBlockSuspicion(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"no route to host", errors.New("dial tcp 23.235.42.39:2499: connect: no route to host"), true},
		{"wrapped no route", errors.New("fxvpn: h2 dial node:2499: dial tcp: connect: no route to host"), true},
		{"network unreachable", errors.New("dial tcp: connect: network is unreachable"), true},
		{"host unreachable", errors.New("connect: host unreachable"), true},
		{"connection refused", errors.New("dial tcp: connect: connection refused"), true},
		{"connection reset", errors.New("read: connection reset by peer"), true},
		{"timeout", toErr{}, true},
		{"context deadline", context.DeadlineExceeded, true},
		{"unrelated", errors.New("tls: bad certificate"), false},
	}
	for _, tc := range cases {
		if got := portBlockSuspicion(tc.err); got != tc.want {
			t.Errorf("%s: portBlockSuspicion = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestStrikeDataPlaneRecyclesSession pins the b4x-79sd fix: consecutive
// data-plane failures recycle the serving session instead of leaving a dead
// relay behind a green liveness flag.
func TestStrikeDataPlaneRecyclesSession(t *testing.T) {
	fx := newLiveFixture(t, 15)
	rt := fx.rt

	fs := newFakeSession() // OpenTunnel always errors (dead relay)
	rt.mu.Lock()
	rt.session = fs
	rt.sessionHost = "node.example:2499"
	rt.mu.Unlock()

	addr := netip.MustParseAddrPort("192.0.2.1:443")

	for i := 0; i < dataPlaneStrikeThreshold-1; i++ {
		if _, err := rt.DialStream(context.Background(), addr); err == nil {
			t.Fatalf("probe %d: expected error from dead session", i)
		}
	}
	if rt.session == nil {
		t.Fatal("session recycled before the strike threshold")
	}
	if _, err := rt.DialStream(context.Background(), addr); err == nil {
		t.Fatal("threshold probe: expected error")
	}
	if rt.session != nil {
		t.Fatal("session not recycled after the strike threshold")
	}
	if fs.closed == 0 || fs.IsAlive() {
		t.Fatalf("session not closed (closed=%d alive=%v)", fs.closed, fs.IsAlive())
	}
}
