package transportwarp

import (
	"context"
	"fmt"
	"testing"
)

// TestM06ClassifyCanceledIsSessionAborted covers M-06(a): a parent-context
// cancel mid-dial must classify as session-aborted, never as
// udp-egress-blocked (which is a ladder switch-class and would poison the
// anti-oscillation gate on a plain stop/rebalance).
func TestM06ClassifyCanceledIsSessionAborted(t *testing.T) {
	td := []struct {
		name string
		err  error
		want string
	}{
		{"bare-canceled", context.Canceled, FailureSessionAborted},
		{"wrapped-canceled", fmt.Errorf("dial: %w", context.Canceled), FailureSessionAborted},
		// Regression: real path/connection failures stay in their own class.
		{"handshake-timeout", fmt.Errorf("handshake timeout"), FailureUDPEgressBlocked},
	}
	for _, tc := range td {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyH3HandshakeError(tc.err); got != tc.want {
				t.Fatalf("classifyH3HandshakeError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestM06ObserveValidationIgnoresCanceled covers M-06(b): validation aborted
// by shutdown must produce ZERO switch events and leave H3 unblocked (no
// blockH3 / fallback counting) — otherwise a plain stop looks like a real
// "handshake-ok-but-silent" verdict.
func TestM06ObserveValidationIgnoresCanceled(t *testing.T) {
	d, _ := newTestLadder(t, nil)

	events := d.ObserveValidation(TransportH3, context.Canceled)
	if len(events) != 0 {
		t.Fatalf("ObserveValidation(Canceled) = %d events, want 0", len(events))
	}
	m := d.Metrics()
	if m.Switches != 0 {
		t.Fatalf("switches = %d, want 0", m.Switches)
	}
	if m.FallbackToH2 != 0 {
		t.Fatalf("fallbacks = %d, want 0", m.FallbackToH2)
	}
	if m.H3Blocked {
		t.Fatal("H3 must remain unblocked after a canceled validation")
	}

	// Control: a real validation failure still degrades as before.
	events = d.ObserveValidation(TransportH3, ErrValidationTimeout)
	if len(events) != 1 || events[0].Name != EvTransportSwitched {
		t.Fatalf("control events = %+v, want one switch", events)
	}
	m = d.Metrics()
	if m.Switches != 1 || !m.H3Blocked {
		t.Fatalf("control must switch+block: metrics=%+v", m)
	}
}
