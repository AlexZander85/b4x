// Carrier-guard tests (review P2, PT6b): the proton Runtime satisfies the
// reserve.Carrier contract; dials refuse honestly when no established
// session serves, the self-loop guard refuses the active node's entry IP,
// and the dial counters tick.
package protonservice

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/reserve"
	"github.com/daniellavrushin/b4/transport/proton"
)

func newCarrierTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.System.Proton = config.ProtonConfig{
		Enabled:      true,
		IdentityPath: filepath.Join(dir, "identity.json"),
		Location:     config.ProtonLocation{Mode: "country", Country: "NL"},
	}
	rt, err := Build(cfg, Options{Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	rt.client.Pins = mustPinsMemory(t)
	return rt
}

// TestRuntimeImplementsReserveCarrier pins the interface contract at
// compile time (review P2: the carrier seam must be exposed).
func TestRuntimeImplementsReserveCarrier(t *testing.T) {
	rt := newCarrierTestRuntime(t)
	var c reserve.Carrier = rt
	if c.Kind() != reserve.KindProton {
		t.Fatalf("Kind = %q, want proton", c.Kind())
	}
	if !c.SupportsUDP() {
		t.Fatal("proton is the UDP full-scope reserve — SupportsUDP must be true")
	}
}

// TestDialRefusesWithoutEstablishedSession: the honest refusal (no silent
// substitute), counters tick on the fail side.
func TestDialRefusesWithoutEstablishedSession(t *testing.T) {
	rt := newCarrierTestRuntime(t)
	addr := netip.MustParseAddrPort("203.0.113.1:443")

	if _, err := rt.DialStream(context.Background(), addr); !errors.Is(err, ErrNotListening) {
		t.Fatalf("DialStream without session: %v, want ErrNotListening", err)
	}
	if _, err := rt.DialUDP(context.Background(), addr); !errors.Is(err, ErrNotListening) {
		t.Fatalf("DialUDP without session: %v, want ErrNotListening", err)
	}
	rt.mu.Lock()
	ok, fail := rt.dialOK, rt.dialFail
	rt.mu.Unlock()
	if ok != 0 || fail != 2 {
		t.Fatalf("dial counters ok=%d fail=%d, want 0/2", ok, fail)
	}
}

// TestSelfLoopGuardRefusesActiveNode: the active node's entry IP is a
// refused dial target (last-resort anti-loop net).
func TestSelfLoopGuardRefusesActiveNode(t *testing.T) {
	rt := newCarrierTestRuntime(t)
	rt.mu.Lock()
	rt.profiles = []proton.ProtonProfile{{
		Node: proton.Node{
			Name: "NL-FREE#1", Country: "NL", EntryIP: "203.0.113.10",
		},
		Port: 443,
	}}
	rt.profIdx = 0
	rt.mu.Unlock()

	loop := netip.MustParseAddrPort("203.0.113.10:443")
	other := netip.MustParseAddrPort("203.0.113.11:443")

	if _, err := rt.DialStream(context.Background(), loop); !errors.Is(err, ErrProtonSelfLoop) {
		t.Fatalf("DialStream to the active node: %v, want ErrProtonSelfLoop", err)
	}
	// A different target fails on the (absent) session, NOT the loop guard.
	if _, err := rt.DialStream(context.Background(), other); !errors.Is(err, ErrNotListening) {
		t.Fatalf("DialStream to a third host: %v, want ErrNotListening", err)
	}

	rt.mu.Lock()
	loopAddr := rt.selfLoopAddrLocked()
	rt.mu.Unlock()
	if loopAddr != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("selfLoopAddrLocked = %v", loopAddr)
	}
}

// TestCarrierRegistrationCycle: Register replaces and Unregister removes —
// the exact wiring main.go performs on start/stop.
func TestCarrierRegistrationCycle(t *testing.T) {
	reserve.Reset()
	t.Cleanup(reserve.Reset)

	rt := newCarrierTestRuntime(t)
	reserve.Register(rt)
	e, ok := reserve.Lookup(reserve.KindProton)
	if !ok || e.Priority != reserve.PriorityProton {
		t.Fatalf("registered entry %+v ok=%v", e, ok)
	}
	if e.Carrier != reserve.Carrier(rt) {
		t.Fatal("registry carries a different carrier than the runtime")
	}
	reserve.Unregister(reserve.KindProton)
	if _, ok := reserve.Lookup(reserve.KindProton); ok {
		t.Fatal("kind still registered after stop")
	}
}
