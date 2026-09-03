// Registry tests (review P2): the trees see registered kinds in priority
// order, proton is the LOWEST priority entry, replacement is by kind, and
// the proton Runtime satisfies the reserve.Carrier shape.
package reserve

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

type fakeCarrier struct {
	kind Kind
}

func (f *fakeCarrier) Kind() Kind { return f.kind }
func (f *fakeCarrier) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (f *fakeCarrier) SupportsUDP() bool { return false }
func (f *fakeCarrier) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return nil, net.ErrClosed
}

func TestListSortsByPriorityProtonLast(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	for _, k := range []Kind{KindProton, KindH3, KindWarp, KindOpera, KindFxvpn, KindMasque} {
		Register(&fakeCarrier{kind: k})
	}
	got := List()
	if len(got) != 6 {
		t.Fatalf("List() = %d entries, want 6", len(got))
	}
	if got[0].Kind != KindWarp {
		t.Fatalf("head = %s, want warp (highest priority)", got[0].Kind)
	}
	if got[len(got)-1].Kind != KindProton {
		t.Fatalf("tail = %s, want proton (lowest priority, design §7)", got[len(got)-1].Kind)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Priority < got[i].Priority {
			t.Fatalf("priority order violated at %d: %d < %d", i, got[i-1].Priority, got[i].Priority)
		}
	}
}

func TestRegisterReplacesByKind(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register(&fakeCarrier{kind: KindProton})
	Register(&fakeCarrier{kind: KindProton})
	if got := len(List()); got != 1 {
		t.Fatalf("duplicate registration produced %d entries, want 1", got)
	}
}

func TestLookupAndUnregister(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	if _, ok := Lookup(KindProton); ok {
		t.Fatal("unregistered kind must not resolve")
	}
	Register(&fakeCarrier{kind: KindProton})
	e, ok := Lookup(KindProton)
	if !ok || e.Priority != PriorityProton {
		t.Fatalf("Lookup = %+v ok=%v, want priority %d", e, ok, PriorityProton)
	}
	Unregister(KindProton)
	if _, ok := Lookup(KindProton); ok {
		t.Fatal("kind still resolvable after Unregister")
	}
}

func TestRegisterNilIsNoop(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	Register(nil)
	if got := len(List()); got != 0 {
		t.Fatalf("nil registration produced %d entries", got)
	}
}
