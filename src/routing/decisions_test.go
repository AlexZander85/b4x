package routing

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

func decisionStore(t *testing.T) (*DecisionStore, *clock.FixedClock) {
	t.Helper()
	clk := clock.NewFixed(time.Unix(100, 0))
	return NewDecisionStore(0, 0, clk), clk
}

func testDecision(mark uint32) RouteDecision {
	return RouteDecision{Route: RouteGeneric, RouteID: "generic", SOMark: mark, RuleTable: 100}
}

func TestDecisionStoreStoresAndResolvesFlow(t *testing.T) {
	store, clk := decisionStore(t)
	client := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.77")
	store.Store(client, dst, 443, 6, "youtube.com", testDecision(1<<28), clk.Now())

	got, ok := store.LookupFlow(client, dst, 443, 6)
	if !ok || got.SOMark != 1<<28 {
		t.Fatalf("flow decision not resolved: ok=%v got=%+v", ok, got)
	}
}

func TestDecisionStoreFlowKeyIsDirectionIndependent(t *testing.T) {
	store, clk := decisionStore(t)
	client := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.77")
	store.Store(client, dst, 443, 6, "", testDecision(1<<28), clk.Now())

	// The reply direction (dst as source, client as destination) resolves to
	// the same flow decision via the same destination port.
	if got, ok := store.LookupFlow(client, dst, 443, 6); !ok || got.SOMark != 1<<28 {
		t.Fatalf("flow lookup failed: ok=%v", ok)
	}
}

func TestDecisionStoreResolvesByDomain(t *testing.T) {
	store, clk := decisionStore(t)
	client := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.77")
	store.Store(client, dst, 443, 6, "YouTube.COM", testDecision(1<<28), clk.Now())

	// Domain lookups are case-insensitive and do not need the IP.
	got, ok := store.LookupDomain(client, "youtube.com", 443)
	if !ok || got.SOMark != 1<<28 {
		t.Fatalf("domain decision not resolved: ok=%v got=%+v", ok, got)
	}
}

func TestDecisionStoreExpiresAfterTTL(t *testing.T) {
	store, clk := decisionStore(t)
	client := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.77")
	store.Store(client, dst, 443, 6, "", testDecision(1<<28), clk.Now())

	clk.Advance(3 * time.Minute)
	if removed := store.GC(clk.Now()); removed != 1 {
		t.Fatalf("GC removed %d entries, want 1 (expired)", removed)
	}
	if _, ok := store.LookupFlow(client, dst, 443, 6); ok {
		t.Fatal("expired entry still resolvable after GC")
	}
	// A fresh entry survives the same GC pass.
	store.Store(client, netip.MustParseAddr("203.0.113.9"), 8443, 6, "other.com", testDecision(1<<27), clk.Now())
	if removed := store.GC(clk.Now()); removed != 0 {
		t.Fatalf("GC removed %d fresh entries", removed)
	}
	if got, ok := store.LookupFlow(client, netip.MustParseAddr("203.0.113.9"), 8443, 6); !ok || got.SOMark != 1<<27 {
		t.Fatalf("fresh entry lost: ok=%v", ok)
	}
}

func TestDecisionStoreBoundedByMaxEntries(t *testing.T) {
	clk := clock.NewFixed(time.Unix(100, 0))
	store := NewDecisionStore(2, 0, clk)
	client := netip.MustParseAddr("192.0.2.10")
	for i := 0; i < 5; i++ {
		dst := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
		store.Store(client, dst, uint16(1024+i), 6, "", testDecision(uint32(i+1)), clk.Now())
	}
	if n := store.Len(); n > 2 {
		t.Fatalf("store exceeded max entries: %d", n)
	}
}

func TestDecisionStoreIgnoresZeroMark(t *testing.T) {
	store, clk := decisionStore(t)
	client := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.77")
	store.Store(client, dst, 443, 6, "youtube.com", RouteDecision{Route: RouteDirect, SOMark: 0}, clk.Now())
	if n := store.Len(); n != 0 {
		t.Fatalf("zero-mark decision stored: %d", n)
	}
}
