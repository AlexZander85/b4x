// Package reserve is the carrier-registry seam of E-PROTON design §7
// (review P2, stage PT6b step б): the place where the daemon registers
// every reserve transport KIND with its selection priority, so the scoped
// router / future selection trees can enumerate carriers without importing
// service internals.
//
// The RegionTransportPolicy lesson (Nova I4) is encoded here as a red
// line: a reserve is a NAMED carrier with an explicit priority — the
// scoped router picks it deliberately; no transport ever silently
// substitutes another. Proton carries the LOWEST priority of the family
// (design §7: strictly below AWG-WARP/MASQUE/H3 and below the other
// reserves — it is the last UDP full-scope fallback, never a default).
//
// warp/masque/h3 and opera/fxvpn join this registry as their own review
// stages land on the same Carrier shape; until then the trees see only
// the kinds that registered — an honest, enumerable state.
package reserve

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
)

// Kind identifies a reserve transport (stable wire string, kebab-case).
type Kind string

// The known reserve kinds. Only kinds that ACTUALLY registered appear in
// List(); the constants alone do not promise an implementation.
const (
	KindWarp   Kind = "warp"   // AWG-WARP (UDP full-scope)
	KindMasque Kind = "masque" // MASQUE-WARP (UDP full-scope)
	KindH3     Kind = "h3"     // MASQUE-WARP H3 nested (UDP full-scope)
	KindOpera  Kind = "opera"  // Opera VPN (TCP only)
	KindFxvpn  Kind = "fxvpn"  // Firefox VPN (TCP only)
	KindProton Kind = "proton" // Proton VPN AWG (UDP full-scope)
)

// Priorities encode the design §7 tree order (HIGHER wins). Proton sits
// strictly below AWG-WARP/MASQUE/H3 — and below the TCP-only reserves —
// because it is the last-call UDP fallback with a third-party geo-exit.
const (
	PriorityWarp   = 60
	PriorityMasque = 50
	PriorityH3     = 40
	PriorityOpera  = 30
	PriorityFxvpn  = 20
	PriorityProton = 10
)

// Carrier is the scoped-router contract of a reserve transport (review P2
// step а): TCP streams through DialStream; UDP through DialUDP when
// SupportsUDP is true (Proton is the only UDP full-scope reserve today —
// the QUIC-scope consumers the UDP legs exist for).
type Carrier interface {
	// Kind is the stable transport kind this carrier serves.
	Kind() Kind
	// DialStream dials ONE TCP stream to addr THROUGH the tunnel.
	DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	// SupportsUDP reports native UDP egress. TCP-only carriers return
	// false and their DialUDP must not be called.
	SupportsUDP() bool
	// DialUDP dials ONE UDP exchange to addr THROUGH the tunnel (a
	// datagram-capable net.Conn bound to addr).
	DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
}

// Entry is one registered carrier with its selection priority.
type Entry struct {
	Kind     Kind
	Priority int
	Carrier  Carrier
}

var (
	mu       sync.Mutex
	registry = map[Kind]Entry{}
)

// Register wires a carrier into the trees. Re-registering a kind replaces
// the previous carrier (engine restart / soft-swap semantics); it never
// duplicates. nil is a no-op (disabled engines stay unregistered).
func Register(c Carrier) {
	if c == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	registry[c.Kind()] = Entry{Kind: c.Kind(), Priority: priorityOf(c.Kind()), Carrier: c}
}

// Unregister removes a kind (engine stop).
func Unregister(kind Kind) {
	mu.Lock()
	defer mu.Unlock()
	delete(registry, kind)
}

// Lookup returns one carrier by kind.
func Lookup(kind Kind) (Entry, bool) {
	mu.Lock()
	defer mu.Unlock()
	e, ok := registry[kind]
	return e, ok
}

// List snapshots the registered carriers sorted by priority DESC (the
// tree order: the head is the first candidate, proton the last).
func List() []Entry {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Entry, 0, len(registry))
	for _, e := range registry {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// Reset clears the registry (tests only).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	registry = map[Kind]Entry{}
}

func priorityOf(k Kind) int {
	switch k {
	case KindWarp:
		return PriorityWarp
	case KindMasque:
		return PriorityMasque
	case KindH3:
		return PriorityH3
	case KindOpera:
		return PriorityOpera
	case KindFxvpn:
		return PriorityFxvpn
	case KindProton:
		return PriorityProton
	default:
		return 0 // unknown kinds park at the tail until prioritized
	}
}
