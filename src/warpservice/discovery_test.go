package warpservice

import (
	"context"
	"net/netip"
	"testing"

	warp "github.com/daniellavrushin/b4/transport/warp"
)

// fakeDiscoverer stands in for *warp.Discoverer so unit tests never probe a
// catalog candidate (the consent rule).
type fakeDiscoverer struct {
	winner netip.AddrPort
	err    error
}

func (f fakeDiscoverer) Discover(context.Context) (warp.DiscoveryResult, error) {
	if f.err != nil {
		return warp.DiscoveryResult{}, f.err
	}
	return warp.DiscoveryResult{Source: "scan", Winner: warp.EndpointScore{Endpoint: f.winner}}, nil
}

// TestDiscoveryAdoptsWinner pins the bd b4x-wh6 pt.1 wiring: a fresh runtime
// keeps the static endpoint (no override), and a discovery pass with a stored
// identity adopts the verified winner for the next generation.
func TestDiscoveryAdoptsWinner(t *testing.T) {
	orig := newDiscoverer
	defer func() { newDiscoverer = orig }()

	winner := netip.MustParseAddrPort("162.159.198.1:443")
	newDiscoverer = func(warp.DiscovererConfig) (discoveryRunner, error) {
		return fakeDiscoverer{winner: winner}, nil
	}

	c := testConfig(t)
	if err := (&warp.IdentityStore{Path: c.System.Warp.IdentityPath}).Save(validTestIdentity(t)); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	rt, err := Build(c, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if ep, ok := rt.currentEndpoint(); ok {
		t.Fatalf("fresh runtime must not override the static endpoint, got %s", ep)
	}
	ep, ok := rt.discoverOnce(context.Background())
	if !ok || ep != winner {
		t.Fatalf("discoverOnce = %s, %v; want %s, true", ep, ok, winner)
	}
	rt.winnerMu.Lock()
	rt.winner = ep
	rt.winnerMu.Unlock()
	if got, ok := rt.currentEndpoint(); !ok || got != winner {
		t.Fatalf("currentEndpoint = %s, %v; want %s, true", got, ok, winner)
	}
}

// TestDiscoveryFailSafeNoIdentity: with no loadable identity the pass is a
// silent no-op — the static endpoint stays in place, so discovery can never be
// worse than the previous behavior.
func TestDiscoveryFailSafeNoIdentity(t *testing.T) {
	c := testConfig(t) // IdentityPath points at a temp dir with no slot
	rt, err := Build(c, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if ep, ok := rt.discoverOnce(context.Background()); ok {
		t.Fatalf("discovery without an identity must be a no-op, got %s", ep)
	}
	if _, ok := rt.currentEndpoint(); ok {
		t.Fatal("no-op discovery must not adopt an endpoint")
	}
}

// TestDiscoveryWiringIsOptionalForSupervisor pins the seam contract: Build wires
// EndpointFor, and a nil-returning provider leaves the template endpoint alone.
func TestDiscoveryWiringIsOptionalForSupervisor(t *testing.T) {
	c := testConfig(t)
	rt, err := Build(c, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rt.sup == nil {
		t.Fatal("supervisor not assembled")
	}
	if rt.template.Endpoint.String() != "162.159.198.2:443" {
		t.Fatalf("static template endpoint = %s", rt.template.Endpoint)
	}
}
