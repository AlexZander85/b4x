package socks5

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/routing"
)

func TestMarkForClientByIP(t *testing.T) {
	store := routing.NewDecisionStore(0, 0, clock.NewFixed(time.Unix(100, 0)))
	client := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.77")
	// Store keyed for TCP (proto 6).
	store.Store(client, dst, 443, 6, "", routing.RouteDecision{Route: routing.RouteGeneric, SOMark: 1 << 28}, time.Unix(100, 0))

	s := &Server{routeDecisions: store}
	if mark := s.markForClient(client, "198.51.100.77", 443); mark != 1<<28 {
		t.Fatalf("IP flow mark=%d want %d", mark, 1<<28)
	}
	// Unknown destination -> no mark.
	if mark := s.markForClient(client, "203.0.113.9", 443); mark != 0 {
		t.Fatalf("unknown destination mark=%d want 0", mark)
	}
}

func TestMarkForClientByDomain(t *testing.T) {
	store := routing.NewDecisionStore(0, 0, clock.NewFixed(time.Unix(100, 0)))
	client := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.77")
	store.Store(client, dst, 443, 6, "youtube.COM", routing.RouteDecision{Route: routing.RouteProxy, SOMark: 1 << 29}, time.Unix(100, 0))

	s := &Server{routeDecisions: store}
	// Domain lookup is case-insensitive.
	if mark := s.markForClient(client, "YouTube.com", 443); mark != 1<<29 {
		t.Fatalf("domain mark=%d want %d", mark, 1<<29)
	}
	// Different client does not resolve.
	other := netip.MustParseAddr("192.0.2.99")
	if mark := s.markForClient(other, "youtube.com", 443); mark != 0 {
		t.Fatalf("cross-client mark=%d want 0", mark)
	}
}
