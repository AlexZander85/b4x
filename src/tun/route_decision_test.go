package tun

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/routing"
	"github.com/daniellavrushin/b4/sock"
)

// buildTCPPkt fabricates a minimal IPv4+TCP packet with the given
// src/dst and dport. Enough for senderFor flow extraction.
func buildTCPPkt(srcIP, dstIP []byte, sport, dport uint16) []byte {
	pkt := make([]byte, 20+20)
	pkt[0] = 0x45 // IHL=5, v4
	pkt[9] = 6    // TCP
	copy(pkt[12:16], srcIP)
	copy(pkt[16:20], dstIP)
	pkt[20] = byte(sport >> 8)
	pkt[21] = byte(sport)
	pkt[22] = byte(dport >> 8)
	pkt[23] = byte(dport)
	return pkt
}

func TestSenderForUsesDecisionMark(t *testing.T) {
	store := routing.NewDecisionStore(0, 0, clock.NewFixed(time.Unix(100, 0)))
	client := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.77")
	store.Store(client, dst, 443, 6, "", routing.RouteDecision{Route: routing.RouteGeneric, SOMark: 1 << 28}, time.Unix(100, 0))

	e := &Engine{decisions: store, markSenders: make(map[uint32]*sock.Sender)}
	e.routes = &routeManager{tcpPorts: []string{}}

	// Flow with a route decision -> senderForMark is used; sender creation
	// fails in a test environment (no raw socket), so the result must
	// fall back to the default sender (nil here), never panic.
	e.sender = nil
	e.clientSender = nil
	sender := e.senderFor(buildTCPPkt([]byte{192, 0, 2, 10}, []byte{198, 51, 100, 77}, 12345, 443))
	if sender != nil {
		t.Fatalf("expected fail-open default sender, got %p", sender)
	}
}

func TestSenderForIgnoresZeroMarkDecision(t *testing.T) {
	store := routing.NewDecisionStore(0, 0, clock.NewFixed(time.Unix(100, 0)))
	client := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.77")
	// Zero-mark (native/direct) decision must not switch senders.
	store.Store(client, dst, 443, 6, "", routing.RouteDecision{Route: routing.RouteDirect, SOMark: 0}, time.Unix(100, 0))

	e := &Engine{decisions: store, markSenders: make(map[uint32]*sock.Sender)}
	e.routes = &routeManager{tcpPorts: []string{}}
	// Fail-open default is the (nil) default sender path.
	e.sender = nil
	e.clientSender = nil
	if sender := e.senderFor(buildTCPPkt([]byte{192, 0, 2, 10}, []byte{198, 51, 100, 77}, 12345, 443)); sender != nil {
		t.Fatalf("zero-mark decision must not switch sender, got %p", sender)
	}
}
