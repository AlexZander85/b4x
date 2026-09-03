// Netzone tests (review §6): the /24 header format, the STUN XOR-MAPPED-
// ADDRESS parsing against a fake STUN edge, and the honest degrade when no
// anchor answers. The api.go contract (header sent only when non-empty) is
// pinned in transport/proton by the logicals header test.
package protonservice

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

// fakeSTUNEdge answers every binding request with a Binding Success
// carrying XOR-MAPPED-ADDRESS(ip) (and nothing else).
func fakeSTUNEdge(t *testing.T, ip net.IP, port uint16, reply bool) netzoneDialFunc {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if !reply || n < 20 {
				continue
			}
			resp := make([]byte, 20+12)
			binary.BigEndian.PutUint16(resp[0:2], 0x0101) // binding success
			copy(resp[8:20], buf[8:20])                   // echo the txn id
			binary.BigEndian.PutUint16(resp[20:22], 0x0020)
			binary.BigEndian.PutUint16(resp[22:24], 8)
			resp[24] = 0x00 // reserved
			resp[25] = 0x01 // IPv4
			xport := port ^ uint16(stunMagicCookie>>16)
			binary.BigEndian.PutUint16(resp[26:28], xport)
			for i := 0; i < 4; i++ {
				resp[28+i] = ip[i] ^ byte(uint32(stunMagicCookie)>>(24-8*i))
			}
			binary.BigEndian.PutUint16(resp[2:4], 12)
			if _, err := pc.WriteTo(resp, addr); err != nil {
				return
			}
		}
	}()
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, pc.LocalAddr().String())
	}
}

// TestNetzoneHeaderFormat pins the review §6 unit: a public IPv4 renders as
// its /24; v6/loopback/unspecified yield "" (the header is omitted).
func TestNetzoneHeaderFormat(t *testing.T) {
	cases := []struct {
		in   net.IP
		want string
	}{
		{net.ParseIP("203.0.113.199"), "203.0.113.0/24"},
		{net.ParseIP("1.2.3.4"), "1.2.3.0/24"},
		{net.ParseIP("127.0.0.1"), ""},   // loopback never leaks
		{net.ParseIP("0.0.0.0"), ""},     // unspecified
		{net.ParseIP("2001:db8::1"), ""}, // v6 has no netzone
		{net.ParseIP("not-an-ip"), ""},   // invalid
	}
	for _, c := range cases {
		if got := maskV4To24(c.in); got != c.want {
			t.Fatalf("maskV4To24(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestNetzoneDiscoverParsesSTUN: the fake edge answers with the mapped
// address 203.0.113.199 -> the netzone is its /24.
func TestNetzoneDiscoverParsesSTUN(t *testing.T) {
	dial := fakeSTUNEdge(t, net.IPv4(203, 0, 113, 199).To4(), 3478, true)
	got := discoverNetzone(context.Background(), dial)
	if got != "203.0.113.0/24" {
		t.Fatalf("discoverNetzone = %q, want 203.0.113.0/24", got)
	}
}

// TestNetzoneDiscoverFallsBackAcrossAnchors: the first anchor dead, the
// second answers — the walk continues.
func TestNetzoneDiscoverFallsBackAcrossAnchors(t *testing.T) {
	// Simulate a dead first anchor by failing the dial for it; the second
	// anchor answers through a fresh fake edge.
	zone := discoverNetzone(context.Background(), func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == netzoneAnchors[0] {
			return nil, errors.New("dead anchor")
		}
		return fakeSTUNEdge(t, net.IPv4(198, 51, 100, 7).To4(), 3478, true)(ctx, network, addr)
	})
	if zone != "198.51.100.0/24" {
		t.Fatalf("netzone after fallback = %q, want 198.51.100.0/24", zone)
	}
}

// TestNetzoneDiscoverSilentEdge: an edge that never answers (and dead
// anchors) yields "" — the honest degrade, no wrong header.
func TestNetzoneDiscoverSilentEdge(t *testing.T) {
	dial := fakeSTUNEdge(t, net.IPv4(203, 0, 113, 199).To4(), 3478, false)
	// Shorten the anchor walk: a silent edge burns the full probe timeout
	// per anchor, so patch the list for the test.
	old := netzoneAnchors
	netzoneAnchors = netzoneAnchors[:1]
	t.Cleanup(func() { netzoneAnchors = old })
	if got := discoverNetzone(context.Background(), dial); got != "" {
		t.Fatalf("silent edge must yield empty netzone, got %q", got)
	}
}
