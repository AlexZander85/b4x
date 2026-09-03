// WG6 nested composition tests: config validation table and the Backend-B
// loopback forwarder driven over plain HOST sockets (no gVisor) so relay
// semantics, last-client-wins and close discipline are deterministic.
package transportwg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// nestedIdents builds two independent identities with distinct assigned
// addresses (the common valid fixture).
func nestedIdents(t *testing.T) (outer, inner *Identity) {
	t.Helper()
	opriv := mustKeyNow()
	ipriv := mustKeyNow()
	oedgePriv := mustKeyNow()
	iedgePriv := mustKeyNow()
	outer, err := NewIdentity(opriv.B64(), oedgePriv.Pub().B64(), "uS9/", "10.0.0.2", "", false)
	if err != nil {
		t.Fatal(err)
	}
	inner, err = NewIdentity(ipriv.B64(), iedgePriv.Pub().B64(), "uS8/", "10.0.1.2", "", false)
	if err != nil {
		t.Fatal(err)
	}
	return outer, inner
}

func validNestedWg() *NestedWgConfig {
	return &NestedWgConfig{
		Outer: NestedLayer{
			Profile: Profile{JunkCount: 4, JunkMin: 40, JunkMax: 70},
		},
		Inner:     NestedLayer{},
		OuterEdge: netip.MustParseAddrPort("162.159.193.5:2408"),
		InnerEdge: netip.MustParseAddrPort("198.51.100.7:4500"),
		InnerDial: netip.MustParseAddrPort("127.0.0.1:0"),
	}
}

func TestNestedWgValidate(t *testing.T) {
	outerID, innerID := nestedIdents(t)

	t.Run("happy", func(t *testing.T) {
		c := validNestedWg()
		c.Outer.Ident, c.Inner.Ident = outerID, innerID
		if err := c.Validate(); err != nil {
			t.Fatalf("valid nested rejected: %v", err)
		}
		if got := c.Outer.EffectiveMTU(true); got != DefaultMTU {
			t.Fatalf("outer MTU=%d want %d", got, DefaultMTU)
		}
		if got := c.Inner.EffectiveMTU(false); got != DefaultInnerMTU {
			t.Fatalf("inner MTU=%d want %d", got, DefaultInnerMTU)
		}
		if c.Outer.EffectiveKeepalive(true) == c.Inner.EffectiveKeepalive(false) {
			t.Fatal("keepalive defaults must stay separated")
		}
	})

	t.Run("identical-identity", func(t *testing.T) {
		c := validNestedWg()
		c.Outer.Ident, c.Inner.Ident = outerID, outerID
		if !errors.Is(c.Validate(), ErrNestedIdenticalIdentity) {
			t.Fatal("identical identities accepted")
		}
	})

	t.Run("address-conflict", func(t *testing.T) {
		c := validNestedWg()
		c.Outer.Ident = outerID
		same, err := NewIdentity(mustKeyNow().B64(), mustPub(t, mustKeyNow()).B64(), "uS7/", outerID.AssignedV4, "", false)
		if err != nil {
			t.Fatal(err)
		}
		c.Inner.Ident = same
		if !errors.Is(c.Validate(), ErrNestedAddressConflict) {
			t.Fatal("same assigned address accepted")
		}
	})

	t.Run("same-public-edge", func(t *testing.T) {
		c := validNestedWg()
		c.Outer.Ident, c.Inner.Ident = outerID, innerID
		c.InnerEdge = netip.MustParseAddrPort("162.159.193.5:9999")
		if !errors.Is(c.Validate(), ErrNestedSameEdge) {
			t.Fatal("same public edge accepted")
		}
	})

	t.Run("loopback-co-location-is-test-artifact", func(t *testing.T) {
		c := validNestedWg()
		c.Outer.Ident, c.Inner.Ident = outerID, innerID
		c.OuterEdge = netip.MustParseAddrPort("127.0.0.1:40001")
		c.InnerEdge = netip.MustParseAddrPort("127.0.0.2:4500") // distinct loopback IP
		if err := c.Validate(); err != nil {
			t.Fatalf("distinct-loopback test topology rejected: %v", err)
		}
	})

	t.Run("inner-dial-must-be-loopback", func(t *testing.T) {
		c := validNestedWg()
		c.Outer.Ident, c.Inner.Ident = outerID, innerID
		c.InnerDial = netip.MustParseAddrPort("192.0.2.1:500")
		if !errors.Is(c.Validate(), ErrInnerNotLoopback) {
			t.Fatal("direct-WAN inner dial accepted (carrier hole)")
		}
	})

	t.Run("mtu-gradient", func(t *testing.T) {
		c := validNestedWg()
		c.Outer.Ident, c.Inner.Ident = outerID, innerID
		c.Inner.MTU = 1280 // == outer default
		if !errors.Is(c.Validate(), ErrNestedMTUGradient) {
			t.Fatal("flat MTU accepted")
		}
	})

	t.Run("outer-obf-required", func(t *testing.T) {
		c := validNestedWg()
		c.Outer.Ident, c.Inner.Ident = outerID, innerID
		c.Outer.Profile = Profile{} // vanilla outer defeats R3 layering
		if !errors.Is(c.Validate(), ErrOuterObfRequired) {
			t.Fatal("vanilla outer accepted")
		}
	})

	t.Run("keepalive-collision", func(t *testing.T) {
		c := validNestedWg()
		c.Outer.Ident, c.Inner.Ident = outerID, innerID
		c.Inner.KeepaliveSec = NestedOuterKeepaliveSec // == outer default 5
		if !errors.Is(c.Validate(), ErrKeepaliveCollision) {
			t.Fatal("synchronized keepalives accepted")
		}
	})
}

// ---- forwarder over real host sockets ----

// fakeEdgeUDP is a stand-in inner edge on real loopback sockets.
type fakeEdgeUDP struct {
	conn     *net.UDPConn
	lastFrom *net.UDPAddr
}

func startFakeEdgeUDP(t *testing.T) *fakeEdgeUDP {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return &fakeEdgeUDP{conn: pc.(*net.UDPConn)}
}

func (f *fakeEdgeUDP) addr() netip.AddrPort {
	local, _ := net.ResolveUDPAddr("udp", f.conn.LocalAddr().String())
	ip, _ := netip.AddrFromSlice(local.IP)
	return netip.AddrPortFrom(ip.Unmap(), uint16(local.Port))
}

// readOne awaits one datagram and remembers its source (the forwarder).
func (f *fakeEdgeUDP) readOne(t *testing.T) string {
	t.Helper()
	_ = f.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, from, err := f.conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("edge read: %v", err)
	}
	f.lastFrom = from
	return string(buf[:n])
}

// echoLast answers the last sender with prefix+payload.
func (f *fakeEdgeUDP) echoLast(t *testing.T, prefix byte, payload string) {
	t.Helper()
	if _, err := f.conn.WriteToUDP(append([]byte{prefix}, payload...), f.lastFrom); err != nil {
		t.Fatalf("edge echo: %v", err)
	}
}

func TestForwarderRelayBothDirections(t *testing.T) {
	edge := startFakeEdgeUDP(t)
	dial := func(ctx context.Context, network, address string) (udpConn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		c, err := d.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return c.(udpConn), nil
	}
	fwd, err := NewLoopbackForwarder(dial, edge.addr())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientAddr, err := fwd.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !clientAddr.Addr().IsLoopback() || clientAddr.Port() == 0 {
		t.Fatalf("forwarder bound %v want 127.0.0.1:<ephemeral>", clientAddr)
	}

	client, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(clientAddr.Port())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	payload := []byte("inner-handshake-initiation")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if got := edge.readOne(t); got != string(payload) {
		t.Fatalf("edge saw %q want %q", got, payload)
	}
	edge.echoLast(t, 0xAA, string(payload))
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, 1024)
	n, err := client.Read(got)
	if err != nil {
		t.Fatalf("relay round-trip: %v", err)
	}
	if n != len(payload)+1 || got[0] != 0xAA || string(got[1:n]) != string(payload) {
		t.Fatalf("round-trip payload mismatch: %q", got[:n])
	}

	if err := fwd.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	fwd.Wait() // pumps joined
	if err := fwd.Close(); err != nil {
		t.Fatalf("second close must be idempotent no-error, got %v", err)
	}
}

// TestForwarderLastClientWins: superseding client takes over the relay.
// Each round-trip SYNCHRONIZES the previous write through the whole chain,
// so ordering is deterministic (two blind writes would race — same class
// as the WG5 cap-boundary lesson).
func TestForwarderLastClientWins(t *testing.T) {
	edge := startFakeEdgeUDP(t)
	dial := func(ctx context.Context, network, address string) (udpConn, error) {
		c, err := net.Dial(network, address)
		if err != nil {
			return nil, err
		}
		return c.(udpConn), nil
	}
	fwd, _ := NewLoopbackForwarder(dial, edge.addr())
	defer fwd.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bind, err := fwd.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}

	mkClient := func() *net.UDPConn {
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(bind.Port())})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	readOK := func(c *net.UDPConn, prefix byte, payload string) {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		got := make([]byte, 128)
		n, err := c.Read(got)
		if err != nil || n != len(payload)+1 || got[0] != prefix || string(got[1:n]) != payload {
			head := got
			if n < len(head) {
				head = got[:n]
			}
			t.Fatalf("client relay broken: n=%d err=%v head=%x", n, err, head)
		}
	}
	write := func(c *net.UDPConn, s string) {
		t.Helper()
		if _, err := c.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}

	first, second := mkClient(), mkClient()
	defer first.Close()
	defer second.Close()

	// Generation 1: first owns the relay (round-trip proves it).
	write(first, "stale")
	if got := edge.readOne(t); got != "stale" {
		t.Fatalf("edge saw %q want stale", got)
	}
	edge.echoLast(t, 0xBB, "stale")
	readOK(first, 0xBB, "stale")

	// Generation 2: second writes LAST and must take over.
	write(second, "fresh")
	if got := edge.readOne(t); got != "fresh" {
		t.Fatalf("edge saw %q want fresh", got)
	}
	edge.echoLast(t, 0xCC, "fresh")
	readOK(second, 0xCC, "fresh") // fails if first is still the recorded client
}

func TestForwarderStartGuards(t *testing.T) {
	dial := func(ctx context.Context, network, address string) (udpConn, error) {
		return nil, errors.New("no-route")
	}
	if _, err := NewLoopbackForwarder(nil, netip.MustParseAddrPort("127.0.0.1:500")); err == nil {
		t.Fatal("nil dial accepted")
	}
	if _, err := NewLoopbackForwarder(dial, netip.AddrPort{}); err == nil {
		t.Fatal("invalid inner edge accepted")
	}
	fwd, err := NewLoopbackForwarder(dial, netip.MustParseAddrPort("127.0.0.1:500"))
	if err != nil {
		t.Fatal(err)
	}
	defer fwd.Close()
	if _, err := fwd.Start(context.Background()); err == nil {
		t.Fatal("upstream dial failure not surfaced")
	}
}
