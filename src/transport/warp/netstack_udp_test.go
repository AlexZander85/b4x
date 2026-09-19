package transportwarp

// bd b4x-ive: the nested M+M inner H3 leg. These tests pin the two new
// contracts in isolation:
//
//   - NetstackCarrier.ListenPacketConn mints a working UDP PacketConn on the
//     tunnel stack (its datagrams ride the same sink as the TCP carrier);
//   - the H3SessionConfig.H3PacketConn seam is honoured by DialH3Session and
//     a factory failure is a LOCAL verdict, never a network one.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// TestNetstackUDPPacketConnRoundTrip wires two carriers back-to-back and
// exchanges one datagram: A's unconnected PacketConn -> UDP echo on B's stack
// -> reply back to A. Proves the UDP leg traverses the tunnel sink.
func TestNetstackUDPPacketConnRoundTrip(t *testing.T) {
	const mtu = DefaultMTU
	a, b := wireTwoCarriers(t, mtu)
	defer a.Close()
	defer b.Close()

	bAddr := netip.MustParseAddr("100.64.0.2")
	server, err := gonet.DialUDP(b.stack, &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(bAddr.AsSlice()),
		Port: 9999,
	}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("udp bind on B: %v", err)
	}
	defer server.Close()

	go func() {
		buf := make([]byte, 2048)
		n, from, rerr := server.ReadFrom(buf)
		if rerr != nil {
			return
		}
		_, _ = server.WriteTo(buf[:n], from)
	}()

	pc, err := a.ListenPacketConn()
	if err != nil {
		t.Fatalf("listen packet conn: %v", err)
	}
	defer pc.Close()

	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(bAddr, 9999))
	if _, err := pc.WriteTo([]byte("udp-through-netstack"), dst); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if string(buf[:n]) != "udp-through-netstack" {
		t.Fatalf("udp payload = %q", buf[:n])
	}
}

// TestDialH3SessionUsesSuppliedPacketConn pins the UDP seam: with a factory
// supplied, DialH3Session must establish against the fake H3 edge exactly as
// the Policy.ListenUDP path does.
func TestDialH3SessionUsesSuppliedPacketConn(t *testing.T) {
	e := newFakeH3Edge(t)
	var called bool
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) {
		c.H3PacketConn = func(context.Context, string, string) (net.PacketConn, error) {
			called = true
			return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		}
	})
	sess, res, err := DialH3Session(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dial via supplied PacketConn: %v (class=%s)", err, res.FailureClass)
	}
	defer sess.Close()
	if !called {
		t.Fatal("H3PacketConn factory was not used")
	}
	if res.Status != 200 {
		t.Fatalf("status = %d, want 200", res.Status)
	}
}

// TestDialH3SessionPacketConnFactoryErrorIsLocalSocket pins the classifier:
// a caller-supplied socket failure is a local verdict (FailureLocalSocket),
// never a network switch class.
func TestDialH3SessionPacketConnFactoryErrorIsLocalSocket(t *testing.T) {
	e := newFakeH3Edge(t)
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) {
		c.H3PacketConn = func(context.Context, string, string) (net.PacketConn, error) {
			return nil, errors.New("injected local bind failure")
		}
	})
	_, res, err := DialH3Session(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected failure")
	}
	if res.FailureClass != FailureLocalSocket {
		t.Fatalf("class = %q, want %q", res.FailureClass, FailureLocalSocket)
	}
}

// TestH3ConfigFromSessionCarriesUDPSeam pins the ladder threading: the
// SessionConfig UDP seam and the PMTUD toggle must survive the H2->H3 config
// derivation untouched.
func TestH3ConfigFromSessionCarriesUDPSeam(t *testing.T) {
	called := false
	fn := func(context.Context, string, string) (net.PacketConn, error) {
		called = true
		return nil, nil
	}
	h := h3ConfigFromSession(SessionConfig{
		Endpoint:       netip.MustParseAddrPort("162.159.198.2:443"),
		H3PacketConn:   fn,
		DisableH3PMTUD: true,
	})
	if h.H3PacketConn == nil {
		t.Fatal("H3PacketConn not carried")
	}
	if !h.DisableH3PMTUD {
		t.Fatal("DisableH3PMTUD not carried")
	}
	_, _ = h.H3PacketConn(context.Background(), "udp4", "0.0.0.0:0")
	if !called {
		t.Fatal("carried factory not the original")
	}
}

// TestLadderH3OnlyNeverFallsBack pins the M+M inner contract: an H3 failure
// returns the H3 verdict directly — the forbidden H2-in-H2 fallback must never
// be dialed, and no switch event is emitted.
func TestLadderH3OnlyNeverFallsBack(t *testing.T) {
	var h3c, h2c int
	d, _ := newTestLadder(t, func(c *LadderConfig) {
		c.H3Only = true
		c.DialH3 = func(context.Context, H3SessionConfig) (*H3Session, H3ConnectResult, error) {
			h3c++
			return nil, H3ConnectResult{FailureClass: FailureUDPEgressBlocked, DurationMS: 5}, errors.New("injected")
		}
		c.DialH2 = func(context.Context, SessionConfig) (*Session, ConnectResult, error) {
			h2c++
			return nil, ConnectResult{}, errors.New("h2 must not be dialed")
		}
	})
	scfg := SessionConfig{Endpoint: netip.MustParseAddrPort("162.159.198.2:443")}
	ctx := context.Background()

	sess, att, err := d.Dial(ctx, scfg)
	if err == nil || sess != nil {
		t.Fatalf("H3-only failure must surface, got sess=%v err=%v", sess, err)
	}
	if att.Transport != TransportH3 {
		t.Fatalf("transport = %q, want h3", att.Transport)
	}
	if len(att.Events) != 0 {
		t.Fatalf("H3-only must emit no switch event, got %+v", att.Events)
	}
	if h3c != 1 || h2c != 0 {
		t.Fatalf("dial counts h3=%d h2=%d, want 1/0", h3c, h2c)
	}
	// Repeated generations keep retrying H3: no anti-oscillation gate applies
	// when there is no fallback carrier.
	for i := 0; i < 3; i++ {
		if _, _, err := d.Dial(ctx, scfg); err == nil {
			t.Fatal("H3-only generation must keep failing")
		}
	}
	if h3c != 4 || h2c != 0 {
		t.Fatalf("dial counts after retries h3=%d h2=%d, want 4/0", h3c, h2c)
	}
	m := d.Metrics()
	if m.H3Blocked || m.FallbackToH2 != 0 || m.Switches != 0 {
		t.Fatalf("H3-only metrics must show no fallback: %+v", m)
	}
}
