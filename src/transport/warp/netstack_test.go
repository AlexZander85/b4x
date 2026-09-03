package transportwarp

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// chanSink is a PacketSink feeding an in-memory wire (stands in for a MASQUE
// session capsule path).
type chanSink struct {
	ch chan []byte
}

func (s *chanSink) WritePacket(pkt []byte) error {
	cp := append([]byte(nil), pkt...)
	select {
	case s.ch <- cp:
		return nil
	default:
		return ErrNetstackClosed
	}
}

// wireTwoCarriers connects two carriers back-to-back as if their sessions
// were one tunnel: A.out -> B.in, B.out -> A.in.
func wireTwoCarriers(t *testing.T, mtu int) (*NetstackCarrier, *NetstackCarrier) {
	t.Helper()
	aToB := make(chan []byte, 256)
	bToA := make(chan []byte, 256)
	a, errA := AttachNetstack(&chanSink{ch: aToB}, [4]byte{100, 64, 0, 1}, mtu, bToA)
	b, errB := AttachNetstack(&chanSink{ch: bToA}, [4]byte{100, 64, 0, 2}, mtu, aToB)
	if errA != nil || errB != nil {
		t.Fatalf("carrier attach failed: %v / %v", errA, errB)
	}
	return a, b
}

func TestNetstackTCPRoundTrip(t *testing.T) {
	const mtu = DefaultMTU
	a, b := wireTwoCarriers(t, mtu)
	defer a.Close()
	defer b.Close()

	// Server inside carrier B's stack: echo listener on :8080.
	l, err := gonet.ListenTCP(b.stack, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(netip.MustParseAddr("100.64.0.2").AsSlice()),
		Port: 8080,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	payload := []byte("warp-netstack-ok")
	go func() {
		conn, aerr := l.Accept()
		if aerr != nil {
			return
		}
		conn.Write(payload)
		conn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := a.DialStream(ctx, netip.MustParseAddrPort("100.64.0.2:8080"))
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer conn.Close()
	got, err := io.ReadAll(conn)
	if err != nil && !bytes.Contains(got, payload) {
		t.Fatalf("round trip: %v, got %q", err, got)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}
}

func TestNetstackDialRejectsV6AndClosed(t *testing.T) {
	a, b := wireTwoCarriers(t, DefaultMTU)
	defer a.Close()
	defer b.Close()

	ctx := context.Background()
	if _, err := a.DialStream(ctx, netip.MustParseAddrPort("[2001:db8::1]:443")); err == nil {
		t.Fatal("v6 dial must fail closed on v1 carrier")
	}

	a.Close()
	if _, err := a.DialStream(ctx, netip.MustParseAddrPort("100.64.0.2:80")); err == nil {
		t.Fatal("dial after close must fail")
	}
}

func TestNetstackHTTPHelpersWiring(t *testing.T) {
	a, _ := wireTwoCarriers(t, DefaultMTU)
	defer a.Close()
	if HTTPSExchangeViaNetstack(a) == nil {
		t.Fatal("exchange adapter missing")
	}
	if DoHExchangeViaNetstack(a, "https://1.1.1.1/dns-query") == nil {
		t.Fatal("doh adapter missing")
	}
	if HTTPSExchangeViaNetstack(nil) != nil {
		t.Fatal("nil carrier must produce nil adapters")
	}
}
