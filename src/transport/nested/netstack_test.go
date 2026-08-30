package nested

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	twg "github.com/daniellavrushin/b4/transport/wg"
)

// newTestNetstack builds a real gVisor netstack through the transportwg
// factory (CI-safe: the same pattern the WG suite uses everywhere).
func newTestNetstack(t *testing.T) *twg.Tunnel {
	t.Helper()
	tun, err := twg.NewTunnel(twg.TunnelConfig{
		Mode:      twg.ModeNetstack,
		Addresses: []netip.Addr{netip.AddrFrom4([4]byte{198, 51, 100, 7})},
		DNS:       []netip.Addr{netip.AddrFrom4([4]byte{8, 8, 8, 8})},
		MTU:       1280,
	})
	if err != nil {
		t.Fatalf("create netstack tunnel: %v", err)
	}
	return tun
}

func TestNetstackCarrierInjectsDatagram(t *testing.T) {
	tun := newTestNetstack(t)
	c, err := NewNetstackCarrier(tun.Netstack, "gen=1")
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}

	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 9}), 51820)
	payload := []byte("handshake-init")

	type readOut struct {
		pkt []byte
		err error
	}
	out := make(chan readOut, 1)
	go func() {
		// Upstream tun.Device contract: Read RETURNS the buffer count (1);
		// the byte count lands in sizes[0].
		bufs := [][]byte{make([]byte, 65535)}
		sizes := make([]int, 1)
		nBufs, rerr := tun.Device.Read(bufs, sizes, 0)
		if rerr != nil {
			out <- readOut{err: rerr}
			return
		}
		if nBufs < 1 || sizes[0] == 0 {
			out <- readOut{err: errors.New("device returned no bytes")}
			return
		}
		out <- readOut{pkt: bufs[0][:sizes[0]]}
	}()

	if err := c.InjectUDPDatagram(dst, payload); err != nil {
		t.Fatalf("inject: %v", err)
	}

	select {
	case ro := <-out:
		if ro.err != nil {
			t.Fatalf("device read: %v", ro.err)
		}
		tuple, got, err := SplitUDPDatagram(ro.pkt)
		if err != nil {
			t.Fatalf("split injected packet: %v", err)
		}
		if tuple.DstIP != dst.Addr() || tuple.DstPort != dst.Port() {
			t.Fatalf("dst = %v:%d, want %v", tuple.DstIP, tuple.DstPort, dst)
		}
		if string(got) != string(payload) {
			t.Fatalf("payload = %q, want %q", got, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet reached the tunnel device")
	}
}

func TestNetstackCarrierProofAndClose(t *testing.T) {
	tun := newTestNetstack(t)
	c, err := NewNetstackCarrier(tun.Netstack, "gen=7")
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	proof, ok := c.ProofSnapshot()
	if !ok || proof != "netstack:gen=7" {
		t.Fatalf("proof = %q ok=%v", proof, ok)
	}
	c.Close()
	if _, ok := c.ProofSnapshot(); ok {
		t.Fatal("proof must be false after Close")
	}
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 9}), 53)
	if _, err := c.DialUDPThrough(context.Background(), dst); !errors.Is(err, ErrCarrierClosed) {
		t.Fatalf("post-close dial err = %v, want ErrCarrierClosed", err)
	}
}

func TestNetstackCarrierTCPClosedRefuses(t *testing.T) {
	tun := newTestNetstack(t)
	c, err := NewNetstackCarrier(tun.Netstack, "gen=1")
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	c.Close()

	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 10}), 443)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := c.DialTCPThrough(ctx, dst); !errors.Is(err, ErrCarrierClosed) {
		t.Fatalf("closed-carrier tcp dial err = %v, want ErrCarrierClosed", err)
	}

	// NOTE (documented limitation, same class as transportwg trustgate.go):
	// a TCP connect THROUGH this gVisor pin does not honor ctx cancellation
	// during the handshake, so an unanswered-SYN e2e case belongs to the
	// integration stand, not unit CI.
}

// ---- PATCH-24: E-NM NIT package tests ----

// TestResolveCarrierRejectsDeclaredDatagram (E18): CarrierDatagram is
// resolved-only; declaring it in a pair must be a structural error, in sync
// with PairConfig.Validate.
func TestResolveCarrierRejectsDeclaredDatagram(t *testing.T) {
	p := validPair()
	p.Carrier = CarrierDatagram
	if _, err := ResolveCarrier(p, false); err == nil || !strings.Contains(err.Error(), "not declarable") {
		t.Fatalf("declared datagram mode accepted: %v", err)
	}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate must reject the declared datagram mode too")
	}
}

// TestSplitUDPDatagramIgnoresPaddingPastTotal (E20): a datagram padded past
// its IPv4 total-length must not expose the padding as payload; the udp
// length is checked against tot.
func TestSplitUDPDatagramIgnoresPaddingPastTotal(t *testing.T) {
	payload := []byte("hello-nested-udp")
	pkt, err := BuildUDPDatagram(
		netip.AddrFrom4([4]byte{198, 51, 100, 7}),
		netip.AddrFrom4([4]byte{10, 66, 66, 1}),
		40000, 51820, payload)
	if err != nil {
		t.Fatal(err)
	}
	padded := append(append([]byte(nil), pkt...), 0xDE, 0xAD, 0xBE, 0xEF) // padding past tot

	tup, got, err := SplitUDPDatagram(padded)
	if err != nil {
		t.Fatalf("padded datagram rejected: %v", err)
	}
	if len(got) != len(payload) || string(got) != string(payload) {
		t.Fatalf("payload leaked into padding: got %d bytes %q", len(got), got)
	}
	if tup.DstPort != 51820 {
		t.Fatalf("tuple lost: %+v", tup)
	}
}
