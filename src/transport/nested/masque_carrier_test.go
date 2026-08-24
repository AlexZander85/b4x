package nested

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	twarp "github.com/daniellavrushin/b4/transport/warp"
)

// fakePlane is an in-memory CapsulePlane: tests inject inbound capsules and
// observe outbound crafted packets without any MASQUE server.
type fakePlane struct {
	mu        sync.Mutex
	outbound  [][]byte
	routeHeld bool
	subs      map[chan []byte]struct{}
}

func newFakePlane() *fakePlane {
	return &fakePlane{subs: map[chan []byte]struct{}{}}
}

func (f *fakePlane) WritePacket(pkt []byte) error {
	f.mu.Lock()
	f.outbound = append(f.outbound, append([]byte(nil), pkt...))
	f.mu.Unlock()
	return nil
}

func (f *fakePlane) SubscribePackets() (<-chan []byte, func()) {
	ch := make(chan []byte, 64)
	f.mu.Lock()
	f.subs[ch] = struct{}{}
	f.mu.Unlock()
	cancel := func() {
		f.mu.Lock()
		if _, ok := f.subs[ch]; ok {
			delete(f.subs, ch)
			close(ch)
		}
		f.mu.Unlock()
	}
	return ch, cancel
}

func (f *fakePlane) Snapshot() twarp.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return twarp.Status{RouteHeld: f.routeHeld}
}

func (f *fakePlane) emit(pkt []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.subs {
		select {
		case ch <- pkt:
		default:
		}
	}
}

func (f *fakePlane) sent() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.outbound...)
}

func localV4() [4]byte { return [4]byte{198, 51, 100, 7} }

func TestMasqueCarrierCraftsOutboundDatagram(t *testing.T) {
	fp := newFakePlane()
	c, err := NewMasqueDatagramCarrier(MasqueCarrierConfig{Plane: fp, LocalV4: localV4()})
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 9}), 51820)

	if err := c.InjectUDPDatagram(dst, []byte("init")); err != nil {
		t.Fatalf("inject: %v", err)
	}
	sent := fp.sent()
	if len(sent) != 1 {
		t.Fatalf("outbound packets = %d, want 1", len(sent))
	}
	tuple, payload, err := SplitUDPDatagram(sent[0])
	if err != nil {
		t.Fatalf("crafted packet malformed: %v", err)
	}
	if tuple.SrcIP != netip.AddrFrom4(localV4()) || tuple.DstIP != dst.Addr() ||
		tuple.DstPort != dst.Port() {
		t.Fatalf("tuple = %+v, want src=%v dst=%v", tuple, localV4(), dst)
	}
	if string(payload) != "init" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestMasqueCarrierRejectsOversize(t *testing.T) {
	fp := newFakePlane()
	c, err := NewMasqueDatagramCarrier(MasqueCarrierConfig{
		Plane: fp, LocalV4: localV4(), OuterMTU: 1280,
	})
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	big := make([]byte, 1280) // > MTU-28
	if err := c.InjectUDPDatagram(netip.MustParseAddrPort("203.0.113.9:51820"), big); err == nil {
		t.Fatal("oversize datagram accepted")
	}
}

func TestMasqueCarrierDemuxRoutesRepliesToFlow(t *testing.T) {
	fp := newFakePlane()
	c, err := NewMasqueDatagramCarrier(MasqueCarrierConfig{Plane: fp, LocalV4: localV4()})
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	c.StartPumping()

	peer := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 9}), 51820)
	sess, err := c.DialUDPThrough(context.Background(), peer)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// Client write must surface as a crafted packet with the flow's sport.
	if _, err := sess.Write([]byte("ping")); err != nil {
		t.Fatalf("flow write: %v", err)
	}
	sent := fp.sent()
	if len(sent) != 1 {
		t.Fatalf("outbound = %d, want 1", len(sent))
	}
	tuple, gotPayload, _ := SplitUDPDatagram(sent[0])
	if string(gotPayload) != "ping" {
		t.Fatalf("payload = %q", gotPayload)
	}

	// Inbound reply with the reversed tuple must land in the SAME session.
	reply, err := BuildUDPDatagram(peer.Addr(), netip.AddrFrom4(localV4()),
		peer.Port(), tuple.SrcPort, []byte("pong"))
	if err != nil {
		t.Fatalf("build reply: %v", err)
	}
	fp.emit(reply)

	type readRes struct {
		data string
		err  error
	}
	resC := make(chan readRes, 1)
	go func() {
		buf := make([]byte, 128)
		n, rerr := sess.Read(buf)
		if rerr != nil {
			resC <- readRes{err: rerr}
			return
		}
		resC <- readRes{data: string(buf[:n])}
	}()
	select {
	case res := <-resC:
		if res.err != nil {
			t.Fatalf("flow read: %v", res.err)
		}
		if res.data != "pong" {
			t.Fatalf("read payload = %q, want pong", res.data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reply never reached the demuxed session")
	}
}

func TestMasqueCarrierForeignPacketsDoNotBlockPump(t *testing.T) {
	fp := newFakePlane()
	c, err := NewMasqueDatagramCarrier(MasqueCarrierConfig{Plane: fp, LocalV4: localV4()})
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	c.StartPumping()
	// No flows registered: everything drops (counted), pump stays alive.
	fp.emit([]byte{0x45, 0x00, 0x00, 0x14}) // truncated garbage
	fp.emit([]byte("short"))
	if c.DroppedInbound() < 2 {
		time.Sleep(50 * time.Millisecond)
	}
	// Pump goroutine must still be alive for later flows.
	sess, err := c.DialUDPThrough(context.Background(),
		netip.MustParseAddrPort("203.0.113.9:53"))
	if err != nil {
		t.Fatalf("dial after garbage: %v", err)
	}
	_ = sess.Close()
}

func TestMasqueCarrierProofTracksRoute(t *testing.T) {
	fp := newFakePlane()
	c, err := NewMasqueDatagramCarrier(MasqueCarrierConfig{Plane: fp, LocalV4: localV4()})
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	if _, ok := c.ProofSnapshot(); ok {
		t.Fatal("proof must be false while route not held")
	}
	fp.mu.Lock()
	fp.routeHeld = true
	fp.mu.Unlock()
	if p, ok := c.ProofSnapshot(); !ok || p != "masque:route-held" {
		t.Fatalf("proof = %q ok=%v", p, ok)
	}
}

func TestMasqueCarrierTCPStructurallyBlocked(t *testing.T) {
	fp := newFakePlane()
	c, _ := NewMasqueDatagramCarrier(MasqueCarrierConfig{Plane: fp, LocalV4: localV4()})
	if _, err := c.DialTCPThrough(context.Background(),
		netip.MustParseAddrPort("162.159.198.1:443")); !errors.Is(err, ErrNoTCPCarrier) {
		t.Fatalf("tcp dial over datagram plane err = %v, want ErrNoTCPCarrier", err)
	}
}

var _ UDPSession = (*flowConn)(nil)
