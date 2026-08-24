package transportwg

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	twarp "github.com/daniellavrushin/b4/transport/warp"
)

// swapAndQR builds the wire-level reply: reversed addresses, recomputed IPv4
// checksum, swapped UDP ports (answer from :53), QR=1 on the DNS payload.
func swapAndQR(query []byte) []byte {
	if len(query) < 40 || query[0]>>4 != 4 || query[9] != 17 {
		return nil
	}
	out := append([]byte(nil), query...)
	copy(out[12:16], query[16:20])
	copy(out[16:20], query[12:16])
	out[10], out[11] = 0, 0 // clear checksum before recompute
	binary.BigEndian.PutUint16(out[10:], ipv4Checksum(out[:20]))

	ihl := int(query[0]&0x0f) * 4
	u := out[ihl:]
	u[0], u[1], u[2], u[3] = u[2], u[3], u[0], u[1] // swap ports
	binary.BigEndian.PutUint16(u[6:], 0)            // UDP checksum 0 is legal on IPv4

	dns := u[8:]
	dns[2] |= 0x80 // QR=1
	return out
}

func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr)-1; i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// stubRT is a scripted DNSRoundTripper for gate unit tests.
type stubRT struct {
	respond func(query []byte) ([]byte, error)
	sends   int
	gaps    []time.Time
}

func (s *stubRT) Exchange(ctx context.Context, probe twarp.Probe, timeout time.Duration) ([]byte, error) {
	s.sends++
	if len(s.gaps) > 0 || s.sends > 1 {
		// record arrival time of every exchange beyond the first
	}
	s.gaps = append(s.gaps, time.Now())
	return s.respond(probe.Packet[28:])
}

// dnsReply crafts a minimal QR=1 reply carrying the query's txid.
func dnsReply(query []byte) []byte {
	r := append([]byte(nil), query[:12]...)
	r[2] = 0x80 // QR=1
	r[3] = 0x80 // RA
	r = append(r, query[12:]...)
	r = append(r,
		0xc0, 0x0c, // name pointer
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x3c, // ttl 60
		0x00, 0x04, // rdlength 4
		104, 16, 32, 254, // 104.16.32.254
	)
	return r
}

func TestTrustGateHappyPath(t *testing.T) {
	rt := &stubRT{respond: func(q []byte) ([]byte, error) { return dnsReply(q), nil }}
	g := TrustGate{
		LocalV4:    [4]byte{172, 16, 0, 2},
		RoundTrips: 2,
		Gap:        30 * time.Millisecond,
		Window:     2 * time.Second,
	}
	if err := g.Verify(context.Background(), rt); err != nil {
		t.Fatalf("gate verify: %v", err)
	}
	if rt.sends != 2 {
		t.Fatalf("sends=%d want 2", rt.sends)
	}
}

func TestTrustGateSilentDropClassifiedAsStallRX(t *testing.T) {
	rt := &stubRT{respond: func([]byte) ([]byte, error) { return nil, errGateTimeout }}
	g := TrustGate{LocalV4: [4]byte{172, 16, 0, 2}, Gap: time.Millisecond, Window: 150 * time.Millisecond}
	err := g.Verify(context.Background(), rt)
	if !IsClass(err, ClassStallRX) {
		t.Fatalf("err=%v want wg-stall-rx", err)
	}
	var f *Failure
	if !errors.As(err, &f) || f.Reason == "" {
		t.Fatalf("failure lacks structured reason: %v", err)
	}
}

func TestTrustGateMismatchedReplyRejected(t *testing.T) {
	rt := &stubRT{respond: func(q []byte) ([]byte, error) {
		rep := dnsReply(q)
		rep[0] ^= 0xff // wrong txid
		return rep, nil
	}}
	g := TrustGate{LocalV4: [4]byte{172, 16, 0, 2}, Window: 300 * time.Millisecond}
	err := g.Verify(context.Background(), rt)
	if !IsClass(err, ClassStallRX) {
		t.Fatalf("mismatched reply must be wg-stall-rx, got %v", err)
	}
}

func TestTrustGateGapBetweenRoundTrips(t *testing.T) {
	var stamps []time.Time
	rt := &stubRT{respond: func(q []byte) ([]byte, error) {
		stamps = append(stamps, time.Now())
		return dnsReply(q), nil
	}}
	const gap = 120 * time.Millisecond
	g := TrustGate{LocalV4: [4]byte{172, 16, 0, 2}, Gap: gap, Window: 2 * time.Second}
	if err := g.Verify(context.Background(), rt); err != nil {
		t.Fatal(err)
	}
	if len(stamps) != 2 {
		t.Fatalf("stamps=%d", len(stamps))
	}
	if d := stamps[1].Sub(stamps[0]); d < gap-10*time.Millisecond {
		t.Fatalf("gap not respected: %v", d)
	}
}

func TestTrustGateE2EProbeSlotRunsAfterDNS(t *testing.T) {
	order := 0
	dnsOrder, probeOrder := -1, -1
	rt := &stubRT{respond: func(q []byte) ([]byte, error) {
		dnsOrder = order
		order++
		return dnsReply(q), nil
	}}
	g := TrustGate{
		LocalV4: [4]byte{172, 16, 0, 2},
		Gap:     time.Millisecond,
		E2EProbe: func(context.Context) error {
			probeOrder = order
			order++
			return nil
		},
	}
	if err := g.Verify(context.Background(), rt); err != nil {
		t.Fatal(err)
	}
	if dnsOrder >= probeOrder {
		t.Fatalf("probe must run after DNS gate: dns=%d probe=%d", dnsOrder, probeOrder)
	}
}

// loopbackTUN is a minimal tun.Device where every written packet is answered
// by the swapAndQR peer logic — no channels, no races.
type loopbackTUN struct {
	mu      sync.Mutex
	written [][]byte
	replies chan []byte
}

func newLoopbackTUN() *loopbackTUN {
	return &loopbackTUN{replies: make(chan []byte, 64)}
}

func (t *loopbackTUN) File() *os.File           { return nil }
func (t *loopbackTUN) MTU() (int, error)        { return DefaultMTU, nil }
func (t *loopbackTUN) Name() (string, error)    { return "lo0", nil }
func (t *loopbackTUN) Events() <-chan tun.Event { return nil }
func (t *loopbackTUN) Close() error             { return nil }
func (t *loopbackTUN) BatchSize() int           { return 1 }

func (t *loopbackTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt := <-t.replies
	n := copy(bufs[0][offset:], pkt)
	sizes[0] = n
	return 1, nil
}

func (t *loopbackTUN) inject(pkt []byte) error {
	cp := append([]byte(nil), pkt...)
	t.mu.Lock()
	t.written = append(t.written, cp)
	t.mu.Unlock()
	if reply := swapAndQR(cp); reply != nil {
		t.replies <- reply
	}
	return nil
}

func (t *loopbackTUN) Write(bufs [][]byte, offset int) (int, error) {
	pkt := append([]byte(nil), bufs[0][offset:]...)
	_ = t.inject(pkt)
	return len(bufs), nil
}

func TestRawTUNRoundTripperExchange(t *testing.T) {
	lb := newLoopbackTUN()
	rt := &RawTUNRoundTripper{
		Inject: lb.inject,
		Capture: func(ctx context.Context) ([]byte, error) {
			select {
			case pkt := <-lb.replies:
				return pkt, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}

	probe, err := twarp.NewDNSProbe([4]byte{172, 16, 0, 2}, [4]byte{8, 8, 8, 8}, "cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reply, err := rt.Exchange(ctx, *probe, 2500*time.Millisecond)
	if err != nil {
		lb.mu.Lock()
		t.Fatalf("exchange: %v (written=%d first=% x)", err, len(lb.written), lb.written)
	}
	if !validGateReply(reply, probe.TXID) {
		t.Fatalf("reply failed validation")
	}
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if len(lb.written) != 1 {
		t.Fatalf("written=%d want exactly the one probe", len(lb.written))
	}
}

type logWriter struct{ t *testing.T }

func (l logWriter) Printf(format string, args ...any) { l.t.Logf(format, args...) }
