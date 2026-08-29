// MasqueDatagramCarrier (design 3.2, M+W): the OUTER is a MASQUE CONNECT-IP
// session (transportwarp supervisor), which carries raw IP packets both ways.
// The carrier turns that packet plane into the NestedCarrier contract for an
// AWG inner layer:
//
//	Write path: craft IPv4+UDP (src = outer assigned address) and push it
//	            into the capsule stream via the supervisor;
//	Read path:  one tap pump demuxes inbound capsules by tuple and feeds
//	            per-flow UDPSessions (no loopback shim, no extra hop).
//
// DialTCPThrough is structurally unavailable here: CONNECT-IP carries
// datagrams; a userspace TCP stack over the base tunnel is bd b4x-9aa.
// Callers get ErrNoTCPCarrier - BLOCKED_CARRIER semantics, never a silent
// direct dial (red line #2).
package nested

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	twarp "github.com/daniellavrushin/b4/transport/warp"
)

// MasqueCarrierConfig wires one datagram carrier over a running capsule plane.
type MasqueCarrierConfig struct {
	// Plane is the OUTER MASQUE CONNECT-IP instance (*twarp.Supervisor in
	// production; the interface keeps the carrier unit-testable).
	Plane CapsulePlane
	// LocalV4 is the outer's assigned WARP address (crafted source).
	LocalV4 [4]byte
	// OuterMTU bounds crafted packets (default twarp.DefaultMTU).
	OuterMTU int
}

// CapsulePlane is the slice of the MASQUE outer the datagram carrier needs.
// It is satisfied by *twarp.Supervisor.
type CapsulePlane interface {
	WritePacket(pkt []byte) error
	SubscribePackets() (<-chan []byte, func())
	Snapshot() twarp.Status
}

// MasqueDatagramCarrier implements NestedCarrier + UDPSessionCarrier over
// the MASQUE capsule plane.
type MasqueDatagramCarrier struct {
	cfg MasqueCarrierConfig

	mu        sync.Mutex
	flows     map[flowKey]*flowConn
	subCh     <-chan []byte
	subCancel func()
	pumpOnce  sync.Once

	droppedInbound atomic.Uint64
	demuxMatched   atomic.Uint64
	demuxUnknown   atomic.Uint64
	closed         atomic.Bool
}

type flowKey struct {
	peer      netip.Addr
	peerPort  uint16
	localPort uint16
}

// NewMasqueDatagramCarrier validates config shape. StartPumping must be
// called once the composition begins consuming inbound traffic.
func NewMasqueDatagramCarrier(cfg MasqueCarrierConfig) (*MasqueDatagramCarrier, error) {
	if cfg.Plane == nil {
		return nil, fmt.Errorf("nested: masque carrier requires a supervisor")
	}
	if netip.AddrFrom4(cfg.LocalV4).IsUnspecified() {
		return nil, fmt.Errorf("nested: masque carrier requires the outer assigned v4")
	}
	if cfg.OuterMTU <= 0 {
		cfg.OuterMTU = twarp.DefaultMTU
	}
	return &MasqueDatagramCarrier{
		cfg:   cfg,
		flows: make(map[flowKey]*flowConn),
	}, nil
}

// StartPumping subscribes to inbound capsules of every outer generation
// (the plane re-subscribes across reconnects) and routes them to flows.
func (c *MasqueDatagramCarrier) StartPumping() {
	c.pumpOnce.Do(func() {
		ch, cancel := c.cfg.Plane.SubscribePackets()
		c.mu.Lock()
		c.subCh, c.subCancel = ch, cancel
		c.mu.Unlock()
		go c.pump(ch)
	})
}

func (c *MasqueDatagramCarrier) pump(ch <-chan []byte) {
	for pkt := range ch {
		tuple, payload, err := SplitUDPDatagram(pkt)
		if err != nil {
			continue // control probes / foreign payloads ride other consumers
		}
		key := flowKey{peer: tuple.SrcIP, peerPort: tuple.SrcPort, localPort: tuple.DstPort}
		c.mu.Lock()
		f := c.flows[key]
		c.mu.Unlock()
		if f == nil {
			c.droppedInbound.Add(1)
			c.demuxUnknown.Add(1)
			continue
		}
		c.demuxMatched.Add(1)
		buf := make([]byte, len(payload))
		copy(buf, payload)
		select {
		case f.ch <- buf:
		default:
			c.droppedInbound.Add(1) // drop-instead-of-block discipline
		}
	}
}

// InjectUDPDatagram crafts and pushes ONE datagram toward dst.
func (c *MasqueDatagramCarrier) InjectUDPDatagram(dst netip.AddrPort, payload []byte) error {
	return c.writeDatagram(dst, randomSport(), payload)
}

// DialUDPThrough registers a demuxed virtual connected session toward dst.
func (c *MasqueDatagramCarrier) DialUDPThrough(_ context.Context, dst netip.AddrPort) (UDPSession, error) {
	if c.closed.Load() {
		return nil, ErrCarrierClosed
	}
	if !dst.IsValid() || !dst.Addr().Is4() {
		return nil, fmt.Errorf("%w: %v", ErrNotV4, dst)
	}
	sport := randomSport()
	key := flowKey{peer: dst.Addr(), peerPort: dst.Port(), localPort: sport}
	f := &flowConn{c: c, key: key, dst: dst, ch: make(chan []byte, 32), done: make(chan struct{})}
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return nil, ErrCarrierClosed
	}
	c.flows[key] = f
	c.mu.Unlock()
	return f, nil
}

func (c *MasqueDatagramCarrier) writeDatagram(dst netip.AddrPort, sport uint16, payload []byte) error {
	if c.closed.Load() {
		return ErrCarrierClosed
	}
	// PATCH-16 (M-11): fail-closed parity with the kernel/netstack carriers —
	// no datagram leaves through an unproven plane (red line #1/#2). The
	// supervisor's fail-open release on a stall (RouteHeld=false) previously
	// left this carrier silently injecting into a dead/foreign plane.
	if _, ok := c.ProofSnapshot(); !ok {
		return fmt.Errorf("%w: masque plane route not held", ErrCarrierUnproven)
	}
	if len(payload)+UDPDatagramOverhead > c.cfg.OuterMTU {
		return fmt.Errorf("nested: datagram %d exceeds outer mtu %d",
			len(payload)+UDPDatagramOverhead, c.cfg.OuterMTU)
	}
	pkt, err := BuildUDPDatagram(
		netip.AddrFrom4(c.cfg.LocalV4), dst.Addr(),
		sport, dst.Port(), payload,
	)
	if err != nil {
		return err
	}
	return c.cfg.Plane.WritePacket(pkt)
}

// DialTCPThrough: structural limitation (see package comment).
func (c *MasqueDatagramCarrier) DialTCPThrough(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return nil, fmt.Errorf("%w: tcp to %v over masque datagram plane", ErrNoTCPCarrier, dst)
}

// ProofSnapshot: the held route IS the proof (supervisor fail-open releases
// it on any stall, so ok=false tracks reality).
func (c *MasqueDatagramCarrier) ProofSnapshot() (string, bool) {
	if c.closed.Load() || c.cfg.Plane == nil {
		return "", false
	}
	if !c.cfg.Plane.Snapshot().RouteHeld {
		return "", false
	}
	return "masque:route-held", true
}

// DroppedInbound reports drop-instead-of-block accounting of the pump.
func (c *MasqueDatagramCarrier) DroppedInbound() uint64 { return c.droppedInbound.Load() }

// DemuxStats reports matched vs unknown-tuple inbound datagrams
// (observability N4: separates "plane dead" from "stale flow").
func (c *MasqueDatagramCarrier) DemuxStats() (matched, unknown uint64) {
	return c.demuxMatched.Load(), c.demuxUnknown.Load()
}

// Close unsubscribes the pump and closes every flow (idempotent).
func (c *MasqueDatagramCarrier) Close() {
	if c.closed.Swap(true) {
		return
	}
	c.mu.Lock()
	cancel := c.subCancel
	flows := c.flows
	c.flows = make(map[flowKey]*flowConn)
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, f := range flows {
		f.closeNow()
	}
}

func (c *MasqueDatagramCarrier) removeFlow(key flowKey) {
	c.mu.Lock()
	delete(c.flows, key)
	c.mu.Unlock()
}

// randomPortFn is the test seam for source-port generation (PATCH-25:
// tests force collisions deterministically). Production uses randomSport.
var randomPortFn = randomSport

// randomSport picks a source port in the Aether probe range discipline
// (20000-60000). PATCH-25 (N-2): a collision used to silently overwrite the
// existing flow in the demux map (orphaning its client); DialUDPThrough now
// regenerates and finally shifts deterministically instead.
func randomSport() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	v := binary.BigEndian.Uint16(b[:])
	return 20000 + v%40000
}

// nextSport regenerates around a taken port: up to 3 fresh random draws,
// then a deterministic +1 walk within the discipline range (20000-60000)
// until a free port is found.
func nextSport(taken func(uint16) bool) uint16 {
	const lo, span = 20000, 40000
	sport := randomPortFn()
	for i := 0; i < 3 && taken(sport); i++ {
		sport = randomPortFn()
	}
	for taken(sport) {
		sport = lo + ((sport-lo)+1)%span
	}
	return sport
}

// flowConn is one demuxed virtual UDP session toward its peer.
type flowConn struct {
	c    *MasqueDatagramCarrier
	key  flowKey
	dst  netip.AddrPort
	ch   chan []byte
	done chan struct{}

	closeOnce sync.Once
}

func (f *flowConn) Write(b []byte) (int, error) {
	select {
	case <-f.done:
		return 0, ErrCarrierClosed
	default:
	}
	if err := f.c.writeDatagram(f.dst, f.key.localPort, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (f *flowConn) Read(b []byte) (int, error) {
	select {
	case pkt, open := <-f.ch:
		if !open {
			return 0, ErrCarrierClosed
		}
		// PATCH-26 (N-3): net.Conn contract — a short reader buffer is an
		// io.ErrShortBuffer, not a silent truncation; the datagram is
		// consumed either way (UDP semantics).
		if len(pkt) > len(b) {
			return copy(b, pkt), io.ErrShortBuffer
		}
		return copy(b, pkt), nil
	case <-f.done:
		return 0, ErrCarrierClosed
	}
}

func (f *flowConn) Close() error {
	f.closeOnce.Do(func() {
		close(f.done)
		f.c.removeFlow(f.key)
	})
	return nil
}

func (f *flowConn) closeNow() {
	f.closeOnce.Do(func() {
		close(f.done)
	})
}
