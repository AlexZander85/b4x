// WG6 nested runtime tests (design §10 gool scenario). The E2E drives TWO
// REAL devices end to end: the inner WG instance dials loopback, the
// Backend-B forwarder carries it through the outer tunnel's netstack, and
// the OUTER fake edge (channel TUN) relays decrypted UDP toward the REAL
// inner fake edge socket — the production gool topology where the outer
// server forwards toward the inner edge.
//
// Addressing trap (WG6 planning decision): the forwarder's dial target
// MUST be non-loopback (TEST-NET here) or gVisor would deliver the packet
// locally to itself and it would never reach the outer TUN. Translating
// TEST-NET -> the inner edge's real 127.0.0.1:<port> is the harness' job.
//
// Race-gate naming: the device-lifecycle E2E deliberately do NOT match the
// race -run filter (device lifecycle trips the known upstream timers.go
// race); pure units keep the TestNestedWg prefix and stay race-covered.
package transportwg

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	twarp "github.com/daniellavrushin/b4/transport/warp"
)

// goolInnerTarget is the synthetic through-tunnel address of the inner edge
// (TEST-NET-2; never routed on the host, exactly why gVisor emits it into
// the TUN instead of looping it back locally).
var goolInnerTarget = netip.MustParseAddrPort("198.51.100.7:4500")

// ---- relay harness: outer-edge channel TUN <-> real inner-edge socket ----

// goolRelay reads DECRYPTED frames from the outer fake edge's channel TUN,
// answers the outer layer's own DNS probes (bootstrap + trust gate), and
// forwards anything addressed to the synthetic InnerEdge over a host UDP
// socket to the real inner fake edge. Replies travel back as crafted
// IP/UDP frames injected into the channel (checksums mandatory: gVisor
// drops zero-checksum datagrams).
type goolRelay struct {
	edge      *fakeEdge
	target    netip.AddrPort // synthetic InnerEdge (forwarder dial target)
	innerReal netip.AddrPort // real loopback socket of the inner fake edge
	relay     *net.UDPConn   // harness socket toward the inner edge

	mu        sync.Mutex
	silent    bool
	clientSrc netip.AddrPort // latest inner source (outer client, in-tunnel)
	stop      chan struct{}
}

func startGoolRelay(t *testing.T, outer *fakeEdge, target, innerReal netip.AddrPort) *goolRelay {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &goolRelay{
		edge:      outer,
		target:    target,
		innerReal: innerReal,
		relay:     pc.(*net.UDPConn),
		stop:      make(chan struct{}),
	}
	go g.pumpDownlink()
	go g.pumpUplink()
	t.Cleanup(func() {
		close(g.stop)
		_ = pc.Close()
	})
	return g
}

// SetSilent blackholes BOTH directions (DNS answers and inner relaying):
// the silent-DPI fixture for parent-loss scenarios.
func (g *goolRelay) SetSilent(v bool) {
	g.mu.Lock()
	g.silent = v
	g.mu.Unlock()
}

func (g *goolRelay) stopped() bool {
	select {
	case <-g.stop:
		return true
	default:
		return false
	}
}

func (g *goolRelay) pumpDownlink() {
	for {
		select {
		case <-g.stop:
			return
		case pkt := <-g.edge.tun.Inbound:
			g.routeDecrypted(pkt)
		}
	}
}

func (g *goolRelay) routeDecrypted(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	g.mu.Lock()
	silent := g.silent
	g.mu.Unlock()
	if silent {
		return // FULL blackhole: no relaying AND no DNS answers
	}
	payload, src, dst, ok := udpFrameParts(pkt)
	if ok && dst == g.target {
		g.mu.Lock()
		g.clientSrc = src
		g.mu.Unlock()
		if _, err := g.relay.WriteToUDP(payload, net.UDPAddrFromAddrPort(g.innerReal)); err != nil && !g.stopped() {
			// A dropped downlink datagram surfaces downstream as a missing
			// handshake/gate record; UDP loss needs no fatal handling here.
			_ = err
		}
		return
	}
	// The OUTER layer's own bootstrap/gate probes: answer like the real
	// edge would (otherwise the outer session can never prove itself).
	switch k := classifyInner(pkt); k.Kind {
	case "dns-boot", "dns-gate":
		reply := dnsReplyPacket(pkt)
		if reply == nil {
			return
		}
		select {
		case g.edge.tun.Outbound <- reply:
		default:
		}
	}
}

func (g *goolRelay) pumpUplink() {
	buf := make([]byte, 65535)
	for {
		n, _, err := g.relay.ReadFromUDP(buf)
		if err != nil {
			return // cleanup closed the socket
		}
		g.mu.Lock()
		client, silent := g.clientSrc, g.silent
		g.mu.Unlock()
		if silent || !client.IsValid() || n == 0 {
			continue
		}
		frame := udp4Frame(g.target, client, buf[:n])
		select {
		case g.edge.tun.Outbound <- frame:
		default:
		}
	}
}

// udpFrameParts splits a plaintext IPv4/UDP packet into payload and
// addressing.
func udpFrameParts(pkt []byte) (payload []byte, src, dst netip.AddrPort, ok bool) {
	if len(pkt) < 28 || pkt[9] != 17 {
		return nil, netip.AddrPort{}, netip.AddrPort{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return nil, netip.AddrPort{}, netip.AddrPort{}, false
	}
	u := pkt[ihl:]
	ulen := int(binary.BigEndian.Uint16(u[4:6]))
	plen := len(u) - 8
	if ulen >= 8 && ulen-8 < plen {
		plen = ulen - 8
	}
	src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(pkt[12:16])), binary.BigEndian.Uint16(u[0:2]))
	dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(pkt[16:20])), binary.BigEndian.Uint16(u[2:4]))
	return u[8 : 8+plen], src, dst, true
}

// udp4Frame crafts an IPv4/UDP packet with HONEST header and UDP
// checksums (pseudo-header included) — the same math dnsReplyPacket uses.
func udp4Frame(src, dst netip.AddrPort, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	pkt := make([]byte, total)
	ip := pkt[:20]
	s4 := src.Addr().As4()
	d4 := dst.Addr().As4()
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:], inetChecksum(ip))

	u := pkt[20:]
	binary.BigEndian.PutUint16(u[0:], src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], payload) // BEFORE the checksum: it must cover the real bytes
	binary.BigEndian.PutUint16(u[6:], 0)
	sum := uint32(17 + len(u))
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(s4[:])
	add(d4[:])
	add(u)
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(u[6:], ^uint16(sum))
	return pkt
}

func inetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// ---- fixtures ----

// buildGoolFixture wires two generic AWG-server-mode fake edges (NO reserved
// stamping anywhere — red lines §11.3/§11.4: identities are cf_warp=false;
// the outer junk family is an AGREED pair, satisfying §11.4) plus the
// validated nested config and the relay between them.
func buildGoolFixture(t *testing.T) (_ *goolRelay, innerEdge *fakeEdge, cfg NestedWgConfig, rec *sessionRecorder) {
	t.Helper()
	outerEdge, err := startFakeEdge(t, [3]byte{}, false /*require*/, false /*stamp*/, false /*scrub*/)
	if err != nil {
		t.Fatal(err)
	}
	innerEdge, err = startFakeEdge(t, [3]byte{}, false, false, false)
	if err != nil {
		t.Fatal(err)
	}

	oEdgePriv, _ := edgeKeyPair(t)
	iEdgePriv, _ := edgeKeyPair(t)
	oClient, iClient := mustKeyNow(), mustKeyNow()
	outerID, err := NewIdentity(oClient.B64(), oEdgePriv.Pub().B64(), "uS9/", "10.0.0.2", "", false)
	if err != nil {
		t.Fatal(err)
	}
	innerID, err := NewIdentity(iClient.B64(), iEdgePriv.Pub().B64(), "uS8/", "10.0.1.2", "", false)
	if err != nil {
		t.Fatal(err)
	}

	outerProf := Profile{JunkCount: 4, JunkMin: 40, JunkMax: 70} // obf ON for the outer layer (Validate hard rule)
	if err := outerEdge.ConfigureProfile(oEdgePriv, mustPub(t, oClient), netip.MustParseAddr("10.0.0.2"), outerProf); err != nil {
		t.Fatal(err)
	}
	if err := innerEdge.ConfigureProfile(iEdgePriv, mustPub(t, iClient), netip.MustParseAddr("10.0.1.2"), Profile{}); err != nil {
		t.Fatal(err)
	}
	innerEdge.StartResponder(ResponderNormal)

	cfg = NestedWgConfig{
		Outer:     NestedLayer{Ident: outerID, Profile: outerProf},
		Inner:     NestedLayer{Ident: innerID},
		OuterEdge: netip.MustParseAddrPort(outerEdge.addr()),
		InnerEdge: goolInnerTarget,
		InnerDial: netip.MustParseAddrPort("127.0.0.1:0"),
	}
	rec = &sessionRecorder{}
	relay := startGoolRelay(t, outerEdge, goolInnerTarget, innerEdge.addrPort())
	return relay, innerEdge, cfg, rec
}

// goolHealth shrinks CI windows. The outer rx-idle is FINITE (2s) so a
// silenced edge produces a real wg-stall-rx; keepOuterAlive() below keeps
// rx flowing while the test wants the layer healthy. The inner watchdog is
// set to hours so ONLY parent-loss invalidation can take the child down.
func goolHealth() func(*HealthConfig) {
	return func(hc *HealthConfig) {
		hc.HandshakeTimeout = 8 * time.Second
		hc.RestartBackoff = 200 * time.Millisecond
		hc.Gate = TrustGate{RoundTrips: 2, Gap: 30 * time.Millisecond, Window: 3 * time.Second}
		hc.Watchdog = WatchdogConfig{RXIdle: 2 * time.Second, Window: 5 * time.Second, Tick: 100 * time.Millisecond}
	}
}

func goolOptions(rec *sessionRecorder) NestedWgOptions {
	return NestedWgOptions{
		DNS:            netip.MustParseAddr("8.8.8.8"),
		MaxGenerations: 6,
		OuterHealth:    goolHealth(),
		InnerHealth: func(hc *HealthConfig) { // inner: quiet-forever posture
			goolHealth()(hc)
			hc.Watchdog.RXIdle = time.Hour
		},
		OnEvent: rec.onEvent,
	}
}

// keepOuterAlive continuously pushes REAL DNS probes through the OUTER
// tunnel's CURRENT generation so its rx-idle watchdog stays quiet while the
// test wants the layer healthy (the relay answers any genuine UDP/53
// query). It re-reads Tunnel() every tick because every outer generation
// owns a FRESH netstack.
func keepOuterAlive(rt *NestedWgRuntime, stop <-chan struct{}) {
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(300 * time.Millisecond):
			}
			tun := rt.outer.Tunnel()
			if tun == nil || tun.Netstack == nil {
				continue
			}
			probe, err := twarp.NewDNSProbe([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8}, "keepalive.test")
			if err != nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			conn, err := nsUDPDial(tun.Netstack)(ctx, "udp", "8.8.8.8:53")
			if err != nil {
				cancel()
				continue
			}
			_, _ = conn.Write(probe.Packet[28:])
			_ = conn.Close()
			cancel()
		}
	}()
}

// waitGoroutinesSettled asserts no goroutine leak after teardown.
func waitGoroutinesSettled(base, now int) bool {
	return now <= base+4
}

// countEvents counts recorder events by name.
func countEvents(rec *sessionRecorder, name string) int {
	n := 0
	for _, e := range rec.names() {
		if e == name {
			n++
		}
	}
	return n
}

// classEventLog keeps SessionEvent objects (names AND structural classes)
// for assertions that must key on the failure taxonomy (§8).
type classEventLog struct {
	mu  sync.Mutex
	evs []SessionEvent
}

func (l *classEventLog) add(ev SessionEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evs = append(l.evs, ev)
}

func (l *classEventLog) has(name string, class FailureClass) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ev := range l.evs {
		if ev.Name == name && ev.Class == class {
			return true
		}
	}
	return false
}

func (l *classEventLog) snapshot() []SessionEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]SessionEvent(nil), l.evs...)
}

// ---- tests ----

// TestGoolE2ENestedHandshakeThroughBothDevices: full nested handshake and
// inner trust-gate payload land INSIDE the inner edge — proof of transit
// through BOTH devices and the loopback carrier.
func TestGoolE2ENestedHandshakeThroughBothDevices(t *testing.T) {
	_, innerEdge, cfg, rec := buildGoolFixture(t)
	rt, err := NewNestedWgRuntime(cfg, goolOptions(rec))
	if err != nil {
		t.Fatal(err)
	}
	stopKeepalive := make(chan struct{})
	defer close(stopKeepalive)

	base := runtime.NumGoroutine()
	if err := rt.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Stop)
	keepOuterAlive(rt, stopKeepalive)

	if !waitFor(func() bool { return innerEdge.handshakeEstablished() }, 25*time.Second) {
		t.Fatalf("inner handshake never completed through both devices; events=%v lost=%+v",
			rec.names(), rec.lostList())
	}
	if !waitFor(func() bool {
		for _, r := range innerEdge.innerStats() {
			if r.Kind == "dns-gate" {
				return true
			}
		}
		return false
	}, 15*time.Second) {
		t.Fatalf("inner gate payload never reached the inner edge; stats=%+v", innerEdge.innerStats())
	}

	st := rt.Status()
	if st.Link != NestedUp || !st.ChildRunning || st.ParentGen < 1 {
		t.Fatalf("status=%+v want up/running/gen>=1", st)
	}
	if !waitFor(func() bool { return countEvents(rec, "wg_established") >= 2 }, 10*time.Second) {
		t.Fatalf("both layers never reached established: %d; events=%v",
			countEvents(rec, "wg_established"), rec.names())
	}

	rt.Stop()
	if !waitFor(func() bool { return waitGoroutinesSettled(base, runtime.NumGoroutine()) }, 5*time.Second) {
		t.Fatalf("goroutine leak after stop: base=%d now=%d", base, runtime.NumGoroutine())
	}
	if st := rt.Status(); st.Link != NestedChildInvalidated {
		t.Fatalf("post-stop link=%s want child-invalidated", st.Link)
	}
}

// TestGoolE2EParentLossInvalidatesChildThenRecovers: silencing the OUTER
// edge stops the relay's DNS answers, the outer session's rx goes idle, and
// its own watchdog fires wg-stall-rx; the runtime invalidates the child
// IMMEDIATELY (the inner layer's own watchdog is set to HOURS, so the
// transition provably comes from the bridge, not from the child dying of
// natural causes). Healing revalidates against the new parent generation
// with a FRESH forwarder (fresh netstack of the fresh generation).
func TestGoolE2EParentLossInvalidatesChildThenRecovers(t *testing.T) {
	relay, innerEdge, cfg, rec := buildGoolFixture(t)
	log := &classEventLog{}
	opt := goolOptions(rec)
	baseOnEvent := opt.OnEvent
	opt.OnEvent = func(ev SessionEvent) {
		log.add(ev)
		baseOnEvent(ev)
	}
	rt, err := NewNestedWgRuntime(cfg, opt)
	if err != nil {
		t.Fatal(err)
	}
	stopKeepalive := make(chan struct{})
	defer close(stopKeepalive)

	base := runtime.NumGoroutine()
	if err := rt.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Stop)
	keepOuterAlive(rt, stopKeepalive)

	if !waitFor(func() bool { return innerEdge.handshakeEstablished() }, 25*time.Second) {
		t.Fatalf("initial inner handshake never completed; events=%v lost=%+v",
			rec.names(), rec.lostList())
	}
	// Wait until BOTH layers are fully established BEFORE silencing: the
	// loss scenario must kill a healthy settled pair, not race the child's
	// own trust gate.
	if !waitFor(func() bool { return countEvents(rec, "wg_established") >= 2 }, 15*time.Second) {
		t.Fatalf("pair never fully established before the loss scenario; events=%v", rec.names())
	}
	gen1 := rt.Status().ParentGen
	if gen1 == 0 {
		t.Fatalf("parent generation not counted: %+v", rt.Status())
	}

	relay.SetSilent(true)

	// Parent loss classified structurally: the runtime surfaces the parent's
	// failure as wg_nested_parent_lost carrying the structural class.
	if !waitFor(func() bool { return log.has("wg_nested_parent_lost", ClassStallRX) }, 15*time.Second) {
		t.Fatalf("parent loss never fired with wg-stall-rx; events=%+v", log.snapshot())
	}
	if !waitFor(func() bool { return rt.Status().Link == NestedChildInvalidated }, 3*time.Second) {
		t.Fatalf("child not invalidated promptly; status=%+v events=%v", rt.Status(), rec.names())
	}
	if st := rt.Status(); st.ChildRunning {
		t.Fatalf("child still running after invalidation: %+v", st)
	}

	relay.SetSilent(false)
	if !waitFor(func() bool {
		st := rt.Status()
		return st.ParentGen > gen1 && st.Link == NestedUp && st.ChildRunning
	}, 30*time.Second) {
		t.Fatalf("no revalidation after heal; status=%+v events=%v", rt.Status(), rec.names())
	}
	if !waitFor(func() bool { return countEvents(rec, "wg_established") >= 4 }, 20*time.Second) {
		t.Fatalf("layers did not re-establish: %d; events=%v",
			countEvents(rec, "wg_established"), rec.names())
	}

	rt.Stop()
	if !waitFor(func() bool { return waitGoroutinesSettled(base, runtime.NumGoroutine()) }, 5*time.Second) {
		t.Fatalf("goroutine leak: base=%d now=%d", base, runtime.NumGoroutine())
	}
}

// TestNestedWgRuntimeRejectsInvalidConfig: the constructor passes every
// Validate rule through unchanged (pure unit; matches the race -run filter
// via the TestNestedWg prefix).
func TestNestedWgRuntimeRejectsInvalidConfig(t *testing.T) {
	outerID, innerID := nestedIdents(t)

	cases := []struct {
		name string
		mut  func(*NestedWgConfig)
		want error
	}{
		{"identical-identity", func(c *NestedWgConfig) { c.Outer.Ident, c.Inner.Ident = outerID, outerID }, ErrNestedIdenticalIdentity},
		{"same-public-edge", func(c *NestedWgConfig) { c.InnerEdge = netip.MustParseAddrPort("162.159.193.5:9999") }, ErrNestedSameEdge},
		{"non-loopback-inner-dial", func(c *NestedWgConfig) { c.InnerDial = netip.MustParseAddrPort("192.0.2.1:500") }, ErrInnerNotLoopback},
		{"flat-mtu", func(c *NestedWgConfig) { c.Inner.MTU = 1280 }, ErrNestedMTUGradient},
		{"vanilla-outer", func(c *NestedWgConfig) { c.Outer.Profile = Profile{} }, ErrOuterObfRequired},
		{"ka-collision", func(c *NestedWgConfig) { c.Inner.KeepaliveSec = NestedOuterKeepaliveSec }, ErrKeepaliveCollision},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validNestedWg()
			c.Outer.Ident, c.Inner.Ident = outerID, innerID
			tc.mut(c)
			if _, err := NewNestedWgRuntime(*c, NestedWgOptions{}); !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
		})
	}

	t.Run("happy-pre-start-status", func(t *testing.T) {
		c := validNestedWg()
		c.Outer.Ident, c.Inner.Ident = outerID, innerID
		rt, err := NewNestedWgRuntime(*c, NestedWgOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if st := rt.Status(); st.Link != NestedWaitingParent || st.ParentGen != 0 || st.ChildRunning {
			t.Fatalf("pre-start status=%+v", st)
		}
	})
}
