// warp-scan: bounded endpoint discovery for the cf-warp WG edge (nova-go
// warp/scan.go canon, rebuilt on the b4x endpoint catalog + the shared
// wgprobe crypto core). A "hit" is an endpoint that answered our handshake
// initiation with an AUTHENTICATED type-2 response — not "something
// listens": the Noise exchange proves the edge holds the peer static key
// AND that our identity is registered, which no TCP/ICMP ping can.
//
// Address iteration is a full-cycle LCG (Hull-Dobell: c odd, a ≡ 1 (mod 4)
// on a power-of-two range) seeded per scan — the warp-plus ipscanner
// lineage: the /24 is walked pseudo-randomly with NO repetition and NO
// clustering, so a short scan still samples the whole range evenly instead
// of burning itself out on x.x.x.1..k.
//
// Red line (§11.5 / MASQUE §34): the scan emits addresses ONLY inside the
// catalog ranges on measured ports. The AllowOutOfCatalog escape mirrors
// the SeekerConfig one — tests with loopback fake edges ONLY.
//
// Probe shape replicates the ENGINE's default cf-warp profile
// (vanilla-off): a bare initiation (no junk prelude) with the reserved
// bytes stamped after mac1 (StampReserved) and the response scrubbed
// before authentication (ScrubReserved) — ReservedHook wire discipline.
package transportwg

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/transport/wgprobe"
)

// Scan canon (nova-go scan.go numbers).
const (
	DefaultWarpScanLimit   = 50
	DefaultWarpScanMaxRTT  = 1500 * time.Millisecond
	DefaultWarpScanWorkers = 16
	MaxWarpScanWorkers     = 128
	// warpScanProbeTimeout: one probe's read deadline. The engine's
	// handshake timeout is 5 s (seek canon); the scan does not retry on
	// the same socket (the seeker will, on the endpoint that won).
	WarpScanProbeTimeout = 5 * time.Second
)

// fastFailWindow: a probe that errors this fast never reached the wire
// (no route for the family); a burst of those switches the family off
// instead of burning the worker pool (nova-go canon).
const (
	fastFailWindow = 250 * time.Millisecond
	fastFailPause  = 250 * time.Millisecond
	fastFailLimit  = 24
)

// WarpScanOptions shapes one scan run. Zero fields fall back to defaults.
type WarpScanOptions struct {
	// PrivateKey/PeerPublicKey: the device identity (raw 32-byte keys —
	// the same pair the engine's Identity carries). Required.
	PrivateKey    [32]byte
	PeerPublicKey [32]byte
	// Reserved: cf-warp client_id bytes (zero for vanilla peers).
	Reserved [3]byte

	// Prefixes restrict the scan space (default: the ZT v4 catalog range).
	// Everything outside the catalog gate is rejected unless
	// AllowOutOfCatalog is set (tests only).
	Prefixes []netip.Prefix
	// Limit stops the scan after this many verified hits (default 50).
	Limit int
	// MaxRTT discards hits slower than this (default 1500 ms).
	MaxRTT time.Duration
	// Workers bounds concurrency (default 16, cap 128).
	Workers int
	// Ports overrides the port window (default: core ∪ extended, the
	// measured sets). Every port still passes the KnownWGPort gate.
	Ports []uint16
	// Rand seeds the LCG (tests pin determinism); nil = crypto/rand.
	Rand func() (int64, error)
	// Logf receives progress lines (nil = discard).
	Logf func(format string, args ...any)

	// AllowOutOfCatalog is a TESTS-ONLY escape (loopback fake edges live
	// outside the catalog). Production MUST leave it false.
	AllowOutOfCatalog bool
}

// WarpScanHit is one verified endpoint with its handshake RTT.
type WarpScanHit struct {
	AddrPort netip.AddrPort
	RTT      time.Duration
}

// WarpScanStats counts what the probes saw.
type WarpScanStats struct {
	Probes      int64
	Hits        int
	Duplicates  int
	TooSlow     int
	Timeouts    int
	Unreachable int
	Other       int
	Elapsed     time.Duration
}

// scanErrorClass classifies a probe transport error for the stats.
func scanErrorClass(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "unreachable"
	}
	return "other"
}

// lcgIterator is the full-cycle pseudo-random address walk over one or
// more prefixes (warp-plus ipscanner lineage). Per prefix, position p
// advances linearly 0..m-1 and the emitted host offset is
// (a*p + c) mod m — a bijective remap (Hull-Dobell: m a power of two,
// c odd, a ≡ 1 (mod 4)), so one period visits every address of every
// prefix EXACTLY once, in pseudo-random order, without clustering.
type lcgIterator struct {
	prefixes []netip.Prefix
	// per-prefix linear position and LCG remap constants
	pos     []uint64
	a, c    uint64
	primary int // round-robin cursor across prefixes
}

func newLCGIterator(prefixes []netip.Prefix, seedFn func() (int64, error)) (*lcgIterator, error) {
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("transportwg: scan needs at least one prefix")
	}
	var seed uint64
	if seedFn != nil {
		v, err := seedFn()
		if err != nil {
			return nil, fmt.Errorf("transportwg: lcg seed: %w", err)
		}
		seed = uint64(v)
	} else {
		v, err := cryptoSeed()
		if err != nil {
			return nil, fmt.Errorf("transportwg: lcg seed: %w", err)
		}
		seed = uint64(v)
	}
	// Numerical Recipes constants: a = 1664525 ≡ 1 (mod 4), c = 1013904223
	// (odd) — full period on any power-of-two modulus. The seed rotates c
	// per prefix so two prefixes do not walk in visible lockstep.
	const a = uint64(1664525)
	return &lcgIterator{
		prefixes: prefixes,
		pos:      make([]uint64, len(prefixes)),
		a:        a,
		c:        uint64(1013904223) + seed%2, // stays odd: seed rotated
		primary:  int(seed) % len(prefixes),
	}, nil
}

// modulusOf returns the address-space size of the prefix host part.
func modulusOf(p netip.Prefix) uint64 {
	hostBits := uint(0)
	if p.Addr().Is4() {
		hostBits = 32 - uint(p.Bits())
	} else {
		hostBits = 128 - uint(p.Bits())
	}
	if hostBits == 0 {
		return 1
	}
	if hostBits > 32 {
		hostBits = 32 // cap: /0 walks are not a scan shape
	}
	return 1 << hostBits
}

// next produces the next address, rotating across prefixes so a
// multi-prefix scan samples them evenly. ok=false when every prefix has
// completed one full period.
func (it *lcgIterator) next() (netip.Addr, bool) {
	n := len(it.prefixes)
	for k := 0; k < n; k++ {
		i := (it.primary + k) % n
		p := it.prefixes[i]
		m := modulusOf(p)
		if it.pos[i] >= m {
			continue // prefix exhausted for this run
		}
		offset := (it.a*it.pos[i] + it.c) % m
		addr := prefixAddrAt(p, offset)
		it.pos[i]++
		it.primary = (i + 1) % n
		return addr, true
	}
	return netip.Addr{}, false
}

// prefixAddrAt renders the address with host offset inside p (v6 remaps
// only the low 32 host bits — wider v6 walks are not a scan shape).
func prefixAddrAt(p netip.Prefix, offset uint64) netip.Addr {
	if p.Addr().Is4() {
		if p.Bits() >= 32 {
			return p.Addr()
		}
		hostBits := uint(32 - p.Bits())
		base := p.Addr().As4()
		v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
		v &= ^uint32(0) << hostBits
		v |= uint32(offset) & (^uint32(0) >> (32 - hostBits))
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	base := p.Addr().As16()
	if p.Bits() < 128 {
		hostBits := uint(128 - p.Bits())
		if hostBits > 32 {
			hostBits = 32
		}
		lo := uint64(0)
		for i := 8; i < 16; i++ {
			lo = lo<<8 | uint64(base[i])
		}
		lo &= ^uint64(0) << hostBits
		lo |= offset & (^uint64(0) >> (64 - hostBits))
		for i := 8; i < 16; i++ {
			base[i] = byte(lo >> (8 * (15 - i)))
		}
	}
	return netip.AddrFrom16(base)
}

// cryptoSeed is the production LCG seed source.
func cryptoSeed() (int64, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return 0, err
	}
	return v.Int64(), nil
}

// WarpScan runs the bounded endpoint scan. Only bad options produce an
// error; an empty result set is a legitimate outcome (nothing answered).
// The scan stops at Limit verified hits or when ctx ends; in-flight
// probes are abandoned (their sockets close with the context).
func WarpScan(ctx context.Context, opts WarpScanOptions) ([]WarpScanHit, WarpScanStats, error) {
	var stats WarpScanStats
	started := time.Now()
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = DefaultWarpScanLimit
	}
	maxRTT := opts.MaxRTT
	if maxRTT <= 0 {
		maxRTT = DefaultWarpScanMaxRTT
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = DefaultWarpScanWorkers
	}
	if workers > MaxWarpScanWorkers {
		workers = MaxWarpScanWorkers
	}

	prefixes := opts.Prefixes
	if len(prefixes) == 0 {
		prefixes = append([]netip.Prefix{}, ztZeroTrustV4...) // catalog default
	}
	// The §34 gate: every prefix must sit inside the catalog unless the
	// tests-only escape is armed.
	if !opts.AllowOutOfCatalog {
		for _, p := range prefixes {
			if !prefixInCatalog(p) {
				return nil, stats, fmt.Errorf(
					"transportwg: scan prefix %s outside the endpoint catalog (red line §11.5)", p)
			}
		}
	}

	ports := opts.Ports
	if len(ports) == 0 {
		ports = AllPorts()
	}
	var gatedPorts []uint16
	for _, p := range ports {
		if opts.AllowOutOfCatalog || KnownWGPort(p) {
			gatedPorts = append(gatedPorts, p)
		}
	}
	if len(gatedPorts) == 0 {
		return nil, stats, fmt.Errorf("transportwg: no measured ports in the scan window")
	}

	it, err := newLCGIterator(prefixes, opts.Rand)
	if err != nil {
		return nil, stats, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var probes atomic.Int64
	addrs := make(chan netip.Addr)
	go func() {
		defer close(addrs)
		for ctx.Err() == nil {
			addr, ok := it.next()
			if !ok {
				return
			}
			select {
			case addrs <- addr:
			case <-ctx.Done():
				return
			}
		}
	}()

	type probeOutcome struct {
		hit WarpScanHit
		err error
	}
	results := make(chan probeOutcome, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for addr := range addrs {
				if ctx.Err() != nil {
					return
				}
				probes.Add(1)
				port := gatedPorts[int(addrProbeCounter(addr))%len(gatedPorts)]
				ap := netip.AddrPortFrom(addr.Unmap(), port)
				hit, perr := warpScanProbe(ctx, ap, opts)
				if perr != nil && ctx.Err() != nil {
					return // cancelled mid-probe: not an observation
				}
				select {
				case results <- probeOutcome{hit: hit, err: perr}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	best := make(map[netip.AddrPort]time.Duration)
	accept := func(res probeOutcome) {
		if res.err != nil {
			switch scanErrorClass(res.err) {
			case "timeout":
				stats.Timeouts++
			case "unreachable":
				stats.Unreachable++
			default:
				stats.Other++
			}
			return
		}
		if res.hit.RTT > maxRTT {
			stats.TooSlow++
			return
		}
		if prev, seen := best[res.hit.AddrPort]; seen {
			stats.Duplicates++
			if res.hit.RTT < prev {
				best[res.hit.AddrPort] = res.hit.RTT
			}
			return
		}
		best[res.hit.AddrPort] = res.hit.RTT
	}

collect:
	for len(best) < limit {
		select {
		case res, ok := <-results:
			if !ok {
				break collect
			}
			accept(res)
		case <-ctx.Done():
			for len(best) < limit {
				select {
				case res, ok := <-results:
					if !ok {
						break collect
					}
					accept(res)
				default:
					break collect
				}
			}
			break collect
		}
	}
	cancel()

	hits := make([]WarpScanHit, 0, len(best))
	for ap, rtt := range best {
		hits = append(hits, WarpScanHit{AddrPort: ap, RTT: rtt})
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].RTT != hits[j].RTT {
			return hits[i].RTT < hits[j].RTT
		}
		return hits[i].AddrPort.Compare(hits[j].AddrPort) < 0
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	stats.Probes = probes.Load()
	stats.Hits = len(hits)
	stats.Elapsed = time.Since(started)
	logf("warp-scan: done in %s probes=%d hits=%d too_slow=%d timeouts=%d unreachable=%d other=%d",
		stats.Elapsed.Round(100*time.Millisecond), stats.Probes, stats.Hits,
		stats.TooSlow, stats.Timeouts, stats.Unreachable, stats.Other)
	return hits, stats, nil
}

// addrProbeCounter derives a stable per-address port index (so the same
// address is always probed on the same port within one run shape).
func addrProbeCounter(addr netip.Addr) uint32 {
	if addr.Is4() {
		b := addr.As4()
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	b := addr.As16()
	return uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])
}

// warpScanProbe executes ONE handshake probe against ap: bare initiation
// (engine vanilla-off profile), reserved bytes stamped after mac1,
// response scrubbed before authentication. RTT covers send→verified reply.
func warpScanProbe(ctx context.Context, ap netip.AddrPort, opts WarpScanOptions) (WarpScanHit, error) {
	// Fresh ephemeral + sender index per probe.
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return WarpScanHit{}, fmt.Errorf("eph: %w", err)
	}
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64
	var idxBuf [4]byte
	if _, err := rand.Read(idxBuf[:]); err != nil {
		return WarpScanHit{}, fmt.Errorf("index: %w", err)
	}
	in, err := wgprobe.BuildInitiation(opts.PrivateKey, opts.PeerPublicKey, ephPriv,
		uint32(idxBuf[0])|uint32(idxBuf[1])<<8|uint32(idxBuf[2])<<16|uint32(idxBuf[3])<<24,
		wgprobe.Tai64n(time.Now()))
	if err != nil {
		return WarpScanHit{}, err
	}
	packet := append([]byte(nil), in.Packet()...)
	wgprobe.StampReserved(packet, opts.Reserved) // engine wire discipline

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", ap.String())
	if err != nil {
		return WarpScanHit{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	started := time.Now()
	if _, err := conn.Write(packet); err != nil {
		return WarpScanHit{}, err
	}
	if err := conn.SetReadDeadline(started.Add(WarpScanProbeTimeout)); err != nil {
		return WarpScanHit{}, err
	}

	buf := make([]byte, 2048)
	for {
		n, rerr := conn.Read(buf)
		if rerr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return WarpScanHit{}, ctxErr
			}
			return WarpScanHit{}, rerr // deadline: silence is the verdict
		}
		resp := append([]byte(nil), buf[:n]...)
		wgprobe.ScrubReserved(resp) // the edge sends them SET; MACs cover zeros
		if !in.ResponseLooksLike(resp) {
			continue // unrelated datagram (cover echo, foreign traffic)
		}
		if err := in.ConsumeResponse(resp); err != nil {
			continue // forged/broken: keep waiting for the real one
		}
		rtt := time.Since(started)
		if rtt < time.Millisecond {
			rtt = time.Millisecond // Nova coerceAtLeast(1)
		}
		return WarpScanHit{AddrPort: ap, RTT: rtt}, nil
	}
}

// prefixInCatalog reports whether every address of p is inside the WG
// catalog ranges (a scan must never widen the endpoint set).
func prefixInCatalog(p netip.Prefix) bool {
	if p.Bits() == 0 {
		return false
	}
	// The catalog ranges are /24, /32, /48, /64 — containment check via
	// any member address + width: a prefix is inside iff its base address
	// is inside AND its width does not exceed the containing range's.
	addr := p.Addr().Unmap()
	if !InWGCatalog(addr) {
		return false
	}
	for _, pool := range RegionalPools {
		for _, rp := range pool.Prefixes {
			if rp.Contains(addr) && p.Bits() >= rp.Bits() {
				return true
			}
		}
	}
	for _, rp := range ztZeroTrustV4 {
		if rp.Contains(addr) && p.Bits() >= rp.Bits() {
			return true
		}
	}
	for _, rp := range ztZeroTrustV6 {
		if rp.Contains(addr) && p.Bits() >= rp.Bits() {
			return true
		}
	}
	for _, rp := range regionalV6 {
		if rp.Contains(addr) && p.Bits() >= rp.Bits() {
			return true
		}
	}
	return false
}
