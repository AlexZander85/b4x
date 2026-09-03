// Data-plane trust gate (design §4): WG has no structural "CONNECT-IP 200",
// so trust is proven ONLY by traffic — after the Noise handshake completes,
// the gate pushes two DNS round-trips (cloudflare.com @ 8.8.8.8, gap
// 600 ms) through the tunnel and requires matched replies within the
// window (Aether data-validation lineage). Only then may the session be
// reported established and drive route/camouflage decisions.
//
// The optional E2E probe slot (trace warp=on|plus, double measurement)
// runs after the DNS gate when wired: in netstack mode it is a plain HTTP
// exchange through gvisor; in kernel-TUN mode it belongs to the field
// layer. nil = skipped by design, never silently "passed".
package transportwg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	twarp "github.com/daniellavrushin/b4/transport/warp"
)

// Gate defaults (design §4; Aether quic.rs/masque.rs lineage).
const (
	DefaultGateRoundTrips = 2
	DefaultGateGap        = 600 * time.Millisecond
	DefaultGateWindow     = 10 * time.Second
	defaultGateDNS        = "8.8.8.8"
	defaultGateQName      = "cloudflare.com"
	// probeRetryInterval: a single lost probe must not consume the gate —
	// re-transmit within the window (Aether init-retry reference 750/2000 ms;
	// we stay under 750 ms so the first retry beats the handshake backoff).
	probeRetryInterval = 700 * time.Millisecond
	// DefaultGateSigMinTX: minimum tx delta across a failed gate window for
	// the failure to be upgraded to awg-version-mismatch (rx must be exactly
	// zero). Probes are ~60 B and retries double them, so 128 B separates
	// "we really sent" from "nothing left the host".
	DefaultGateSigMinTX uint64 = 128
	// bootstrapQNameLabel marks the session's own handshake-triggering probe
	// so wire-level consumers (and tests) can tell it apart from trust-gate
	// probes.
	bootstrapQNameLabel = "bootstrap."
)

// DNSRoundTripper sends one prebuilt probe packet into the tunnel and
// returns the matched reply's DNS payload.
type DNSRoundTripper interface {
	Exchange(ctx context.Context, probe twarp.Probe, timeout time.Duration) (reply []byte, err error)
}

// E2EProbe is the optional trace probe slot (warp=on|plus double shot).
type E2EProbe func(ctx context.Context) error

// GateSkip (negative RoundTrips) disables the gate entirely: the loop body
// never runs and Verify returns nil after the nil-rt check. The documented
// consumer is the kernel-TUN mode (review P2 stage в): the raw probe path
// cannot complete over a kernel stack (the probe's source is the tunnel
// address, the reply dies at local delivery), so kernel sessions prove
// liveness through the handshake + the counters watchdog instead. Netstack
// sessions MUST NOT use it.
const GateSkip = -1

// TrustGate proves end-to-end reachability over an established handshake.
type TrustGate struct {
	LocalV4    [4]byte
	DNSServer  [4]byte
	QName      string
	RoundTrips int
	Gap        time.Duration
	Window     time.Duration // per-round-trip budget
	E2EProbe   E2EProbe      // optional; nil = skip (kernel-TUN field layer)
	// E2EProbeEnabled turns the built-in netstack trace probe ON for
	// netstack-mode sessions that did not attach an explicit E2EProbe
	// (PATCH-10/A5, WG MINOR 14): production wiring flips this flag; CI
	// fixtures and the seek ladder leave it off (the chan-TUN factory has
	// no HTTP surface, and seek budgets cannot afford the extra RTT).
	// An on-path injector that forges DNS replies with the correct TXID is
	// rejected here: the trace answer must actually say warp=on (two
	// measurements).
	E2EProbeEnabled bool
	// SigMinTX is the gate-scope version-mismatch signature threshold: on a
	// failed gate, tx delta >= SigMinTX with zero rx upgrades the failure to
	// awg-version-mismatch. 0 -> DefaultGateSigMinTX.
	SigMinTX uint64
}

func (g *TrustGate) fillDefaults() {
	if g.RoundTrips == 0 {
		g.RoundTrips = DefaultGateRoundTrips
	}
	if g.Gap == 0 {
		g.Gap = DefaultGateGap
	}
	if g.Window == 0 {
		g.Window = DefaultGateWindow
	}
	if g.QName == "" {
		g.QName = defaultGateQName
	}
	if g.DNSServer == ([4]byte{}) {
		g.DNSServer = [4]byte{8, 8, 8, 8}
	}
}

// Verify runs the gate: RoundTrips DNS exchanges separated by Gap, then the
// optional E2E probe. Every failure is a structural *Failure of class
// wg-stall-rx (the data plane accepted control but dropped payload family).
func (g *TrustGate) Verify(ctx context.Context, rt DNSRoundTripper) error {
	g.fillDefaults()
	if rt == nil {
		return newFailure(ClassParamRejected, "gate-nil-roundtripper", nil)
	}
	for i := 0; i < g.RoundTrips; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(g.Gap):
			}
		}
		probe, err := twarp.NewDNSProbe(g.LocalV4, g.DNSServer, g.QName)
		if err != nil {
			return newFailure(ClassParamRejected, "gate-probe-build", err)
		}
		reply, err := rt.Exchange(ctx, *probe, g.Window)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return newFailure(ClassStallRX, fmt.Sprintf("gate-dns-no-answer[%d]", i), err)
		}
		if !validGateReply(reply, probe.TXID) {
			return newFailure(ClassStallRX, fmt.Sprintf("gate-dns-mismatched-reply[%d]", i), nil)
		}
	}
	if g.E2EProbe != nil {
		pctx, cancel := context.WithTimeout(ctx, g.Window*2)
		defer cancel()
		if err := g.E2EProbe(pctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return newFailure(ClassStallRX, "gate-e2e-probe", err)
		}
	}
	return nil
}

// validGateReply checks QR=1 plus the transaction id; semantic parsing
// stays with the layer that owns the exchange.
func validGateReply(reply []byte, txid [2]byte) bool {
	if len(reply) < 12 {
		return false
	}
	return reply[0] == txid[0] && reply[1] == txid[1] && reply[2]&0x80 != 0
}

var errGateTimeout = fmt.Errorf("dns round trip timed out")

// RawTUNRoundTripper drives the gate over a raw TUN surface: Inject feeds
// the query into the tunnel-outbound direction; Capture awaits inbound
// packets delivered by the device to the local stack.
type RawTUNRoundTripper struct {
	Inject  func([]byte) error
	Capture func(ctx context.Context) ([]byte, error)
}

// Exchange writes the probe packet and scans inbound packets for the
// matching UDP/DNS reply (src=server:53 -> our sport, same txid). A lost
// probe is re-transmitted every probeRetryInterval until the window closes;
// handshake pacing is untouched — initiations stay owned by the engine's
// own retry timers.
func (rt *RawTUNRoundTripper) Exchange(ctx context.Context, probe twarp.Probe, timeout time.Duration) ([]byte, error) {
	local := probeLocalV4(probe.Packet)
	server := probeServerV4(probe.Packet)
	sport := be16(probe.Packet[20], probe.Packet[21])

	if err := rt.Inject(probe.Packet); err != nil {
		return nil, fmt.Errorf("gate write: %w", err)
	}
	lastSend := time.Now()
	deadline := lastSend.Add(timeout)
	for {
		now := time.Now()
		remainTotal := deadline.Sub(now)
		if remainTotal <= 0 {
			return nil, errGateTimeout
		}
		wait := probeRetryInterval - now.Sub(lastSend)
		if wait > remainTotal {
			wait = remainTotal
		}
		if wait < 0 {
			wait = 0
		}
		cctx, ccancel := context.WithTimeout(ctx, wait)
		pkt, err := rt.Capture(cctx)
		ccancel()
		if err == nil {
			dns, ok := gateReplyPayload(pkt, local, server, sport, probe.TXID)
			if ok {
				return append([]byte(nil), dns...), nil
			}
			continue
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		now = time.Now()
		if now.After(deadline) {
			return nil, errGateTimeout
		}
		if now.Sub(lastSend) >= probeRetryInterval {
			if err := rt.Inject(probe.Packet); err != nil {
				return nil, fmt.Errorf("gate write(retry): %w", err)
			}
			lastSend = now
		}
	}
}

func probeLocalV4(pkt []byte) [4]byte { return [4]byte{pkt[12], pkt[13], pkt[14], pkt[15]} }

func probeServerV4(pkt []byte) [4]byte { return [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]} }

func be16(hi, lo byte) uint16 { return uint16(hi)<<8 | uint16(lo) }

// gateReplyPayload validates IPv4/UDP/DNS reply geometry: proto 17, reversed
// endpoints, server port 53 back to our sport, matching txid. Replies
// mangled by anycast load balancing still match on ports + txid.
func gateReplyPayload(pkt []byte, local, server [4]byte, ourSport uint16, txid [2]byte) ([]byte, bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return nil, false
	}
	src := [4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}
	dst := [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}
	if src != server || dst != local {
		return nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	u := pkt[ihl:]
	if len(u) < 8+12 {
		return nil, false
	}
	sport := be16(u[0], u[1]) // from resolver :53
	dport := be16(u[2], u[3]) // back to us
	if dport != ourSport || sport != 53 {
		return nil, false
	}
	dns := u[8:]
	if dns[0] != txid[0] || dns[1] != txid[1] {
		return nil, false
	}
	return dns, true
}

// NetstackRoundTripper drives the gate through the gvisor userspace stack:
// the query's DNS payload is sent as a REAL UDP exchange via the netstack,
// proving the full TCP/IP implementation path end-to-end.
//
// PATCH-09 (WG MINOR 6): the netstack gate RETRANSMITS on loss at the same
// cadence as the raw-TUN path (probeRetryInterval) — one lost probe no
// longer consumes the whole gate and tears the session down. The retransmit
// count is carried in timeout errors for lossy-path diagnostics
// (gate_retransmits_total).
type NetstackRoundTripper struct {
	NS    dialUDPFunc
	Local [4]byte

	// retransmits counts intra-window re-writes (diagnostics; part of the
	// gate_retransmits_total surface via Retransmits()).
	retransmits atomic.Uint64
}

// Retransmits reports how many re-writes the last exchanges performed
// (lossy-path diagnostics; the value is cumulative per round-tripper).
func (rt *NetstackRoundTripper) Retransmits() uint64 { return rt.retransmits.Load() }

type dialUDPFunc func(ctx context.Context, network, address string) (udpConn, error)

// udpConn is the minimal conn surface used by the netstack exchanger.
// Concurrent Read+Write across the two directions is required (the reader
// goroutine stays blocked while retransmit writes happen).
type udpConn interface {
	Write(b []byte) (int, error)
	Read(b []byte) (int, error)
	Close() error
}

// NewNetstackRoundTripper adapts netstack.Net.DialContext.
func NewNetstackRoundTripper(dial func(ctx context.Context, network, address string) (udpConn, error), local [4]byte) *NetstackRoundTripper {
	return &NetstackRoundTripper{NS: dial, Local: local}
}

// Exchange sends the probe's DNS payload to server:53 through the stack and
// reads until the matching reply arrives or the window closes. A lost probe
// is re-transmitted every probeRetryInterval within the window (PATCH-09;
// parity with RawTUNRoundTripper) — a single lost datagram no longer fails
// the gate. Timeout errors carry the retransmit count for diagnostics.
func (rt *NetstackRoundTripper) Exchange(ctx context.Context, probe twarp.Probe, timeout time.Duration) ([]byte, error) {
	const dnsPayloadOffset = 28 // ip20 + udp8
	if len(probe.Packet) <= dnsPayloadOffset {
		return nil, fmt.Errorf("gate probe too short")
	}
	query := probe.Packet[dnsPayloadOffset:]
	server := netip.AddrPortFrom(netip.AddrFrom4(probeServerV4(probe.Packet)), 53)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := rt.NS(ctx, "udp", server.String())
	if err != nil {
		return nil, fmt.Errorf("gate udp dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	write := func(what string) error {
		if _, err := conn.Write(query); err != nil {
			return fmt.Errorf("gate udp %s: %w", what, err)
		}
		return nil
	}
	if err := write("write"); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)

	// One reader owns the socket reads for the whole window; matching
	// datagrams flow through the channel, everything else keeps reading.
	buf := make([]byte, 4096)
	replies := make(chan []byte, 4)
	readErr := make(chan error, 1)
	go func() {
		for {
			n, rerr := conn.Read(buf)
			if rerr != nil {
				readErr <- rerr
				return
			}
			if n >= 12 && buf[0] == probe.TXID[0] && buf[1] == probe.TXID[1] && buf[2]&0x80 != 0 {
				data := append([]byte(nil), buf[:n]...)
				select {
				case replies <- data:
				case <-ctx.Done():
					return
				}
			}
			// non-matching datagram: keep reading
		}
	}()

	ticker := time.NewTicker(probeRetryInterval)
	defer ticker.Stop()
	for {
		select {
		case data := <-replies:
			return data, nil
		case rerr := <-readErr:
			if ctx.Err() != nil {
				return nil, errGateTimeout
			}
			return nil, rerr
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (after %d retransmits)", errGateTimeout, rt.retransmits.Load())
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("%w (after %d retransmits)", errGateTimeout, rt.retransmits.Load())
			}
			if err := write("write(retry)"); err != nil {
				return nil, err
			}
			rt.retransmits.Add(1)
		}
	}
}
