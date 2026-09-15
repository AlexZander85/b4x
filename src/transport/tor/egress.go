package tor

// Egress dialer (design §3.2, patch-plan §4.1): the single point where ALL
// of tor's own outbound connections leave the process — both the vanilla
// relay/bridge legs (via the loopback SOCKS5 egress bridge that tor's
// Socks5Proxy points at) and the PT legs (via the in-process PT proxy's
// protected dial). Every dial is classified, self-loop guarded, resolved
// through DoH (no ISP DNS leak for hostname bridges) and routed by policy:
//
//      direct          marked net.Dialer (SO_MARK MarkTorEgress)
//      through:<kind>  reserve.Lookup(kind).Carrier.DialStream (composition)
//      auto            operaservice failover canon: direct 5s → negative cache
//                      60s after 2 fails → carrier-first + self-heal probe
//
// Rendezvous (snowflake broker/AMP) and bootstrap sources (onionoo, Moat,
// collector mirrors) NEVER honor a pinned carrier and never travel through
// tor itself: they always run the direct-with-carrier-fallback shape —
// the anti-loop invariant (design §9.2) holds by construction because this
// dialer is the only egress and it never dials through tor's SOCKS.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/reserve"
)

// ConnClass labels the outbound connection category (design §3.2) —
// metrics dimension and policy input.
type ConnClass string

const (
	ClassBridgePT      ConnClass = "bridge-pt"        // PT endpoints (obfs4/webtunnel/meek/snowflake)
	ClassBridgeVanilla ConnClass = "bridge-vanilla"   // vanilla bridge ORPort
	ClassRelayDir      ConnClass = "relay-dir"        // relays + directory authorities
	ClassRendezvous    ConnClass = "rendezvous"       // snowflake broker / AMP cache
	ClassBootstrapSrc  ConnClass = "bootstrap-source" // onionoo / Moat / collector mirrors
)

// ErrTorSelfLoop refuses a dial to tor's own listeners (design §3.2
// self-loop guard): tor dialing itself (or the egress bridge dialing the
// carrier's own session when the carrier is tor) is a loop that can only
// spin, never connect.
var ErrTorSelfLoop = errors.New("tor egress self-loop refused")

// Sentinel: no carrier of the requested kind is registered.
var ErrCarrierUnavailable = errors.New("tor egress carrier unavailable")

// ErrNotListening: the tor SOCKS listener is not up (pre-bootstrap or
// torn down) — the carrier refuses honestly instead of hanging.
var ErrNotListening = errors.New("tor socks listener not up")

// CarrierLookup is the injected registry seam (production: reserve.Lookup;
// tests: a fake with dial counters).
type CarrierLookup func(kind reserve.Kind) (reserve.Entry, bool)

// ResolveFunc resolves a hostname to global unicast IPs (production: DoH;
// tests: fake). Anti-SSRF filtering happens on the results.
type ResolveFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// LoopAddrs returns the CURRENT tor-runtime listener set (SOCKS, control,
// PT proxy, egress bridge) for the self-loop guard; nil disables the guard
// (unit dial tests without a runtime).
type LoopAddrs func() []string

// EgressPolicy is the resolved policy (config.tor.egress projection).
type EgressPolicy struct {
	// Through is ""|none|warp|masque|h3|opera|fxvpn|proton|auto.
	Through string
	// BaitProfile is ""|none|first-flight (informational for the tables
	// layer; the mark is set either way — OUTPUT decides bait vs bypass).
	BaitProfile string
	// Now is the clock seam.
	Now func() time.Time
}

// EgressDialFunc is the egress dial seam shared by the service layer and
// the snowflake adapter (production: the runtime's egress Dialer.Dial).
type EgressDialFunc func(ctx context.Context, class ConnClass, host string, port uint16) (net.Conn, error)

// MarkControlFunc is the platform SO_MARK seam (nil in sandboxes without
// CAP_NET_ADMIN).
type MarkControlFunc func(network, address string, c syscall.RawConn) error

// Failover canon constants (operaservice §H2 — the same numbers).
const (
	// EgressDirectTimeout bounds a direct egress dial (5s — the OS-level
	// ~2min black hole is a price no data dial should ever pay).
	EgressDirectTimeout = 5 * time.Second
	egressDirectFailCap = 2
	egressDirectDeadTTL = 60 * time.Second
	egressDNSFailTTL    = 60 * time.Second
)

// DefaultEgressDoHServers are IP-hosted wire-format DoH resolvers (no DNS
// bootstrap needed for the resolver itself — the anti-leak property). The
// resolver built on them lives in torservice (the dns package imports
// classifier->config: wiring it here would be an import cycle; the seam
// stays injectable so the transport layer never depends on it).
var DefaultEgressDoHServers = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
}

// Dialer is the egress dialer (design §3.2).
type Dialer struct {
	policy  EgressPolicy
	lookup  CarrierLookup
	resolve ResolveFunc
	loops   LoopAddrs
	// markCtl applies SO_MARK MarkTorEgress on the direct legs (bait AND
	// bypass both key off the mark — production always sets it). The seam
	// exists because SO_MARK needs CAP_NET_ADMIN: dev/test sandboxes that
	// lack it inject nil instead of failing every dial.
	markCtl func(network, address string, c syscall.RawConn) error

	mu              sync.Mutex
	directFails     int
	directDeadUntil time.Time
	dnsOK           map[string][]netip.Addr // positive cache: until restart
	dnsDead         map[string]time.Time    // negative cache: short TTL
}

// NewDialer builds the dialer; nil seams get production defaults.
func NewDialer(policy EgressPolicy, lookup CarrierLookup, resolve ResolveFunc, loops LoopAddrs) *Dialer {
	if policy.Now == nil {
		policy.Now = time.Now
	}
	if lookup == nil {
		lookup = reserve.Lookup
	}
	if resolve == nil {
		resolve = unwiredResolve
	}
	return &Dialer{
		policy:  policy,
		lookup:  lookup,
		resolve: resolve,
		loops:   loops,
		markCtl: egressMarkControl(),
		dnsOK:   map[string][]netip.Addr{},
		dnsDead: map[string]time.Time{},
	}
}

// Policy exposes the resolved policy (status projection).
func (d *Dialer) Policy() EgressPolicy { return d.policy }

// SetLoops wires the self-loop guard's listener set (the service layer
// installs it once the loopback listeners exist).
func (d *Dialer) SetLoops(loops LoopAddrs) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loops = loops
}

// Dial dials one classified outbound connection (design §3.2). The
// self-loop guard runs BEFORE resolution: a loopback listener target is
// refused as a loop, not as an anti-SSRF violation (different diagnosis,
// different class).
func (d *Dialer) Dial(ctx context.Context, class ConnClass, host string, port uint16) (net.Conn, error) {
	if d.isSelfLoop(host, port) {
		recordDialMetrics(class, "fail")
		return nil, fmt.Errorf("%w: %s:%d is a tor-runtime listener", ErrTorSelfLoop, host, port)
	}
	addr, err := d.resolveTarget(ctx, host)
	if err != nil {
		recordDialMetrics(class, "fail")
		return nil, err
	}

	target := netip.AddrPortFrom(addr, port)
	policy := d.effectivePolicy(class)

	switch policy {
	case "none":
		conn, err := d.dialDirect(ctx, target)
		if err != nil {
			recordDialMetrics(class, "fail")
			return nil, err
		}
		recordDialMetrics(class, "ok")
		return conn, nil
	case "auto":
		conn, err := d.dialFailover(ctx, target)
		if err != nil {
			recordDialMetrics(class, "fail")
			return nil, err
		}
		recordDialMetrics(class, "ok")
		return conn, nil
	default:
		// through:<kind> — a named carrier (design §3.3).
		kind := reserve.Kind(policy)
		conn, err := d.dialCarrier(ctx, kind, target)
		if err != nil {
			recordDialMetrics(class, "fail")
			return nil, err
		}
		recordDialMetrics(class, "ok")
		return conn, nil
	}
}

// effectivePolicy maps (class, configured policy) onto the runtime policy:
// rendezvous and bootstrap sources always run direct-with-carrier-fallback
// (design §3.3/§9.2 — the anti-loop invariant), everything else honors the
// configured Through.
func (d *Dialer) effectivePolicy(class ConnClass) string {
	switch class {
	case ClassRendezvous, ClassBootstrapSrc:
		return "auto"
	}
	return resolveThrough(d.policy.Through)
}

func resolveThrough(through string) string {
	if through == "" {
		return "none"
	}
	return through
}

// resolveTarget resolves host to exactly one dialable IP. LITERALS dial
// as given (they came from tor's own control plane or parser-admitted
// bridge lines; only undialable families are refused) — the strict
// is_global anti-SSRF rule (design §3.2) applies to RESOLVED hostnames:
// a bridge line whose hostname resolves into LAN space is a
// misconfiguration, not a tunnel, and must never dial.
func (d *Dialer) resolveTarget(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := requireDialableLiteral(ip); err != nil {
			return netip.Addr{}, err
		}
		return ip, nil
	}
	// hostname: positive cache first (until restart — design §3.2), then DoH.
	d.mu.Lock()
	if addrs, ok := d.dnsOK[host]; ok && len(addrs) > 0 {
		d.mu.Unlock()
		return addrs[0], nil
	}
	if dead, ok := d.dnsDead[host]; ok && d.policy.Now().Before(dead) {
		d.mu.Unlock()
		return netip.Addr{}, fmt.Errorf("tor egress resolve %q: negative cache (recent failure)", host)
	}
	d.mu.Unlock()

	addrs, err := d.resolve(ctx, host)
	if err != nil || len(addrs) == 0 {
		if err == nil {
			err = errors.New("empty answer")
		}
		d.mu.Lock()
		d.dnsDead[host] = d.policy.Now().Add(egressDNSFailTTL)
		d.mu.Unlock()
		return netip.Addr{}, fmt.Errorf("tor egress resolve %q: %w", host, err)
	}
	var global []netip.Addr
	for _, a := range addrs {
		if requireGlobal(a) == nil {
			global = append(global, a)
		}
	}
	if len(global) == 0 {
		d.mu.Lock()
		d.dnsDead[host] = d.policy.Now().Add(egressDNSFailTTL)
		d.mu.Unlock()
		return netip.Addr{}, fmt.Errorf("tor egress resolve %q: no global unicast address in answer (anti-SSRF)", host)
	}
	d.mu.Lock()
	d.dnsOK[host] = global
	d.mu.Unlock()
	return global[0], nil
}

func requireGlobal(ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("invalid address")
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return fmt.Errorf("address %s is not a global unicast address (anti-SSRF)", ip)
	}
	return nil
}

// requireDialableLiteral refuses only undialable literal families
// (unspecified/multicast); loopback and private literals pass — the
// self-loop guard owns the loopback hazard, the parser owns bridge-line
// hygiene, and local test stands live on loopback.
func requireDialableLiteral(ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("invalid address")
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("address %s is not a dialable unicast address", ip)
	}
	return nil
}

// isSelfLoop compares the target (host:port, host literal or name) against
// the runtime listener set BEFORE any resolution: exact matches and
// loopback-family matches on the same port both count (the guard must be
// at least as strict as the listener kernel binding).
func (d *Dialer) isSelfLoop(host string, port uint16) bool {
	if d.loops == nil {
		return false
	}
	portStr := strconv.FormatUint(uint64(port), 10)
	hostNorm := host
	hip, hipErr := netip.ParseAddr(host)
	if hipErr == nil {
		hostNorm = hip.String()
	}
	for _, l := range d.loops() {
		lh, lp, err := net.SplitHostPort(l)
		if err != nil {
			if l == net.JoinHostPort(hostNorm, portStr) {
				return true
			}
			continue
		}
		if lp != portStr {
			continue
		}
		if lh == hostNorm {
			return true
		}
		if lip, lerr := netip.ParseAddr(lh); lerr == nil && lip.IsLoopback() {
			if hipErr == nil && (hip.IsLoopback() || hip.IsUnspecified()) {
				return true
			}
			if strings.EqualFold(hostNorm, "localhost") {
				return true
			}
		}
	}
	return false
}

// dialDirect is the marked direct leg (SO_MARK MarkTorEgress — the OUTPUT
// mangle layer turns it into bait or bypass per the bait profile; local
// control because the socks5 package is config-coupled and importing it
// from here would close an import cycle).
func (d *Dialer) dialDirect(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	nd := net.Dialer{Timeout: EgressDirectTimeout, KeepAlive: 30 * time.Second}
	nd.Control = d.markCtl // nil in mark-less sandboxes (tests)
	return nd.DialContext(ctx, "tcp", target.String())
}

// dialCarrier dials through a named carrier (composition — design §2.2).
// Tor itself is excluded from the candidate set by construction: the
// carrier kind list never contains KindTor here (a pinned "tor through
// tor" config is rejected at the config layer: through enum has no tor).
func (d *Dialer) dialCarrier(ctx context.Context, kind reserve.Kind, target netip.AddrPort) (net.Conn, error) {
	entry, ok := d.lookup(kind)
	if !ok || entry.Carrier == nil {
		return nil, fmt.Errorf("%w: kind=%s", ErrCarrierUnavailable, kind)
	}
	return entry.Carrier.DialStream(ctx, target)
}

// dialFailover is the operaservice failover canon (review E-OPERA H2):
// direct-first hard-bounded at 5s; two consecutive direct failures poison
// direct for 60s (carrier-first then, zero black-hole time on the censored
// path); when the carrier also fails, one direct self-heal probe runs so
// recovery is noticed.
func (d *Dialer) dialFailover(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	if d.directAlive() {
		conn, err := d.dialDirect(ctx, target)
		if err == nil {
			d.recordDirect(true)
			return conn, nil
		}
		d.recordDirect(false)
		if cconn, cerr := d.dialAnyCarrier(ctx, target); cerr == nil {
			return cconn, nil
		}
		return nil, err
	}
	// direct presumed dead: carrier-first
	if cconn, cerr := d.dialAnyCarrier(ctx, target); cerr == nil {
		return cconn, nil
	}
	// self-heal probe: one direct attempt re-arms the cache on success
	conn, err := d.dialDirect(ctx, target)
	if err == nil {
		d.recordDirect(true)
		return conn, nil
	}
	d.recordDirect(false)
	return nil, fmt.Errorf("tor egress failover exhausted: direct: %v", err)
}

// dialAnyCarrier tries carriers by registry priority (tor excluded).
func (d *Dialer) dialAnyCarrier(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	for _, entry := range reserve.List() {
		if entry.Kind == reserve.KindTor || entry.Carrier == nil {
			continue // never ourselves — the loop guard of the auto mode
		}
		if conn, err := entry.Carrier.DialStream(ctx, target); err == nil {
			return conn, nil
		}
	}
	return nil, ErrCarrierUnavailable
}

func (d *Dialer) directAlive() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.policy.Now().After(d.directDeadUntil) || d.directDeadUntil.IsZero()
}

func (d *Dialer) recordDirect(ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ok {
		d.directFails = 0
		d.directDeadUntil = time.Time{}
		return
	}
	d.directFails++
	if d.directFails >= egressDirectFailCap {
		d.directDeadUntil = d.policy.Now().Add(egressDirectDeadTTL)
	}
}

// unwiredResolve is the nil-seam fallback: hostname resolution MUST be
// wired by the service layer (DoH with the tor egress mark); an unwired
// resolver refuses loudly instead of leaking into the system resolver.
func unwiredResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return nil, fmt.Errorf("tor egress resolver not wired (hostname %q)", host)
}

func recordDialMetrics(class ConnClass, result string) {
	observability.Default().Metrics.Inc(observability.MetricTorDialTotal,
		map[string]string{"class": string(class), "result": result}, 1)
}
