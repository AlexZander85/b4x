// Non-RU route gate — data plane (design §7; addendum v1.2 §42–47 geo
// attestation, §62.5 НЕ РФ gate with gate-close reasons, §62.6 DNS path
// proof, §63 warp_nonru_revocation_latency_seconds, §69 scenario matrix).
//
// This file mirrors the src/warp contract vocabulary (geo.go
// GeoObservation/GeoAttestation + attestationFresh semantics, nonru.go
// verdict helpers) while keeping the engine dependency-free: the engine
// owns the RUNTIME truth (probes through the inner tunnel, quorum,
// revocation timing); the contract package owns hard-gate accounting that
// the E7 wiring feeds from this state. Two deliberate deviations from the
// mirror source are recorded here:
//   - PublicIP is stored HASHED only (§71 hash_public_ips wins over name
//     parity; src/warp stores raw);
//   - GeoObservation carries Country (ISO alpha-2) so the quorum can check
//     the §44 "same non-RU country" rule, which src/warp's class-only
//     observations cannot express.
//
// Probe requirements implemented here (§43): probes can ONLY travel through
// the inner tunnel (the transport interface exposes no other egress), each
// probe must move the inner packet counters (counter-delta proof), and the
// result freshness/path identity are stamped by the gate.
package transportwarp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Verdicts (addendum §42 ADR-WARP-7).
type GeoVerdict string

const (
	VerdictPassNonRU    GeoVerdict = "PASS_NON_RU"
	VerdictFailRU       GeoVerdict = "FAIL_RU"
	VerdictInconclusive GeoVerdict = "INCONCLUSIVE"
	VerdictStale        GeoVerdict = "STALE"
)

// Gate-close reasons (addendum §62.5, exact strings).
const (
	CloseProviderRU        = "provider-ru"
	CloseDisagreement      = "provider-disagreement"
	CloseAttestationStale  = "attestation-stale"
	ClosePublicIPChanged   = "public-ip-changed"
	CloseParentReconnected = "parent-reconnected"
	CloseDNSPathFailed     = "dns-path-failed"
	CloseIPv6PathFailed    = "ipv6-path-failed"
	CloseDirectWANObserved = "direct-wan-observed"
	CloseInnerPathLost     = "inner-path-lost"
	CloseTargetServiceGeo  = "target-service-geo-failed"
	CloseManualDisable     = "manual-disable"
	CloseConfigGenChange   = "config-generation-change"
)

// Required events (§62.5 + §62.6 subset emitted by the engine). Target-
// service probing (scenarios 17/18) is wired separately and intentionally
// out of the E6 scope; the constant is declared to keep event names in one
// place.
const (
	EvGeoProbeStarted       = "warp_geo_probe_started"
	EvGeoProbePathProven    = "warp_geo_probe_path_proven"
	EvGeoProviderResult     = "warp_geo_provider_result"
	EvGeoProviderFailed     = "warp_geo_provider_failed"
	EvGeoQuorumEvaluated    = "warp_geo_quorum_evaluated"
	EvGeoAttestationIssued  = "warp_geo_attestation_issued"
	EvGeoAttestationExpired = "warp_geo_attestation_expired"
	EvGeoPublicIPChanged    = "warp_geo_public_ip_changed"
	EvGeoTargetServiceProbe = "warp_geo_target_service_probe_result"

	EvNonRUGateOpened             = "warp_nonru_gate_opened"
	EvNonRUGateClosed             = "warp_nonru_gate_closed"
	EvNonRURoutePromoted          = "warp_nonru_route_promoted"
	EvNonRURouteRevocationStarted = "warp_nonru_route_revocation_started"
	EvNonRURouteRevoked           = "warp_nonru_route_revoked"
	// EvRouteRevokeTimeout reports a revoke hook that exceeded RouteRevokeTimeout
	// (M3-14): the gate keeps running and the route is still revoked, but the
	// external hook stalled past its budget and Status carries RevokeDegraded.
	EvRouteRevokeTimeout = "warp_route_revoke_timeout"
	EvNonRUFailClosed    = "warp_nonru_fail_closed_activated"
	EvNonRUFallbackBase  = "warp_nonru_fallback_to_base_activated"

	EvDNSPathProven = "warp_dns_path_proven" // §62.6
	EvDNSPathFailed = "warp_dns_path_failed"
)

// Geo observation classes mirror src/warp.GeoClass values.
const (
	geoClassRU           = "ru"
	geoClassNonRU        = "non-ru"
	geoClassUnknown      = "unknown"
	geoClassDisagreement = "disagreement"
)

// Defaults (addendum §45 geo_attestation yaml; §43 two providers minimum).
const (
	DefaultRequiredProviders = 2
	DefaultGeoAttestationTTL = 120 * time.Second // ttl
	DefaultGeoRefreshEvery   = 60 * time.Second  // refresh_interval; grace_on_probe_failure = 0s
	DefaultGeoProbeTimeout   = 3 * time.Second   // per-provider budget
)

var (
	// ErrBlockedCarrier is the STRUCTURAL blocked status for every feature
	// whose byte carrier is the userspace TCP-over-base adapter that the
	// zero-dependency engine deliberately does not ship (Backend-B dial,
	// DoH exchange, CF-trace HTTPS probe). Owner decision at E8 close-out:
	// diagnostics must classify these as "carrier absent" — a different
	// failure layer from network failures; never report them as
	// connectivity errors.
	ErrBlockedCarrier     = errors.New("transportwarp: BLOCKED_CARRIER base-tunnel tcp carrier absent")
	ErrRouteRevokeTimeout = errors.New("transportwarp: revoke hook exceeded its budget")
	// ErrHTTPSNotWired: HTTPS-in-tunnel needs the userspace carrier above;
	// wraps ErrBlockedCarrier so callers can classify by layer.
	ErrHTTPSNotWired = fmt.Errorf("transportwarp: geo https probe %w", ErrBlockedCarrier)
	// ErrNoCounterDelta: a provider returned a result without any inner
	// counter movement — direct-WAN escape suspected (§43 / §69-21).
	ErrNoCounterDelta = errors.New("transportwarp: geo probe without inner counter delta")
	// ErrInnerTransportDown: the inner session is currently unavailable.
	ErrInnerTransportDown = errors.New("transportwarp: geo inner transport unavailable")
	// ErrTraceNotWARP: cloudflare trace did not report warp=on|plus.
	ErrTraceNotWARP = errors.New("transportwarp: trace does not report warp=on|plus")
)

// DeltaPackets reports how many packets moved between two snapshots of the
// session traffic counters (type lives next to Session.Counters).
func DeltaPackets(a, b PacketCounters) uint64 {
	return (b.TxPackets - a.TxPackets) + (b.RxPackets - a.RxPackets)
}

// ErrNotIPv4 reports a geo observation that carries no usable IPv4 address
// (BLOCKER B-1, decision D1). Unlike the trusted identity paths (Validate /
// intake) which reject such input fail-closed, the observation boundary is
// tolerant: callers treat ErrNotIPv4 as «observation without an IPv4 address»
// (neither RU nor non-RU — counted as unknown), never as a panic.
var ErrNotIPv4 = errors.New("transportwarp: geo observation without an IPv4 address")

// HashPublicIP returns the redacted-safe identity of an observed public IP
// (§71: geo probes store only country + IP hash by default). Only IPv4 and
// 4-in-6 addresses are hashable; a pure v6 or invalid address yields
// ErrNotIPv4. 4-in-6 is normalized with Unmap() so the hash equals the bare
// IPv4 form (source format the observer does not control).
func HashPublicIP(ip netip.Addr) (string, error) {
	if !ip.IsValid() {
		return "", ErrNotIPv4
	}
	if !ip.Is4() && !ip.Is4In6() {
		return "", ErrNotIPv4
	}
	a4 := ip.Unmap().As4()
	sum := sha256.Sum256(a4[:])
	return hex.EncodeToString(sum[:8]), nil
}

// GeoResult is one provider outcome before gate stamping.
type GeoResult struct {
	ProviderID   string
	Country      string // ISO-3166 alpha-2, "" = unclassifiable (unknown)
	PublicIPHash string
}

// GeoProvider is one INDEPENDENT source of geo truth (§43: at least two;
// Cloudflare trace MAY be one but never the only one — enforced by
// NewNonRUGate via distinct provider classes/IDs and the >=2 floor).
type GeoProvider interface {
	ID() string
	ProviderClass() string
	Probe(ctx context.Context, tr GeoProbeTransport) (GeoResult, error)
}

// GeoProbeTransport carries geo probes STRICTLY through the inner tunnel:
// there is no method on this interface that could reach the WAN directly,
// which is the structural half of the §43 "no direct fallback" proof (the
// observable half is the counter delta).
type GeoProbeTransport interface {
	PathID() string
	// ResolveA resolves through the inner resolver (UDP/53-in-tunnel).
	ResolveA(ctx context.Context, name string) ([]netip.Addr, time.Duration, error)
	// HTTPSExchange fetches a URL through the inner HTTPS adapter when the
	// E7 field layer wired it; ErrHTTPSNotWired otherwise.
	HTTPSExchange(ctx context.Context, url string) ([]byte, error)
	// Counters snapshots inner-path traffic for the delta proof.
	Counters() PacketCounters
}

// TunnelGeoTransport is the engine-side GeoProbeTransport over one
// established CONNECT-IP session: DNS goes out as IP packets to Cloudflare's
// dedicated resolvers (dns_tunnel.go pattern), inbound replies arrive via
// the session tap. One transport serializes its own exchanges; attach ONE
// transport per consumer.
type TunnelGeoTransport struct {
	sess           *Session
	path           string
	ch             <-chan []byte
	stop           func()
	resolveTimeout time.Duration
	https          HTTPSExchangeFunc // nil = fail closed (ErrHTTPSNotWired)
}

// AttachTunnelGeoTransport subscribes to sess inbound packets. Close MUST
// be called (or session Close will close the tap channel instead).
func AttachTunnelGeoTransport(sess *Session) *TunnelGeoTransport {
	ch, stop := sess.SubscribePackets()
	return &TunnelGeoTransport{
		sess:           sess,
		path:           EndpointHash(sess.cfg.Endpoint),
		ch:             ch,
		stop:           stop,
		resolveTimeout: 2 * time.Second,
	}
}

// Close unsubscribes from the session tap (idempotent via Session).
func (t *TunnelGeoTransport) Close() { t.stop() }

// WithResolveTimeout bounds one DNS exchange (tests shrink this).
func (t *TunnelGeoTransport) WithResolveTimeout(d time.Duration) *TunnelGeoTransport {
	t.resolveTimeout = d
	return t
}

// PathID is the redacted-safe inner path identity (endpoint hash).
func (t *TunnelGeoTransport) PathID() string { return t.path }

// Counters exposes the session counters for the §43 delta proof.
func (t *TunnelGeoTransport) Counters() PacketCounters { return t.sess.Counters() }

// ResolveA exchanges one DNS A query through the tunnel and proves the
// exchange on the inner counters (delta > 0 or ErrNoCounterDelta).
func (t *TunnelGeoTransport) ResolveA(ctx context.Context, name string) ([]netip.Addr, time.Duration, error) {
	local := t.sess.cfg.LocalV4
	q, err := NewDNSProbe(local, InnerTunnelDNS1, name)
	if err != nil {
		return nil, 0, err
	}
	sport := udpSportOf(q.Packet)
	if sport == 0 {
		return nil, 0, errors.New("transportwarp: geo resolve: bad query sport")
	}
	before := t.sess.Counters()

	started := time.Now()
	if err := t.sess.WritePacket(q.Packet); err != nil {
		return nil, 0, err
	}
	deadline := time.NewTimer(t.resolveTimeout)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-deadline.C:
			return nil, 0, ErrDNSNoAnswer
		case pkt, open := <-t.ch:
			if !open {
				return nil, 0, ErrDNSNoAnswer // session closed underneath
			}
			if !isDNSReply(pkt, local, InnerTunnelDNS1, sport, q.TXID) {
				continue // foreign payload: keep draining
			}
			if DeltaPackets(before, t.sess.Counters()) == 0 {
				return nil, 0, ErrNoCounterDelta
			}
			addrs, perr := parseDNSA(pkt[28:])
			if perr != nil || len(addrs) == 0 {
				return nil, 0, ErrDNSNoAnswer
			}
			return addrs, time.Since(started), nil
		}
	}
}

// WhoamiDNSProvider resolves a well-known "who am I" name through the INNER
// resolver; the returned A record is the public egress IPv4 as seen by an
// independent authority (Akamai whoami.akamai.net / Google
// o-o.myaddr.l.google.com debug patterns). Country classification is
// INJECTED — the engine ships no GeoIP database; production wiring supplies
// the oracle (E7). Two instances with different qnames/IDs are independent
// providers under §43.
type WhoamiDNSProvider struct {
	id       string
	qname    string
	classify func(netip.Addr) string
}

const (
	// ProviderClassDNSResolverAuthority is a provider whose geo truth is a DNS
	// resolution through the INNER resolver (§62.6). Only this class may stamp
	// DNSProof, so only it contributes a DNS-path-proven vote to the quorum.
	ProviderClassDNSResolverAuthority = "dns-resolver-authority"
	// ProviderClassCloudflareTrace is a single-vendor, single-observation-point
	// class (§43): a valid corroborating source, never a quorum on its own.
	ProviderClassCloudflareTrace = "cloudflare-trace"
)

func NewWhoamiDNSProvider(id, qname string, classify func(netip.Addr) string) *WhoamiDNSProvider {
	return &WhoamiDNSProvider{id: id, qname: qname, classify: classify}
}

func (p *WhoamiDNSProvider) ID() string            { return p.id }
func (p *WhoamiDNSProvider) ProviderClass() string { return ProviderClassDNSResolverAuthority }

func (p *WhoamiDNSProvider) Probe(ctx context.Context, tr GeoProbeTransport) (GeoResult, error) {
	addrs, _, err := tr.ResolveA(ctx, p.qname)
	if err != nil {
		return GeoResult{}, err
	}
	// BLOCKER B-1: an observation without a usable IPv4 address is not a
	// provider failure nor a panic — it is an «unknown» observation.
	hash, err := HashPublicIP(addrs[0])
	if err != nil {
		return GeoResult{ProviderID: p.id}, err
	}
	res := GeoResult{ProviderID: p.id, PublicIPHash: hash}
	if p.classify != nil {
		res.Country = p.classify(addrs[0])
	}
	return res, nil
}

// CFTraceProvider parses the Cloudflare edge trace (https://1.1.1.1/cdn-cgi/
// trace, z2k #1 pattern) fetched through the inner HTTPS adapter. The body
// must report warp=on|plus (a trace from OUTSIDE the tunnel fails this) —
// the structural stand-in for path proof until the adapter supplies real
// socket evidence.
type CFTraceProvider struct {
	id  string
	url string
}

func NewCFTraceProvider(id string) *CFTraceProvider {
	return &CFTraceProvider{id: id, url: "https://1.1.1.1/cdn-cgi/trace"}
}

func (p *CFTraceProvider) ID() string            { return p.id }
func (p *CFTraceProvider) ProviderClass() string { return ProviderClassCloudflareTrace }

func (p *CFTraceProvider) Probe(ctx context.Context, tr GeoProbeTransport) (GeoResult, error) {
	body, err := tr.HTTPSExchange(ctx, p.url)
	if err != nil {
		return GeoResult{}, err
	}
	var ip, loc, warp string
	for _, line := range strings.Split(string(body), "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "ip":
			ip = kv[1]
		case "loc":
			loc = kv[1]
		case "warp":
			warp = kv[1]
		}
	}
	if warp != "on" && warp != "plus" {
		return GeoResult{}, ErrTraceNotWARP
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return GeoResult{}, err
	}
	// BLOCKER B-1: a pure-v6 observation is «unknown», not a panic.
	hash, herr := HashPublicIP(addr)
	if herr != nil {
		return GeoResult{ProviderID: p.id, Country: loc}, herr
	}
	return GeoResult{ProviderID: p.id, Country: loc, PublicIPHash: hash}, nil
}

// GeoObservation mirrors src/warp.GeoObservation (same field semantics:
// provider identity, path identity, class, DNS proof, freshness window,
// counter delta, session generation) with the documented deviations: the
// public IP appears hashed, and Country is carried explicitly.
type GeoObservation struct {
	Provider          string
	PublicIPHash      string
	Country           string
	PathID            string
	Class             string // ru | non-ru | unknown (src/warp.GeoClass values)
	DNSProof          bool
	IPv6Proof         bool
	ObservedAt        time.Time
	ExpiresAt         time.Time
	CounterDelta      uint64
	SessionGeneration uint64
}

// GeoQuorum is the decision record (mirrors §62.5 GeoQuorumTrace fields
// relevant to the engine decision).
type GeoQuorum struct {
	Verdict      GeoVerdict
	Valid        int
	Required     int
	Countries    []string // distinct non-RU countries among valid observations
	AnyRU        bool
	AnyUnknown   bool
	AnyZeroDelta bool
	IPMismatch   bool
	Disagreement bool
	Insufficient bool
	Country      string // PASS winner
	PublicIPHash string
}

// EvaluateGeoQuorum mirrors src/warp.BuildGeoAttestation semantics (skip
// expired / zero-delta / no-DNS-proof observations; any RU dominates;
// strict same-country majority required) and extends them with what the
// runtime gate needs: configurable quorum size, the disagreement-vs-
// insufficient distinction (chooses between the provider-disagreement
// immediate revoke and holding until attestation-stale), and cross-provider
// public-IP consistency.
//
// Classification rules:
//   - any valid RU observation            → FAIL_RU (§44: one RU flips all);
//   - >= required same-country non-RU,
//     zero unknown, consistent IP        → PASS_NON_RU;
//   - conflicting countries / unknown mix /
//     differing public IPs               → INCONCLUSIVE+Disagreement
//     (§73: route must not stay active);
//   - everything else                    → INCONCLUSIVE+Insufficient
//     (not enough fresh evidence; attestation simply stops renewing).
func EvaluateGeoQuorum(obs []GeoObservation, required int, now time.Time) GeoQuorum {
	if required < 1 {
		required = DefaultRequiredProviders
	}
	q := GeoQuorum{Required: required}
	counts := map[string]int{}
	var ipHash string
	for _, o := range obs {
		if !o.ExpiresAt.IsZero() && !now.Before(o.ExpiresAt) {
			continue // expired: not fresh evidence
		}
		if o.CounterDelta == 0 {
			q.AnyZeroDelta = true
			continue // mirror src/warp: no counter movement, no vote
		}
		if !o.DNSProof {
			continue
		}
		q.Valid++
		switch {
		case o.Class == geoClassRU:
			q.AnyRU = true
		case o.Class == geoClassNonRU && o.Country != "":
			counts[o.Country]++
			if ipHash == "" {
				ipHash = o.PublicIPHash
			} else if ipHash != o.PublicIPHash {
				q.IPMismatch = true
			}
		default:
			q.AnyUnknown = true
		}
	}
	for c := range counts {
		q.Countries = append(q.Countries, c)
	}
	sort.Strings(q.Countries)
	q.PublicIPHash = ipHash

	// §44 counts PROVIDERS reporting the SAME country, not distinct
	// countries: "at least 2 providers report same non-RU country".
	sameVotes := 0
	for _, n := range counts {
		if n > sameVotes {
			sameVotes = n
		}
	}

	switch {
	case q.AnyRU:
		q.Verdict = VerdictFailRU
	case len(q.Countries) == 1 && sameVotes >= required && !q.AnyUnknown && !q.IPMismatch:
		q.Verdict = VerdictPassNonRU
		q.Country = q.Countries[0]
	case len(q.Countries) > 1 || q.IPMismatch || (q.AnyUnknown && len(q.Countries) >= 1):
		q.Verdict = VerdictInconclusive
		q.Disagreement = true
	default:
		q.Verdict = VerdictInconclusive
		q.Insufficient = true
	}
	return q
}

// GeoAttestation mirrors src/warp.GeoAttestation (class/providers/quorum/
// public-ip/path/freshness/revoked) plus the generation it was issued for.
type GeoAttestation struct {
	Class             string
	Country           string
	Providers         int
	Quorum            int
	PublicIPHash      string
	PathID            string
	FreshUntil        time.Time
	IssuedAt          time.Time
	SessionGeneration uint64
	Revoked           bool
}

// Valid mirrors src/warp attestationFresh: a current eligible non-RU
// attestation has non-RU class, is not revoked, carries public-ip and path
// identity, and is inside its freshness window.
func (a GeoAttestation) Valid(now time.Time) bool {
	return a.Class == geoClassNonRU && !a.Revoked && a.PublicIPHash != "" && a.PathID != "" &&
		!a.FreshUntil.IsZero() && now.Before(a.FreshUntil)
}
