// Masquerade layer for the Opera reserve transport (review E-OPERA §7,
// stage OP-M0): the anti-DPI discipline that turns the transport from "a
// Go robot talking to a known VPN range" into "browser-shaped TLS".
//
// Mechanisms shipped here:
//
//   - SNI discipline (§7.4.1): the ClientHello carries the REAL node name
//     (a legitimate CDN-class name the Opera browser itself sends) by
//     default; pool mode picks from the white-SNI pool; suppression stays
//     available as the explicit ladder bottom. Pin/WebPKI verification is
//     INDEPENDENT of SNI (7.4.0 invariant) — masquerading never weakens
//     the trust anchors.
//   - ClientHello tuning (§7.4.2a): browser cipher-suite order, browser
//     curve preferences, browser ALPN. This alone does not make JA3 equal
//     Chrome (extension layout stays Go), but it removes the crudest
//     differences and is the base the uTLS layer (OP-M1) builds on.
//   - Session resumption (§7.4.4): a shared ClientSessionCache turns the
//     handshake burst into the browser pattern (few full handshakes, many
//     resumptions). Compatible with pin verification: a session ticket can
//     only exist after a full handshake whose VerifyConnection PASSED, and
//     the cache is keyed per host.
//
// The trust model (§7.4.0 red line) is untouched: VerifyConnection against
// the real node name with the embedded Mozilla/NSS pool remains the only
// anchor for the data plane, the TOFU SPKI pin remains the only anchor for
// the control channel.
package opera

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"strings"
	"sync"
)

// SNIMode selects the ClientHello SNI discipline.
type SNIMode string

const (
	// SNIModeNode sends the real node name (default — review §7.4.1).
	SNIModeNode SNIMode = "node"
	// SNIModePool sends a name from the white-SNI pool (sticky per node).
	SNIModePool SNIMode = "pool"
	// SNIModeNone suppresses the SNI extension (the historical default;
	// the last rung of the masquerade ladder).
	SNIModeNone SNIMode = "none"
)

// MasqueradeProfile selects the ladder step.
type MasqueradeProfile string

const (
	// MasqueradeBrowser: full masquerade (fingerprint + SNI + ALPN +
	// resumption).
	MasqueradeBrowser MasqueradeProfile = "browser"
	// MasqueradeMinimal: SNI discipline only, plain Go TLS (the fallback
	// rung when the fingerprint layer breaks).
	MasqueradeMinimal MasqueradeProfile = "minimal"
	// MasqueradeOff: historical behavior (plain Go TLS, no SNI).
	MasqueradeOff MasqueradeProfile = "off"
)

// MasqueradeSettings is the resolved, engine-side masquerade state. Zero
// values resolve to the browser profile with node SNI.
type MasqueradeSettings struct {
	Profile           MasqueradeProfile
	SNIMode           SNIMode
	SNIPool           []string
	ALPN              []string
	SessionResumption bool
	TTLFake           bool
}

// DefaultMasquerade returns the shipping defaults (review §7.3): browser
// profile, node SNI, browser ALPN, resumption on. The NFQ bait defaults
// off (needs the OUTPUT hook wired — OP-M3).
func DefaultMasquerade() MasqueradeSettings {
	return MasqueradeSettings{
		Profile:           MasqueradeBrowser,
		SNIMode:           SNIModeNode,
		ALPN:              []string{"http/1.1"},
		SessionResumption: true,
	}
}

// ResolveMasquerade folds the config section into engine settings (the
// config layer validates shapes; this layer owns semantics and defaults).
func ResolveMasquerade(profile, sniMode string, sniPool []string, alpn []string, resumption *bool, ttlFake bool) MasqueradeSettings {
	m := DefaultMasquerade()
	switch MasqueradeProfile(strings.ToLower(strings.TrimSpace(profile))) {
	case MasqueradeOff:
		m.Profile = MasqueradeOff
		m.SNIMode = SNIModeNone
		m.SessionResumption = false
		m.ALPN = nil
		return m
	case MasqueradeMinimal:
		m.Profile = MasqueradeMinimal
		m.SessionResumption = false
	case "", MasqueradeBrowser:
		// defaults hold
	default:
		// validated upstream; unknown falls back to browser
	}
	switch SNIMode(strings.ToLower(strings.TrimSpace(sniMode))) {
	case SNIModePool:
		m.SNIMode = SNIModePool
	case SNIModeNone:
		m.SNIMode = SNIModeNone
	case "", SNIModeNode:
		m.SNIMode = SNIModeNode
	}
	if len(sniPool) > 0 {
		m.SNIPool = normalizeSNIPool(sniPool)
		if m.SNIMode != SNIModePool && len(m.SNIPool) > 0 {
			// A configured pool with explicit pool mode absent keeps node
			// mode (the pool is an override for pool mode only).
		}
	}
	if len(alpn) > 0 {
		m.ALPN = alpn
	}
	if resumption != nil {
		m.SessionResumption = *resumption
	}
	if m.Profile == MasqueradeMinimal {
		m.SessionResumption = false
	}
	m.TTLFake = ttlFake
	return m
}

func normalizeSNIPool(pool []string) []string {
	out := make([]string, 0, len(pool))
	seen := make(map[string]struct{}, len(pool))
	for _, n := range pool {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// EffectiveNodeSNI resolves the ClientHello SNI for one node entry
// (review §7.4.1). nodeName is the REAL node name; nodeKey (the node
// IP:port) makes pool picks sticky per node so session resumption stays
// coherent.
func (m MasqueradeSettings) EffectiveNodeSNI(nodeName, nodeKey string) string {
	switch m.SNIMode {
	case SNIModeNone:
		return ""
	case SNIModePool:
		if len(m.SNIPool) == 0 {
			return nodeName
		}
		return m.SNIPool[pickIndex(nodeKey, len(m.SNIPool))]
	default: // node
		return nodeName
	}
}

// EffectiveAPISNI resolves the control-channel SNI (review §7.4.5): the
// real api2.sec-tunnel.com name by default — the TOFU pin is independent
// of SNI, so a pool name is safe here as well.
func (m MasqueradeSettings) EffectiveAPISNI(apiHost string) string {
	switch m.SNIMode {
	case SNIModeNone:
		return ""
	case SNIModePool:
		if len(m.SNIPool) == 0 {
			return apiHost
		}
		return m.SNIPool[pickIndex(apiHost, len(m.SNIPool))]
	default:
		return apiHost
	}
}

// pickIndex is a stable per-key pick (SHA-256 truncated): deterministic,
// uniformly distributed, no time skew.
func pickIndex(key string, n int) int {
	sum := sha256.Sum256([]byte(key))
	return int(binary.BigEndian.Uint32(sum[:4]) % uint32(n))
}

// browserCipherSuites mirrors the Chrome 1.2 offer order (review §7.4.2a).
// TLS 1.3 suites are not configurable in Go and coincide with Chrome.
var browserCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// browserCurves mirrors the Chrome key-share order.
var browserCurves = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
}

// sessionCaches is the shared per-runtime session store factory (§7.4.4):
// one cache per dialer keeps resumption per host while capping memory.
var sessionCaches sync.Pool

// NewSessionCache returns a bounded LRU session cache (Go stdlib).
func NewSessionCache() tls.ClientSessionCache {
	return tls.NewLRUClientSessionCache(32)
}

// applyMasquerade folds the masquerade settings into a tls.Config:
// SNI handling stays with the caller (ServerName semantics differ between
// the data plane — fake-or-real — and pin verification), this applies the
// shared fingerprint/ALPN/resumption knobs.
func (m MasqueradeSettings) applyMasquerade(cfg *tls.Config, sessionCache tls.ClientSessionCache) {
	if cfg == nil {
		return
	}
	if m.Profile != MasqueradeOff {
		cfg.CipherSuites = browserCipherSuites
		cfg.CurvePreferences = browserCurves
	}
	if len(m.ALPN) > 0 {
		cfg.NextProtos = append([]string(nil), m.ALPN...)
	} else {
		cfg.NextProtos = nil
	}
	if m.SessionResumption && sessionCache != nil {
		cfg.ClientSessionCache = sessionCache
	}
}
