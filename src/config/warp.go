package config

import (
	"fmt"
	"net/netip"
	"strings"

	warp "github.com/daniellavrushin/b4/transport/warp"
)

// DefaultWarpIdentityPath is the on-router location of the engine identity
// store (atomic 0600 writes; the reconciler keeps its cooldown stamps next
// to it as <path>.state). Design: .ag/research/warp-dataplane-design.md SS5.
const DefaultWarpIdentityPath = "/opt/etc/b4/warp/identity.json"

// WarpConfig enables the built-in WARP/MASQUE base transport (design v2;
// E0-E8 engine lives in src/transport/warp). It is DISABLED by default: the
// field layer flips it explicitly on a config COPY (deploy discipline in
// AGENTS.md / PROJECT_DIRECTIVES SS4).
type WarpConfig struct {
	Enabled bool `json:"enabled"`
	// IdentityPath is the engine identity store path. An empty value is
	// filled with DefaultWarpIdentityPath by ApplyConfigDefaults.
	IdentityPath string `json:"identity_path"`
	// Endpoint overrides the catalog-default H2 endpoint ("ip:port").
	// Empty = transportwarp.DefaultH2Endpoint(). Any explicit value must be
	// a member of the versioned endpoint catalog (addendum §34: no
	// arbitrary internet scanning).
	Endpoint string `json:"endpoint"`
	// DeferRevalidation trusts a locally valid stored identity for the first
	// connect without contacting the registration API (field finding:
	// networks that SNI-filter api.cloudflareclient.com deadlock the default
	// Ensure-at-start loop). Revalidation resumes on the normal 24h cadence
	// after the connect. Default false — the strict discipline stays the
	// shipping behavior.
	DeferRevalidation bool `json:"defer_revalidation"`
	// Masquerade is the anti-DPI section for the MASQUE H3 carrier (review
	// chapter 7 of the E-FXVPN review, applied to this transport via the
	// b4x quic-go fork). Zero values keep the vanilla crypto/tls handshake.
	Masquerade WarpMasqueradeConfig `json:"masquerade"`
	// AWG arms the AWG-WARP transport (kind "warp"): one AmneziaWG session
	// over the CF WARP WG edge (tunnels panel stage 2). Independent of the
	// MASQUE branch above: each transport owns its identity slot.
	AWG WarpAWGConfig `json:"awg"`
	// Chains arms the nested compositions (masque+awg, awg+masque) from
	// transport/nested. Each entry owns two DISTINCT identity slots (one CF
	// device per layer, red line #3).
	Chains []WarpChainConfig `json:"chains"`
	// NonRU arms the experimental НЕ РФ mode (addendum §3.2 / ADR-WARP-6):
	// a nested WARP session over THIS base warp, geo-gated by the
	// transport/warp NonRUGate. Requires the base (system.warp.enabled).
	NonRU WarpNonRUConfig `json:"nonru"`
}

// WarpMasqueradeConfig configures the uTLS ClientHello of the MASQUE H3
// carrier. Fingerprint: "chrome120" (recommended — the legitimate WARP
// client is boringssl-based, so the Chrome-shaped hello is the closest
// legal profile), "firefox" (experimental), "" (default — vanilla).
type WarpMasqueradeConfig struct {
	Fingerprint string `json:"fingerprint"`
	// SNI is the cover TLS server-name sent on the MASQUE carrier(s) (both
	// H2/TCP and H3/QUIC — the name is DPI-visible in the TCP ClientHello and
	// in the QUIC Initial). The canonical consumer-masque.cloudflareclient.com
	// name is DPI-flagged in RU: the environment blackholes the flow shortly
	// after establishment once it is seen (field bd b4x-5oy: H3 transport
	// switch at ~0.5-2.3 s, H2 stall on the first large inbound record).
	// Identity binds by public-key pinning, so the SNI is free — any benign
	// hostname works. Empty = DefaultCoverSNI (shipped device default).
	SNI string `json:"sni"`
}

// Validate checks the masquerade section shape (dial-time errors would
// otherwise surface as opaque handshake failures).
func (m WarpMasqueradeConfig) Validate() error {
	switch m.Fingerprint {
	case "", "chrome120", "firefox":
	default:
		return fmt.Errorf("system.warp.masquerade.fingerprint %q invalid (empty, chrome120 or firefox)", m.Fingerprint)
	}
	if m.SNI != "" && !validCoverSNI(m.SNI) {
		return fmt.Errorf("system.warp.masquerade.sni %q invalid (use a DNS hostname)", m.SNI)
	}
	return nil
}

// EffectiveSNI resolves the cover SNI: an explicit value wins, otherwise the
// shipped DefaultCoverSNI (never the canonical MASQUE name — it is a DPI
// fingerprint, see the field note above).
func (m WarpMasqueradeConfig) EffectiveSNI() string {
	if m.SNI != "" {
		return m.SNI
	}
	return warp.DefaultCoverSNI
}

// validCoverSNI accepts a plain DNS hostname (labels of letters/digits/hyphen,
// no leading/trailing dot). Deliberately permissive on underscores.
func validCoverSNI(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return false
		}
	}
	return true
}

// EffectiveEndpoint resolves the configured endpoint against the versioned
// catalog. The zero-value Endpoint maps to the measured default edge; an
// explicit value must pass the InCatalog + KnownPort gates.
func (w *WarpConfig) EffectiveEndpoint() (netip.AddrPort, error) {
	if w.Endpoint == "" {
		return warp.DefaultH2Endpoint(), nil
	}
	ap, err := netip.ParseAddrPort(w.Endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("system.warp.endpoint %q: %v", w.Endpoint, err)
	}
	if !warp.InCatalog(warp.KindMasqueH2, ap.Addr()) {
		return ap, fmt.Errorf("system.warp.endpoint %q: address outside the versioned MASQUE-H2 catalog (addendum SS34)", w.Endpoint)
	}
	if !warp.KnownPort(ap.Port()) {
		return ap, fmt.Errorf("system.warp.endpoint %q: port outside the catalog port set", w.Endpoint)
	}
	return ap, nil
}
