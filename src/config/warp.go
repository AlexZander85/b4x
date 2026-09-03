package config

import (
	"fmt"
	"net/netip"

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
}

// WarpMasqueradeConfig configures the uTLS ClientHello of the MASQUE H3
// carrier. Fingerprint: "chrome120" (recommended — the legitimate WARP
// client is boringssl-based, so the Chrome-shaped hello is the closest
// legal profile), "firefox" (experimental), "" (default — vanilla).
type WarpMasqueradeConfig struct {
	Fingerprint string `json:"fingerprint"`
}

// Validate checks the masquerade section shape (dial-time errors would
// otherwise surface as opaque handshake failures).
func (m WarpMasqueradeConfig) Validate() error {
	switch m.Fingerprint {
	case "", "chrome120", "firefox":
		return nil
	default:
		return fmt.Errorf("system.warp.masquerade.fingerprint %q invalid (empty, chrome120 or firefox)", m.Fingerprint)
	}
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
