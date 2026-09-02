package config

// DefaultFxvpnAccountsPath mirrors the warp/opera slot layout on the router.
const DefaultFxvpnAccountsPath = "/opt/etc/b4/fxvpn/accounts.json"

// FxVPNLocation selects the serving node family (design Дополнение 3).
// Mode "auto" -> REC/CatchAll records; "country" -> Country[/City];
// "host" -> exact server hostname (validated against the cached list).
type FxVPNLocation struct {
        Mode    string `json:"mode"`
        Country string `json:"country,omitempty"`
        City    string `json:"city,omitempty"`
        Host    string `json:"host,omitempty"`
}

// FxVPNMasqueradeConfig configures the anti-DPI masquerade of the fxvpn
// reserve transport (review chapter 7 §7.3 config model; engine side in
// transport/fxvpn/masquerade.go). Zero values resolve to the defaults.
// Red lines (§7.8): the bait never replaces the real handshake and never
// weakens WebPKI/pin verification; TTL bait is UDP-only; nesting announces
// itself; the Mozilla/Fastly control plane gets no extra requests.
type FxVPNMasqueradeConfig struct {
        // Profile selects the ladder step: "firefox" (default — shaped hello
        // + bait when configured), "go-plain" (explicit plain-Go rung),
        // "off" (historical behavior).
        Profile string `json:"profile"`
        // PreflightFake enables the QUIC preflight bait (§7.4.1): 1-2 fake
        // Initials with a white SNI leave a throwaway TTL-limited socket
        // before the real QUIC handshake (H3 carrier). Default false — needs
        // a field-calibrated fake_ttl.
        PreflightFake bool `json:"preflight_fake"`
        // FakeSNI overrides the built-in white-SNI pool (Mozilla-owned names
        // a Firefox install legitimately talks to).
        FakeSNI []string `json:"fake_sni_pool"`
        // FakeTTL is the bait's hop limit (2-8 typical: covers the hops to
        // the DPI but dies before Fastly). Default 4.
        FakeTTL int `json:"fake_ttl"`
        // FakeCount is how many bait datagrams precede the handshake (1-2).
        // Default 2.
        FakeCount int `json:"fake_count"`
        // InitialPadding sets the QUIC InitialPacketSize (Firefox pads to
        // ~1200-1250; engine default 1250 — the constant 1200 was a marker).
        InitialPadding int `json:"initial_padding"`
        // HelloShaping applies the Firefox cipher/curve offer to the plain-Go
        // TLS handshake (H2+QUIC). Nil = enabled for the firefox profile.
        HelloShaping *bool `json:"hello_shaping"`
        // NestOnPortBlock enables the carrier-nesting escalation when the
        // :2499 port/IP block is detected (§7.5, FX-M2). Default false.
        NestOnPortBlock bool `json:"nest_on_port_block"`
}

// FxVPNConfig enables the Firefox VPN reserve transport (E-FXVPN design
// Parts I+II; engine lives in src/transport/fxvpn, assembly in
// src/fxvpservice). DISABLED by default: the field layer flips it explicitly
// on a config COPY (deploy discipline in AGENTS.md).
//
// Role: kind "fxvpn" - a userspace Backend-B style TCP carrier (HTTP(S)
// CONNECT through fastly-masque nodes). The connect dialect is TCP-only by
// protocol; UDP-scope traffic must never be routed here (fail-closed at the
// dialer, honest "tcp-only" in status). Masque/CONNECT-UDP stays a designed
// extension until the production server list carries it.
type FxVPNConfig struct {
        Enabled bool `json:"enabled"`
        // AccountsPath persists accounts.json (0600 atomic, *.corrupt quarantine).
        // Empty value is filled with DefaultFxvpnAccountsPath.
        AccountsPath string `json:"accounts_path"`
        // Location is the desired serving location (auto|country|host).
        Location FxVPNLocation `json:"location"`
        // PreferH3 starts the carrier ladder at QUIC/H3 (falls back to H2 on
        // confirmed transport classes). Default false: H2 first, reference parity.
        PreferH3 bool `json:"prefer_h3"`
        // RotateThresholdPct pre-empts account switch when remaining quota drops
        // below this percentage. 0 => engine default 15.
        RotateThresholdPct int `json:"rotate_threshold_pct"`
        // BootstrapThroughCarrier routes CONTROL-plane requests through the
        // active base tunnel when direct egress cannot reach Mozilla/Fastly
        // (geo/filter resilience, design II.2.2 step 3).
        BootstrapThroughCarrier bool `json:"bootstrap_through_carrier"`
        // ControlTarget overrides the exit-verification probe host ("host:443").
        // Empty => engine default (www.cloudflare.com).
        ControlTarget string `json:"control_target"`
        // Masquerade is the anti-DPI section (review chapter 7 §7.3); zero
        // values resolve to the defaults.
        Masquerade FxVPNMasqueradeConfig `json:"masquerade"`
}

// EffectiveRotateThreshold resolves the configured threshold against the
// engine default (config 0 = unset).
func (f *FxVPNConfig) EffectiveRotateThreshold() int {
        if f.RotateThresholdPct <= 0 || f.RotateThresholdPct > 100 {
                return 15
        }
        return f.RotateThresholdPct
}
