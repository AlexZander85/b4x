package config

// DefaultProtonIdentityPath mirrors the warp/opera/fxvpn slot layout on the
// router; the serverlist cache and the TOFU pin store live next to it.
const (
        DefaultProtonIdentityPath = "/opt/etc/b4/proton/identity.json"
)

// ProtonLocation selects the serving scope (E-PROTON design §5):
// "auto" -> all free nodes ranked by load; "country" -> nodes of one
// country; "host" -> the exact node (name or entry IP, validated against
// the cached catalog).
type ProtonLocation struct {
        Mode    string `json:"mode"`
        Country string `json:"country,omitempty"`
        Host    string `json:"host,omitempty"`
}

// ProtonObfuscation tunes the camouflage family (design §3.4).
type ProtonObfuscation struct {
        // Enabled=false forces the proton-vanilla profile (clean WG); the
        // default true starts the ladder at proton-quic.
        Enabled bool `json:"enabled"`
        // PreferredProfile pins the ladder head ("" => proton-quic).
        PreferredProfile string `json:"preferred_profile,omitempty"`
        // SNIPool replaces the embedded white.sni pool WHOLE (owner names);
        // empty => embedded pool. Every name must pass the admission rules
        // (plausible hostname, not a Proton domain).
        SNIPool []string `json:"sni_pool,omitempty"`
        // I1Adaptation re-issues the I1 of DEGRADED profiles with the next pool
        // name (>= 30 min step); a working profile is never touched.
        I1Adaptation bool `json:"i1_adaptation"`
}

// ProtonConfig enables the Proton VPN reserve transport (E-PROTON design;
// engine in src/transport/proton, assembly in src/protonservice).
// DISABLED by default: the field layer flips it explicitly on a config COPY
// (deploy discipline in AGENTS.md).
//
// Role: kind "proton" — a UDP full-scope carrier with geo-exit (the only
// reserve with native UDP egress); priority BELOW AWG-WARP/MASQUE/H3 in
// every selection tree (design §7).
type ProtonConfig struct {
        Enabled bool `json:"enabled"`
        // IdentityPath persists identity.json (0600 atomic, *.corrupt
        // quarantine) — the SINGLE secret slot. Empty => the default path.
        IdentityPath string `json:"identity_path"`
        // Location is the desired serving scope (auto|country|host).
        Location ProtonLocation `json:"location"`
        // Obfuscation selects the AWG camouflage family and the SNI pool.
        Obfuscation ProtonObfuscation `json:"obfuscation"`
        // Port pins ONE WireGuard port for every candidate (0 => the round-robin
        // catalog [443, 88, 1224, 51820, 500, 4500]).
        Port uint16 `json:"port"`
        // MTU of the tunnel device (0 => 1420, the Nova live-verified value).
        MTU int `json:"mtu"`
        // BootstrapThroughCarrier routes the control plane through the active
        // base tunnel when the direct egress cannot reach Proton (design §2).
        BootstrapThroughCarrier bool `json:"bootstrap_through_carrier"`
        // Client version overrides (release-free spoof bumps; "" => Nova
        // defaults of the design §1.1 table).
        UserAgent  string `json:"user_agent,omitempty"`
        AppVersion string `json:"app_version,omitempty"`
        APIVersion string `json:"api_version,omitempty"`
        // MaxRestartsPerHour caps the supervisor rebuilds (0 => 6, the shared
        // transport discipline).
        MaxRestartsPerHour int `json:"max_restarts_per_hour"`
        // TunnelMode selects the data-plane carrier shape (design §7, review
        // P2 stage в): "netstack" (default) — the gVisor userspace stack, the
        // probes/probes+dial shape; "kernel" — a /dev/net/tun device plus PBR
        // policy routing (the full-scope router path; linux only, needs
        // CAP_NET_ADMIN). Any other value fails Build (honest config error).
        TunnelMode string `json:"tunnel_mode,omitempty"`
        // KernelDevice is the TUN interface name hint in kernel mode; empty =>
        // "b4proton0". The PBR pins follow the ACTUAL device name the kernel
        // created (the hint is advisory, the nested/E4 lesson).
        KernelDevice string `json:"kernel_device,omitempty"`
        // RouteMark / RouteTable override the PBR policy-routing IDs of kernel
        // mode (0 => the dedicated defaults 0xB4B4 / 5182 — outside the per-set
        // auto ranges 0x100..0x7EFF / 100..249 and the queue bypass mark, so a
        // collision with the existing scoped-routing machinery is impossible
        // unless the owner overrides into one).
        RouteMark uint32 `json:"route_mark,omitempty"`
        RouteTable int   `json:"route_table,omitempty"`
}

// Tunnel modes of the proton data plane (design §7).
const (
        ProtonTunnelNetstack = "netstack"
        ProtonTunnelKernel   = "kernel"
)

// EffectiveTunnelMode resolves the carrier shape ("netstack" default).
func (p *ProtonConfig) EffectiveTunnelMode() string {
        if p.TunnelMode == ProtonTunnelKernel {
                return ProtonTunnelKernel
        }
        return ProtonTunnelNetstack
}

// EffectiveKernelDevice resolves the kernel-TUN name hint.
func (p *ProtonConfig) EffectiveKernelDevice() string {
        if p.KernelDevice != "" {
                return p.KernelDevice
        }
        return "b4proton0"
}

// EffectiveRouteMark resolves the PBR fwmark of kernel mode.
func (p *ProtonConfig) EffectiveRouteMark() uint32 {
        if p.RouteMark != 0 {
                return p.RouteMark
        }
        return 0xB4B4
}

// EffectiveRouteTable resolves the PBR routing table of kernel mode.
func (p *ProtonConfig) EffectiveRouteTable() int {
        if p.RouteTable > 0 {
                return p.RouteTable
        }
        return 5182
}

// EffectiveIdentityPath resolves the configured path against the default.
func (p *ProtonConfig) EffectiveIdentityPath() string {
        if p.IdentityPath == "" {
                return DefaultProtonIdentityPath
        }
        return p.IdentityPath
}

// EffectiveMTU resolves the tunnel MTU (0 => 1420).
func (p *ProtonConfig) EffectiveMTU() int {
        if p.MTU <= 0 {
                return 1420
        }
        return p.MTU
}

// EffectiveMaxRestarts resolves the supervisor cap (0 => 6).
func (p *ProtonConfig) EffectiveMaxRestarts() int {
        if p.MaxRestartsPerHour <= 0 {
                return 6
        }
        return p.MaxRestartsPerHour
}
