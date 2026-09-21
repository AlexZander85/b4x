package config

// DefaultVLESSIdentityPath mirrors the warp/wg/opera slot layout on the router
// (design §6). The identity slot doubles as the parent directory of the node
// cache (last-good online assets).
const DefaultVLESSIdentityPath = "/opt/etc/b4/vless/identity.json"

// VLESS helper kinds (design §3.1/§12.1). xray is the shipping default — the
// public vless:// corpus is Xray-oriented and MPL-2.0 is softer to ship.
const (
	VLESSHelperXray     = "xray"
	VLESSHelperSingbox  = "sing-box"
	VLESSHelperExternal = "external"
)

// VLESS client modes (design §8, phase V4: in-process client). "auto" prefers
// the in-process implementation for the transports it carries (raw/tcp, ws,
// httpupgrade over none/tls/reality) and falls back to the external helper for
// grpc/xhttp/kcp/quic.
const (
	VLESSClientAuto      = "auto"
	VLESSClientInProcess = "in-process"
	VLESSClientHelper    = "helper"
)

// VLESSConfig field defaults resolved when a field is left empty/zero.
const (
	DefaultVLESSSocksAddr               = "127.0.0.1:1081"
	DefaultVLESSSubscriptionIntervalSec = 21600
	DefaultVLESSControlTarget           = "www.cloudflare.com"
	DefaultVLESSMaxRestartsPerHour      = 6
	DefaultVLESSSeekIntervalSec         = 300
	DefaultVLESSSeekToleranceMs         = 50
)

// VLESSConfig enables the VLESS(+REALITY) reserve transport (design
// .ag/research/vless-tunnel-design.md §6). It is DISABLED by default: the
// field layer flips it on a config COPY.
//
// Role in the architecture: kind "vless" — a TCP-only userspace carrier that
// dials the local SOCKS5 inbound of an EXTERNAL helper (xray/sing-box). b4x
// never implements VLESS itself and never vendors the helper (quic-go clash);
// V1 renders/validates/stores nodes and carries TCP. The helper lifecycle is
// V2 (helper_manage), UDP is V3.
//
// The three *bool fields are tri-state on purpose: nil means "unset" so the
// documented default (true) can be honoured while an explicit `false` in JSON
// still wins (the opera.SessionResumption pattern).
type VLESSConfig struct {
	Enabled bool `json:"enabled"`
	// Client selects who speaks VLESS: auto (default) | in-process | helper.
	Client string `json:"client"`
	// Helper selects the external helper: xray|sing-box|external ("" => xray).
	Helper string `json:"helper"`
	// HelperPath is the helper binary ("" => search PATH). Used by V2 spawn.
	HelperPath string `json:"helper_path"`
	// HelperManage: b4x spawns/supervises the helper (default true). V1 does
	// not spawn regardless; V2 consumes it. false = operator-managed helper.
	HelperManage *bool `json:"helper_manage"`
	// SocksAddr is the helper's local SOCKS5 inbound (host:port).
	SocksAddr string `json:"socks_addr"`
	// Nodes are inline vless:// links or sing-box outbound JSON objects.
	Nodes []string `json:"nodes"`
	// BundledSources pulls the built-in curated aggregator list (default true).
	BundledSources *bool `json:"bundled_sources"`
	// Subscriptions are the operator's own subscription URLs (extra to bundled).
	Subscriptions []string `json:"subscriptions"`
	// SubscriptionIntervalSec is the refresh period (jitter + conditional GET).
	SubscriptionIntervalSec int `json:"subscription_interval_sec"`
	// NodeCachePath persists the last-good node list ("" => next to the slot).
	NodeCachePath string `json:"node_cache_path"`
	// IdentityPath is the config/cache slot root (like opera).
	IdentityPath string `json:"identity_path"`
	// ControlTarget is the health-probe CONNECT target ("host:port").
	ControlTarget string `json:"control_target"`
	// PreferNonRU filters selection to non-RU egress (default true; V2 seek).
	PreferNonRU *bool `json:"prefer_nonru"`
	// CountryAllow/CountryDeny are server-IP geo allow/deny lists (ISO codes).
	CountryAllow []string `json:"country_allow"`
	CountryDeny  []string `json:"country_deny"`
	// MaxRestartsPerHour caps helper restarts (V2 supervisor).
	MaxRestartsPerHour int `json:"max_restarts_per_hour"`
	// SeekIntervalSec is the node-probe cadence (V2 seek).
	SeekIntervalSec int `json:"seek_interval_sec"`
	// SeekToleranceMs stops rotation for a marginal latency win (URLTest).
	SeekToleranceMs int `json:"seek_tolerance_ms"`
	// PinNode forces selection to one node ("host:port"); empty = free seek.
	PinNode string `json:"pin_node"`
	// UDP enables UDP ASSOCIATE through the helper's SOCKS5 (V3). Only
	// meaningful with client=helper; the in-process client is stream-only.
	UDP bool `json:"udp"`
	// Mixed uses a single-port SOCKS+HTTP inbound (V3). sing-box has a native
	// "mixed" inbound; Xray does not, so mixed requires helper=sing-box
	// (validated early, refused at render otherwise).
	Mixed bool `json:"mixed"`
}

// WithDefaults returns a copy with the documented defaults applied to empty
// fields. Callers use it at assembly time (proton/tor pattern).
func (c VLESSConfig) WithDefaults() VLESSConfig {
	if c.Client == "" {
		c.Client = VLESSClientAuto
	}
	if c.Helper == "" {
		c.Helper = VLESSHelperXray
	}
	if c.SocksAddr == "" {
		c.SocksAddr = DefaultVLESSSocksAddr
	}
	if c.IdentityPath == "" {
		c.IdentityPath = DefaultVLESSIdentityPath
	}
	if c.ControlTarget == "" {
		c.ControlTarget = DefaultVLESSControlTarget
	}
	if c.SubscriptionIntervalSec == 0 {
		c.SubscriptionIntervalSec = DefaultVLESSSubscriptionIntervalSec
	}
	if c.MaxRestartsPerHour == 0 {
		c.MaxRestartsPerHour = DefaultVLESSMaxRestartsPerHour
	}
	if c.SeekIntervalSec == 0 {
		c.SeekIntervalSec = DefaultVLESSSeekIntervalSec
	}
	if c.SeekToleranceMs == 0 {
		c.SeekToleranceMs = DefaultVLESSSeekToleranceMs
	}
	if c.HelperManage == nil {
		c.HelperManage = boolPtr(true)
	}
	if c.BundledSources == nil {
		c.BundledSources = boolPtr(true)
	}
	if c.PreferNonRU == nil {
		c.PreferNonRU = boolPtr(true)
	}
	return c
}

// ManageHelper reports the effective helper_manage (default true).
func (c VLESSConfig) ManageHelper() bool { return c.HelperManage == nil || *c.HelperManage }

// BundledSourcesEnabled reports the effective bundled_sources (default true).
func (c VLESSConfig) BundledSourcesEnabled() bool {
	return c.BundledSources == nil || *c.BundledSources
}

// PreferNonRUEnabled reports the effective prefer_nonru (default true).
func (c VLESSConfig) PreferNonRUEnabled() bool {
	return c.PreferNonRU == nil || *c.PreferNonRU
}

// EffectiveNodeCachePath is the node cache location: the configured path or
// "nodes.json" next to the identity slot.
func (c VLESSConfig) EffectiveNodeCachePath() string {
	if c.NodeCachePath != "" {
		return c.NodeCachePath
	}
	dir := c.IdentityPath
	if i := lastSlash(dir); i >= 0 {
		dir = dir[:i]
	}
	if dir == "" {
		dir = "/opt/etc/b4/vless"
	}
	return dir + "/nodes.json"
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' || s[i] == '\\' {
			return i
		}
	}
	return -1
}

func boolPtr(b bool) *bool { return &b }
