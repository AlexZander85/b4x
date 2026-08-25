package config

// AdBlockConfig configures the SNI-based ad/tracker blocking layer
// (B4X_POST_V23_SNI_ADBLOCK_LAYER_ADDENDUM_v1.0.md). The layer decides on
// TLS ClientHello / QUIC Initial hostnames inside the NFQ pipeline and never
// touches DNS.
type AdBlockConfig struct {
	// Enabled turns the layer on. Requires at least one loadable list;
	// enabling without sources keeps the layer disabled and raises the
	// adblock_list_missing counter (fail-open red line).
	Enabled bool `json:"enabled"`
	// Action is the block action: "drop" (v1.0). "rst" is reserved for a
	// later stage and falls back to "drop".
	Action string `json:"action"`
	// Lists are paths OR http(s):// subscription URLs. URL entries are
	// downloaded into CacheDir and served from there (BLK-5).
	Lists []string `json:"lists"`
	// Allowlist paths win over blocklists (first match wins). Local files
	// only in v1.0.
	Allowlist []string `json:"allowlist"`
	// RefreshHours is the subscription re-check interval; 0 = download only
	// when the cached copy is missing.
	RefreshHours int `json:"refresh_hours"`
	// LogMatches emits a connection-log line per blocked flow.
	LogMatches bool `json:"log_matches"`
	// MaxEntries bounds entries per list (RAM guard for MIPS devices).
	MaxEntries int `json:"max_entries"`
	// CacheDir stores downloaded subscriptions. Empty = "<config dir>/adblock".
	CacheDir string `json:"cache_dir"`
}

// DefaultMaxListEntries is the RAM guard default for MIPS-class devices.
const DefaultMaxListEntries = 300000

// FillDefaults applies zero-value defaults (exported for the adblock layer).
func (a *AdBlockConfig) FillDefaults() {
	if a.Action == "" {
		a.Action = "drop"
	}
	if a.MaxEntries <= 0 {
		a.MaxEntries = DefaultMaxListEntries
	}
}
