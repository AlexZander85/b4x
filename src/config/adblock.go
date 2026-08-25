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
	// Lists are paths to domain lists (domains or hosts format).
	Lists []string `json:"lists"`
	// Allowlist paths win over blocklists (first match wins).
	Allowlist []string `json:"allowlist"`
	// RefreshHours is the remote-list re-check interval; 0 disables
	// periodic refresh (BLK-5).
	RefreshHours int `json:"refresh_hours"`
	// LogMatches emits a connection-log line per blocked flow.
	LogMatches bool `json:"log_matches"`
	// MaxEntries bounds entries per list (RAM guard for MIPS devices).
	MaxEntries int `json:"max_entries"`
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
