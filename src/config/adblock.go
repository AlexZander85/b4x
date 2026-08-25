package config

import (
	"encoding/json"
	"strings"
)

// AdBlockList is one blocklist source with an individual enable switch.
type AdBlockList struct {
	// Source is a local file path or an http(s):// subscription URL.
	Source string `json:"source"`
	// Enabled=false keeps the source in the config but skips it.
	Enabled bool `json:"enabled"`
}

// UnmarshalJSON accepts both the legacy plain-string form ("path") and the
// structured form {"source":"...","enabled":true} so existing b4.json files
// keep loading after the upgrade.
func (l *AdBlockList) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if strings.HasPrefix(s, "\"") {
		var src string
		if err := json.Unmarshal(data, &src); err != nil {
			return err
		}
		l.Source, l.Enabled = src, true
		return nil
	}
	type alias struct {
		Source  string `json:"source"`
		Enabled *bool  `json:"enabled"`
	}
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	l.Source = a.Source
	l.Enabled = a.Enabled == nil || *a.Enabled
	return nil
}

// AdBlockConfig configures the SNI-based ad/tracker blocking layer
// (B4X_POST_V23_SNI_ADBLOCK_LAYER_ADDENDUM_v1.0.md). The layer decides on
// TLS ClientHello / QUIC Initial hostnames inside the NFQ pipeline and never
// touches DNS.
type AdBlockConfig struct {
	// Enabled turns the layer on. Requires at least one loadable list;
	// enabling without sources activates the built-in default subscriptions
	// (see adblock.DefaultSubscriptions); fail-open red line preserved.
	Enabled bool `json:"enabled"`
	// Action is the block action: "drop" (v1.0 default); "rst" sends a
	// forged TCP RST to the LAN client for instant connection teardown
	// (TCP only; QUIC always drops).
	Action string `json:"action"`
	// Lists are blocklist sources: local paths or http(s):// subscriptions,
	// each individually toggleable via Enabled.
	Lists []AdBlockList `json:"lists"`
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

// ActiveSources returns enabled sources in order (hot-path input).
func (a *AdBlockConfig) ActiveSources() []string {
	out := make([]string, 0, len(a.Lists))
	for _, l := range a.Lists {
		if l.Enabled && l.Source != "" {
			out = append(out, l.Source)
		}
	}
	return out
}

// AllSources returns every configured source regardless of enabled state
// (UI listing).
func (a *AdBlockConfig) AllSources() []string {
	out := make([]string, 0, len(a.Lists))
	for _, l := range a.Lists {
		out = append(out, l.Source)
	}
	return out
}
