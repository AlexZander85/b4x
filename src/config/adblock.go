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
	// IPLearn enables kernel-level acceleration of repeat blocks (addendum
	// §BLK-8): the dst-IP of a first SNI block enters the dedicated
	// b4_adblock_learn nft/ipset set whose drop rule sits BEFORE the NFQUEUE
	// capture rule; subsequent connections to that IP die in-kernel.
	IPLearn bool `json:"ip_learn"`
	// IPLearnTTLSec is the lifetime of one learned entry (and its kernel
	// set timeout). Default DefaultIPLearnTTLSec (6h).
	IPLearnTTLSec int `json:"ip_learn_ttl_sec"`
	// IPLearnMaxEntries caps the learned set size; oldest entries are
	// evicted first. Default DefaultIPLearnMaxEntries.
	IPLearnMaxEntries int `json:"ip_learn_max_entries"`
}

// LearnedIPSetV4/V6 are the kernel set names shared by the adblock layer and
// the tables backends (iptables ipset / nftables set).
const (
	LearnedIPSetV4 = "b4_adblock_learn"
	LearnedIPSetV6 = "b4_adblock_learn6"
)

// Ad-block actions (AdBlockConfig.Action).
const (
	// AdBlockActionDrop silently drops the ClientHello/Initial (default):
	// the client sees a connection timeout.
	AdBlockActionDrop = "drop"
	// AdBlockActionRST additionally forges a TCP RST toward the LAN client
	// (seq=clientACK, spoofed from the real server 5-tuple) so the client
	// fails instantly instead of timing out. TCP only — QUIC has no reset
	// and keeps the silent drop.
	AdBlockActionRST = "rst"
)

// ValidAdBlockAction reports whether s is an accepted action value.
func ValidAdBlockAction(s string) bool {
	return s == AdBlockActionDrop || s == AdBlockActionRST
}

// Defaults for the IP-learn sublayer (conservative: off by default).
const (
	DefaultIPLearnTTLSec     = 21600 // 6h
	DefaultIPLearnMaxEntries = 4096
)

// DefaultMaxListEntries is the RAM guard default for MIPS-class devices.
const DefaultMaxListEntries = 300000

// FillDefaults applies zero-value defaults (exported for the adblock layer).
func (a *AdBlockConfig) FillDefaults() {
	if a.Action == "" {
		a.Action = AdBlockActionDrop
	}
	if a.MaxEntries <= 0 {
		a.MaxEntries = DefaultMaxListEntries
	}
	if a.IPLearnTTLSec <= 0 {
		a.IPLearnTTLSec = DefaultIPLearnTTLSec
	}
	if a.IPLearnMaxEntries <= 0 {
		a.IPLearnMaxEntries = DefaultIPLearnMaxEntries
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
