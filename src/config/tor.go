package config

// E-TOR: the Tor reserve tunnel (design tor-reserve-design.md §9.4, stage
// TT1 of tor-reserve-patch-plan.md). Role: R-reserve, TCP-only, the LOWEST
// priority in the registry (below proton) + scoped-egress for .onion.
// Never a silent substitute, never a global toggle — the scoped router
// picks tor deliberately per flow.
//
// Zero values are valid-disabled (the program canon): a b4.json without
// the "tor" key unmarshals to the zero TorConfig and the daemon behaves
// exactly as before. Effective*() resolve 0/"" to the design defaults.
const (
	// DefaultTorDataPath mirrors the warp/opera/proton slot layout on the
	// router (design §7.1): /opt/etc/b4/tor holds torrc, data/, bridges.json,
	// entry_memory.txt and the runtime pid file.
	DefaultTorDataPath = "/opt/etc/b4/tor"
)

// Entry modes (design §2): auto races a mixed bridge set and learns the
// winner; the rest pin one transport. direct and meek never join auto.
const (
	TorEntryAuto      = "auto"
	TorEntryWebtunnel = "webtunnel"
	TorEntryObfs4     = "obfs4"
	TorEntrySnowflake = "snowflake"
	TorEntryMeek      = "meek"
	TorEntryVanilla   = "vanilla"
	TorEntryDirect    = "direct"
)

// Egress carrier selection (design §3.3): "none" dials direct (marked),
// a kind name composes Tor inside another reserve, "auto" picks the
// highest-priority registered carrier with failover.
const (
	TorEgressNone   = "none"
	TorEgressWarp   = "warp"
	TorEgressMasque = "masque"
	TorEgressH3     = "h3"
	TorEgressOpera  = "opera"
	TorEgressFxvpn  = "fxvpn"
	TorEgressProton = "proton"
	TorEgressAuto   = "auto"
)

// NFQ bait profile (design §3.4): the anti-DPI engine protects the tunnel's
// own first-flight handshakes (webtunnel/vanilla TLS ClientHello). Never
// enabled silently — an explicit opt-in, announced by an event.
const (
	TorBaitNone        = "none"
	TorBaitFirstFlight = "first-flight"
)

// Connection padding (design §6.6): reduced by default (router speed),
// full is the privacy opt-in with the documented price.
const (
	TorPaddingReduced = "reduced"
	TorPaddingFull    = "full"
)

// Conflux UX (design §6.1): opportunistic parallel legs via SETCONF after
// bootstrap on tor >= 0.4.8; honest degradation when unsupported.
const (
	TorConfluxAuto       = "auto"
	TorConfluxOff        = "off"
	TorConfluxThroughput = "throughput"
	TorConfluxLatency    = "latency"
)

// Stream isolation (design §6.3): the shared circuit pool by default
// (LAN bulk speed); per-destination is the paranoid opt-in (slower).
const (
	TorIsolationNone           = "none"
	TorIsolationPerDestination = "per-destination"
)

// TorEntryConfig selects the bootstrap entry transport and the racing
// window of the auto mixed-set (design §2.1).
type TorEntryConfig struct {
	// Mode is auto|webtunnel|obfs4|snowflake|meek|vanilla|direct; "" => auto.
	Mode string `json:"mode"`
	// RaceWindow caps how many bridge-set heads the mixed-set races in
	// parallel; 0 => 2. Valid 0..4.
	RaceWindow int `json:"race_window,omitempty"`
}

// TorBridgesConfig configures the bridge collection conveyor (design §4.1).
type TorBridgesConfig struct {
	// Lines are owner-provided bridge lines validated by the same parser
	// as everything else (injection-proof, budget 510 bytes).
	Lines []string `json:"lines,omitempty"`
	// BuiltinSnowflake embeds the CDN77/AMP sets compiled into the binary
	// (default true — snowflake needs no collection wait, TOR-1).
	BuiltinSnowflake bool `json:"builtin_snowflake"`
	// CollectURLs are extra OnionHop mirror URLs prepended to the race.
	CollectURLs []string `json:"collect_urls,omitempty"`
	// Country drives Moat and the relay scanner sort ("" => ru).
	Country string `json:"country,omitempty"`
	// RecollectPauseSec bounds re-collection (0 => 300).
	RecollectPauseSec int `json:"recollect_pause_sec,omitempty"`
}

// TorEgressConfig routes ALL tor-egress through the egress bridge dialer
// (design §3): direct (marked) or composed inside another reserve carrier.
type TorEgressConfig struct {
	// Through is ""|none|warp|masque|h3|opera|fxvpn|proton|auto ("" => none).
	Through string `json:"through,omitempty"`
	// BaitProfile is ""|none|first-flight ("" => none). Explicit opt-in;
	// announces itself via tor_bait_active when the tables layer confirms.
	BaitProfile string `json:"bait_profile,omitempty"`
}

// TorSpeedConfig holds the speed-vs-metadata compromises (design §6), each
// documented in the design; defaults favour router throughput.
type TorSpeedConfig struct {
	// Conflux is ""|auto|off|throughput|latency ("" => auto).
	Conflux string `json:"conflux,omitempty"`
	// Padding is ""|reduced|full ("" => reduced).
	Padding string `json:"padding,omitempty"`
	// GeoIP enables GeoIPFile parsing in tor (default false — a client
	// that does not pick exit countries does not need 26 MB of parsing).
	GeoIP bool `json:"geoip"`
	// SnowflakeMax is the number of snowflake peers (0 => 2, range 1..8).
	SnowflakeMax int `json:"snowflake_max,omitempty"`
	// Isolation is ""|none|per-destination ("" => none — shared pool).
	Isolation string `json:"isolation,omitempty"`
}

// TorScopesConfig adds explicit scope suffixes routed to tor in addition to
// .onion, which always goes to tor (design §9.4).
type TorScopesConfig struct {
	// Suffixes are extra destination suffixes for the scoped router.
	Suffixes []string `json:"suffixes,omitempty"`
}

// TorRelayScanConfig bounds the vanilla relay scanner (design §4.3): deep
// probes may look like scanning to an IDS, so everything is capped and the
// whole scanner can be switched off.
type TorRelayScanConfig struct {
	// Enabled runs the background scan (default false; API/CLI can still
	// request an on-demand run).
	Enabled bool `json:"enabled"`
	// Ports filters candidate OR ports (default 443, 9001).
	Ports []int `json:"ports,omitempty"`
	// Countries prioritises (never hard-filters) relay countries.
	Countries []string `json:"countries,omitempty"`
	// Goal is the early-stop count of verified relays (0 => 6).
	Goal int `json:"goal,omitempty"`
	// TimeoutSec is the overall scan budget (0 => 90).
	TimeoutSec int `json:"timeout_sec,omitempty"`
}

// TorConfig enables the E-TOR reserve tunnel. DISABLED by default (ToS
// grey zone + speed honestly below every other reserve — design §0). The
// C-tor binary itself comes from Entware (/opt/bin/tor) or the owner's
// path; its absence is the honest binary-missing state, never an error.
type TorConfig struct {
	Enabled bool `json:"enabled"`
	// BinaryPath is the tor executable; "" => autodetect
	// /opt/bin/tor -> /usr/sbin/tor.
	BinaryPath string `json:"binary_path,omitempty"`
	// DataPath is the state slot; "" => DefaultTorDataPath.
	DataPath string `json:"data_path,omitempty"`
	// Entry selects the bootstrap entry mode.
	Entry TorEntryConfig `json:"entry"`
	// Bridges configures the collection conveyor.
	Bridges TorBridgesConfig `json:"bridges"`
	// Egress routes tor's own outbound connections.
	Egress TorEgressConfig `json:"egress"`
	// Speed holds the documented speed/privacy compromises.
	Speed TorSpeedConfig `json:"speed"`
	// Scopes adds explicit tor scope suffixes (besides .onion).
	Scopes TorScopesConfig `json:"scopes"`
	// RelayScan bounds the vanilla relay scanner.
	RelayScan TorRelayScanConfig `json:"relay_scan"`
	// MaxRestartsPerHour bounds supervisor restarts (0 => 6).
	MaxRestartsPerHour int `json:"max_restarts_per_hour,omitempty"`
	// BootstrapTimeoutSec is the hard bootstrap cap (0 => 180; the
	// snowflake-only entry gets 300 internally).
	BootstrapTimeoutSec int `json:"bootstrap_timeout_sec,omitempty"`
}

// EffectiveEntryMode resolves the entry mode ("" => auto).
func (t *TorConfig) EffectiveEntryMode() string {
	if t == nil || t.Entry.Mode == "" {
		return TorEntryAuto
	}
	return t.Entry.Mode
}

// EffectiveRaceWindow resolves the mixed-set racing heads (0 => 2).
func (t *TorConfig) EffectiveRaceWindow() int {
	if t == nil || t.Entry.RaceWindow <= 0 {
		return 2
	}
	if t.Entry.RaceWindow > 4 {
		return 4
	}
	return t.Entry.RaceWindow
}

// DefaultTorBinaryCandidates is the autodetect chain for the C-Tor
// executable when system.tor.binary_path is unset. Entware on Keenetic
// installs tor as /opt/sbin/tor, not /opt/bin/tor (b4x-do17), so both must
// be probed before the common distro locations.
var DefaultTorBinaryCandidates = []string{
	"/opt/bin/tor",
	"/opt/sbin/tor",
	"/usr/sbin/tor",
	"/usr/bin/tor",
}

// BinaryCandidates resolves the executable search list: an explicit
// binary_path pins exactly one candidate; otherwise the default chain is
// returned in priority order. Nil-safe.
func (t *TorConfig) BinaryCandidates() []string {
	if t != nil && t.BinaryPath != "" {
		return []string{t.BinaryPath}
	}
	return append([]string(nil), DefaultTorBinaryCandidates...)
}

// EffectiveBinaryPath resolves the tor executable autodetect chain. It is
// the FIRST candidate only (the caller stats the list via
// BinaryCandidates); kept for compatibility and status projection.
func (t *TorConfig) EffectiveBinaryPath() string {
	if t != nil && t.BinaryPath != "" {
		return t.BinaryPath
	}
	return DefaultTorBinaryCandidates[0]
}

// EffectiveDataPath resolves the state slot.
func (t *TorConfig) EffectiveDataPath() string {
	if t == nil || t.DataPath == "" {
		return DefaultTorDataPath
	}
	return t.DataPath
}

// EffectiveCountry resolves the Moat/scanner country ("" => ru).
func (t *TorConfig) EffectiveCountry() string {
	if t == nil || t.Bridges.Country == "" {
		return "ru"
	}
	return t.Bridges.Country
}

// EffectiveRecollectPauseSec resolves the re-collection pause (0 => 300).
func (t *TorConfig) EffectiveRecollectPauseSec() int {
	if t == nil || t.Bridges.RecollectPauseSec <= 0 {
		return 300
	}
	return t.Bridges.RecollectPauseSec
}

// EffectiveEgressThrough resolves the carrier policy ("" => none).
func (t *TorConfig) EffectiveEgressThrough() string {
	if t == nil || t.Egress.Through == "" {
		return TorEgressNone
	}
	return t.Egress.Through
}

// EffectiveBaitProfile resolves the NFQ bait profile ("" => none).
func (t *TorConfig) EffectiveBaitProfile() string {
	if t == nil || t.Egress.BaitProfile == "" {
		return TorBaitNone
	}
	return t.Egress.BaitProfile
}

// EffectiveConflux resolves the conflux UX ("" => auto).
func (t *TorConfig) EffectiveConflux() string {
	if t == nil || t.Speed.Conflux == "" {
		return TorConfluxAuto
	}
	return t.Speed.Conflux
}

// EffectivePadding resolves the padding profile ("" => reduced).
func (t *TorConfig) EffectivePadding() string {
	if t == nil || t.Speed.Padding == "" {
		return TorPaddingReduced
	}
	return t.Speed.Padding
}

// EffectiveSnowflakeMax resolves the peer count (0 => 2, clamp 1..8).
func (t *TorConfig) EffectiveSnowflakeMax() int {
	if t == nil || t.Speed.SnowflakeMax <= 0 {
		return 2
	}
	if t.Speed.SnowflakeMax > 8 {
		return 8
	}
	return t.Speed.SnowflakeMax
}

// EffectiveIsolation resolves the stream isolation mode ("" => none).
func (t *TorConfig) EffectiveIsolation() string {
	if t == nil || t.Speed.Isolation == "" {
		return TorIsolationNone
	}
	return t.Speed.Isolation
}

// EffectiveMaxRestartsPerHour resolves the restart budget (0 => 6).
func (t *TorConfig) EffectiveMaxRestartsPerHour() int {
	if t == nil || t.MaxRestartsPerHour <= 0 {
		return 6
	}
	return t.MaxRestartsPerHour
}

// EffectiveBootstrapTimeoutSec resolves the bootstrap cap (0 => 180).
func (t *TorConfig) EffectiveBootstrapTimeoutSec() int {
	if t == nil || t.BootstrapTimeoutSec <= 0 {
		return 180
	}
	return t.BootstrapTimeoutSec
}

// EffectiveScanGoal resolves the relay-scan early-stop goal (0 => 6).
func (t *TorConfig) EffectiveScanGoal() int {
	if t == nil || t.RelayScan.Goal <= 0 {
		return 6
	}
	return t.RelayScan.Goal
}

// EffectiveScanTimeoutSec resolves the relay-scan budget (0 => 90).
func (t *TorConfig) EffectiveScanTimeoutSec() int {
	if t == nil || t.RelayScan.TimeoutSec <= 0 {
		return 90
	}
	return t.RelayScan.TimeoutSec
}

// EffectiveScanPorts resolves the OR-port filter (default 443, 9001).
func (t *TorConfig) EffectiveScanPorts() []int {
	if t == nil || len(t.RelayScan.Ports) == 0 {
		return []int{443, 9001}
	}
	return t.RelayScan.Ports
}
