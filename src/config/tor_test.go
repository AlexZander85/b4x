package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// TT1 DoD (patch-plan §2): zero-value TorConfig is valid-disabled; every
// enum rejects invalid values with the exact system.tor.<field> code;
// Effective* resolve 0/"" to the design defaults; b4.json without the tor
// key parses as disabled.

func torTestConfig() *Config {
	c := NewConfig()
	return &c
}

func TestTorZeroValueValidDisabled(t *testing.T) {
	c := torTestConfig()
	c.System.Tor = TorConfig{}
	if err := c.Validate(); err != nil {
		t.Fatalf("zero TorConfig must validate (disabled canon): %v", err)
	}
	if c.System.Tor.Enabled {
		t.Fatal("zero TorConfig must be disabled")
	}
}

func TestTorMissingKeyParsesDisabled(t *testing.T) {
	// The real contract: a b4.json without the "tor" key leaves the daemon
	// exactly as before (design §9.4 — no migration needed).
	raw := `{"system": {"web_server": {"port": 8080}}}`
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := doc["tor"]; ok {
		t.Fatal("test fixture must not carry a tor key")
	}
	c := torTestConfig()
	if err := json.Unmarshal([]byte(raw), &c.System); err != nil {
		t.Fatalf("unmarshal system: %v", err)
	}
	if c.System.Tor.Enabled {
		t.Fatal("missing tor key must unmarshal to disabled")
	}
}

func TestTorEntryModeEnum(t *testing.T) {
	valid := []string{"", TorEntryAuto, TorEntryWebtunnel, TorEntryObfs4, TorEntrySnowflake, TorEntryMeek, TorEntryVanilla, TorEntryDirect}
	for _, mode := range valid {
		c := torTestConfig()
		c.System.Tor = TorConfig{Entry: TorEntryConfig{Mode: mode}}
		if err := c.Validate(); err != nil {
			t.Fatalf("entry.mode %q must be valid: %v", mode, err)
		}
	}
	c := torTestConfig()
	c.System.Tor = TorConfig{Entry: TorEntryConfig{Mode: "utopia"}}
	err := c.Validate()
	if err == nil {
		t.Fatal("entry.mode=utopia must fail")
	}
	ve := err.(*ValidationError)
	if len(ve.Fields) != 1 || ve.Fields[0].Path != "system.tor.entry.mode" {
		t.Fatalf("exact field expected, got %+v", ve.Fields)
	}
}

func TestTorEntryModeCaseInsensitive(t *testing.T) {
	c := torTestConfig()
	c.System.Tor = TorConfig{Entry: TorEntryConfig{Mode: "WebTunnel"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("entry.mode WebTunnel must normalize: %v", err)
	}
}

func TestTorRaceWindowRange(t *testing.T) {
	for _, w := range []int{0, 1, 2, 4} {
		c := torTestConfig()
		c.System.Tor = TorConfig{Entry: TorEntryConfig{RaceWindow: w}}
		if err := c.Validate(); err != nil {
			t.Fatalf("race_window %d must be valid: %v", w, err)
		}
	}
	for _, w := range []int{-1, 5, 100} {
		c := torTestConfig()
		c.System.Tor = TorConfig{Entry: TorEntryConfig{RaceWindow: w}}
		err := c.Validate()
		if err == nil {
			t.Fatalf("race_window %d must fail", w)
		}
		if !strings.Contains(err.Error(), "system.tor.entry.race_window") {
			t.Fatalf("race_window %d error must name the field: %v", w, err)
		}
	}
}

func TestTorEgressThroughEnum(t *testing.T) {
	valid := []string{"", TorEgressNone, TorEgressWarp, TorEgressMasque, TorEgressH3, TorEgressOpera, TorEgressFxvpn, TorEgressProton, TorEgressAuto}
	for _, through := range valid {
		c := torTestConfig()
		c.System.Tor = TorConfig{Egress: TorEgressConfig{Through: through}}
		if err := c.Validate(); err != nil {
			t.Fatalf("egress.through %q must be valid: %v", through, err)
		}
	}
	c := torTestConfig()
	c.System.Tor = TorConfig{Egress: TorEgressConfig{Through: "carrier-pigeon"}}
	if err := c.Validate(); err == nil {
		t.Fatal("egress.through=carrier-pigeon must fail")
	} else if !strings.Contains(err.Error(), "system.tor.egress.through") {
		t.Fatalf("must name system.tor.egress.through: %v", err)
	}
}

func TestTorBaitProfileEnum(t *testing.T) {
	for _, bait := range []string{"", TorBaitNone, TorBaitFirstFlight} {
		c := torTestConfig()
		c.System.Tor = TorConfig{Egress: TorEgressConfig{BaitProfile: bait}}
		if err := c.Validate(); err != nil {
			t.Fatalf("bait_profile %q must be valid: %v", bait, err)
		}
	}
	c := torTestConfig()
	c.System.Tor = TorConfig{Egress: TorEgressConfig{BaitProfile: "always"}}
	if err := c.Validate(); err == nil {
		t.Fatal("bait_profile=always must fail (never silent — explicit opt-in only)")
	} else if !strings.Contains(err.Error(), "system.tor.egress.bait_profile") {
		t.Fatalf("must name system.tor.egress.bait_profile: %v", err)
	}
}

func TestTorSpeedEnums(t *testing.T) {
	for _, padding := range []string{"", TorPaddingReduced, TorPaddingFull} {
		c := torTestConfig()
		c.System.Tor = TorConfig{Speed: TorSpeedConfig{Padding: padding}}
		if err := c.Validate(); err != nil {
			t.Fatalf("padding %q must be valid: %v", padding, err)
		}
	}
	for _, conflux := range []string{"", TorConfluxAuto, TorConfluxOff, TorConfluxThroughput, TorConfluxLatency} {
		c := torTestConfig()
		c.System.Tor = TorConfig{Speed: TorSpeedConfig{Conflux: conflux}}
		if err := c.Validate(); err != nil {
			t.Fatalf("conflux %q must be valid: %v", conflux, err)
		}
	}
	for _, isolation := range []string{"", TorIsolationNone, TorIsolationPerDestination} {
		c := torTestConfig()
		c.System.Tor = TorConfig{Speed: TorSpeedConfig{Isolation: isolation}}
		if err := c.Validate(); err != nil {
			t.Fatalf("isolation %q must be valid: %v", isolation, err)
		}
	}
	c := torTestConfig()
	c.System.Tor = TorConfig{Speed: TorSpeedConfig{Padding: "none", Conflux: "turbo", Isolation: "paranoid"}}
	err := c.Validate()
	if err == nil {
		t.Fatal("invalid speed enums must fail")
	}
	ve := err.(*ValidationError)
	paths := map[string]bool{}
	for _, f := range ve.Fields {
		paths[f.Path] = true
	}
	for _, want := range []string{"system.tor.speed.padding", "system.tor.speed.conflux", "system.tor.speed.isolation"} {
		if !paths[want] {
			t.Fatalf("missing field %s in %+v", want, ve.Fields)
		}
	}
}

func TestTorSnowflakeMaxRange(t *testing.T) {
	for _, m := range []int{0, 1, 2, 8} {
		c := torTestConfig()
		c.System.Tor = TorConfig{Speed: TorSpeedConfig{SnowflakeMax: m}}
		if err := c.Validate(); err != nil {
			t.Fatalf("snowflake_max %d must be valid: %v", m, err)
		}
	}
	for _, m := range []int{-1, 9, 100} {
		c := torTestConfig()
		c.System.Tor = TorConfig{Speed: TorSpeedConfig{SnowflakeMax: m}}
		err := c.Validate()
		if err == nil {
			t.Fatalf("snowflake_max %d must fail", m)
		} else if !strings.Contains(err.Error(), "system.tor.speed.snowflake_max") {
			t.Fatalf("must name snowflake_max: %v", err)
		}
	}
}

func TestTorBridgeLineInjectionFloor(t *testing.T) {
	c := torTestConfig()
	c.System.Tor = TorConfig{Bridges: TorBridgesConfig{Lines: []string{
		"obfs4 45.66.35.35:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0",
		"obfs4 1.2.3.4:443 fp\nUseBridges 0",
	}}}
	err := c.Validate()
	if err == nil {
		t.Fatal("bridge line with \\n must fail at the config layer (scenario 3)")
	}
	if !strings.Contains(err.Error(), "system.tor.bridges.lines[1]") {
		t.Fatalf("must name the offending line index: %v", err)
	}

	c2 := torTestConfig()
	c2.System.Tor = TorConfig{Bridges: TorBridgesConfig{Lines: []string{"webtunnel \u00e9 something"}}}
	if err := c2.Validate(); err == nil {
		t.Fatal("non-ASCII bridge line must fail")
	}
}

func TestTorCollectURLs(t *testing.T) {
	c := torTestConfig()
	c.System.Tor = TorConfig{Bridges: TorBridgesConfig{CollectURLs: []string{
		"https://mirror.example/bridges.txt",
		"http://insecure.example/bridges.txt",
		"not a url",
	}}}
	err := c.Validate()
	if err == nil {
		t.Fatal("non-https collect_urls must fail")
	}
	ve := err.(*ValidationError)
	if len(ve.Fields) != 2 {
		t.Fatalf("two URL errors expected (http + garbage), got %+v", ve.Fields)
	}
	for _, f := range ve.Fields {
		if !strings.HasPrefix(f.Path, "system.tor.bridges.collect_urls[") {
			t.Fatalf("unexpected field %s", f.Path)
		}
	}
}

func TestTorEnabledRequiresAbsolutePaths(t *testing.T) {
	c := torTestConfig()
	c.System.Tor = TorConfig{Enabled: true, DataPath: "relative/tor", BinaryPath: "bin/tor"}
	err := c.Validate()
	if err == nil {
		t.Fatal("relative paths must fail when enabled")
	}
	ve := err.(*ValidationError)
	paths := map[string]bool{}
	for _, f := range ve.Fields {
		paths[f.Path] = true
	}
	if !paths["system.tor.data_path"] || !paths["system.tor.binary_path"] {
		t.Fatalf("both path fields expected: %+v", ve.Fields)
	}

	c2 := torTestConfig()
	c2.System.Tor = TorConfig{Enabled: true, DataPath: "/opt/etc/b4/tor", BinaryPath: "/opt/bin/tor"}
	if err := c2.Validate(); err != nil {
		t.Fatalf("absolute paths + enabled must validate: %v", err)
	}
}

func TestTorEnabledValidatedEvenWhenDisabled(t *testing.T) {
	// The canon: a typo cannot hide until enable day — invalid enums fail
	// even with enabled=false.
	c := torTestConfig()
	c.System.Tor = TorConfig{Enabled: false, Entry: TorEntryConfig{Mode: "nope"}}
	if err := c.Validate(); err == nil {
		t.Fatal("invalid enum must fail even when disabled")
	}
}

func TestTorEffectiveDefaults(t *testing.T) {
	var zero TorConfig
	if got := zero.EffectiveEntryMode(); got != TorEntryAuto {
		t.Fatalf("entry mode default = %q, want auto", got)
	}
	if got := zero.EffectiveRaceWindow(); got != 2 {
		t.Fatalf("race window default = %d, want 2", got)
	}
	if got := zero.EffectiveRaceWindow(); got != 2 {
		t.Fatalf("race window default = %d, want 2", got)
	}
	if got := zero.EffectiveBinaryPath(); got != "/opt/bin/tor" {
		t.Fatalf("binary path default = %q, want /opt/bin/tor", got)
	}
	if got := zero.EffectiveDataPath(); got != DefaultTorDataPath {
		t.Fatalf("data path default = %q, want %q", got, DefaultTorDataPath)
	}
	if got := zero.EffectiveCountry(); got != "ru" {
		t.Fatalf("country default = %q, want ru", got)
	}
	if got := zero.EffectiveRecollectPauseSec(); got != 300 {
		t.Fatalf("recollect pause default = %d, want 300", got)
	}
	if got := zero.EffectiveEgressThrough(); got != TorEgressNone {
		t.Fatalf("egress through default = %q, want none", got)
	}
	if got := zero.EffectiveBaitProfile(); got != TorBaitNone {
		t.Fatalf("bait profile default = %q, want none", got)
	}
	if got := zero.EffectiveConflux(); got != TorConfluxAuto {
		t.Fatalf("conflux default = %q, want auto", got)
	}
	if got := zero.EffectivePadding(); got != TorPaddingReduced {
		t.Fatalf("padding default = %q, want reduced", got)
	}
	if got := zero.EffectiveSnowflakeMax(); got != 2 {
		t.Fatalf("snowflake max default = %d, want 2", got)
	}
	if got := zero.EffectiveIsolation(); got != TorIsolationNone {
		t.Fatalf("isolation default = %q, want none", got)
	}
	if got := zero.EffectiveMaxRestartsPerHour(); got != 6 {
		t.Fatalf("restart budget default = %d, want 6", got)
	}
	if got := zero.EffectiveBootstrapTimeoutSec(); got != 180 {
		t.Fatalf("bootstrap timeout default = %d, want 180", got)
	}
	if got := zero.EffectiveScanGoal(); got != 6 {
		t.Fatalf("scan goal default = %d, want 6", got)
	}
	if got := zero.EffectiveScanTimeoutSec(); got != 90 {
		t.Fatalf("scan timeout default = %d, want 90", got)
	}
	ports := zero.EffectiveScanPorts()
	if len(ports) != 2 || ports[0] != 443 || ports[1] != 9001 {
		t.Fatalf("scan ports default = %v, want [443 9001]", ports)
	}
}

func TestTorEffectiveOverridesAndClamps(t *testing.T) {
	cfg := TorConfig{
		BinaryPath:          "/usr/sbin/tor",
		DataPath:            "/custom/tor",
		Entry:               TorEntryConfig{Mode: TorEntryVanilla, RaceWindow: 9},
		Speed:               TorSpeedConfig{SnowflakeMax: 99},
		MaxRestartsPerHour:  12,
		BootstrapTimeoutSec: 240,
	}
	if got := cfg.EffectiveBinaryPath(); got != "/usr/sbin/tor" {
		t.Fatalf("binary path override = %q", got)
	}
	if got := cfg.EffectiveDataPath(); got != "/custom/tor" {
		t.Fatalf("data path override = %q", got)
	}
	if got := cfg.EffectiveEntryMode(); got != TorEntryVanilla {
		t.Fatalf("entry mode override = %q", got)
	}
	if got := cfg.EffectiveRaceWindow(); got != 4 {
		t.Fatalf("race window clamp = %d, want 4", got)
	}
	if got := cfg.EffectiveSnowflakeMax(); got != 8 {
		t.Fatalf("snowflake max clamp = %d, want 8", got)
	}
	if got := cfg.EffectiveMaxRestartsPerHour(); got != 12 {
		t.Fatalf("restart budget override = %d", got)
	}
	if got := cfg.EffectiveBootstrapTimeoutSec(); got != 240 {
		t.Fatalf("bootstrap timeout override = %d", got)
	}
}

// b4x-do17: the autodetect chain must include the Entware /opt/sbin/tor
// location, and an explicit binary_path must pin exactly one candidate.
func TestTorBinaryCandidates(t *testing.T) {
	var zero TorConfig
	got := zero.BinaryCandidates()
	if len(got) != len(DefaultTorBinaryCandidates) || got[0] != "/opt/bin/tor" {
		t.Fatalf("default candidates = %v", got)
	}
	if got[1] != "/opt/sbin/tor" {
		t.Fatalf("Entware /opt/sbin/tor must be in the chain: %v", got)
	}
	// the returned slice must be a copy (no shared-backing mutation)
	got[0] = "/mutated"
	if DefaultTorBinaryCandidates[0] != "/opt/bin/tor" {
		t.Fatal("BinaryCandidates must not expose the default slice backing")
	}
	override := TorConfig{BinaryPath: "/usr/local/bin/tor"}
	if c := override.BinaryCandidates(); len(c) != 1 || c[0] != "/usr/local/bin/tor" {
		t.Fatalf("explicit override candidates = %v", c)
	}
	var nilCfg *TorConfig
	if c := nilCfg.BinaryCandidates(); len(c) != len(DefaultTorBinaryCandidates) {
		t.Fatalf("nil receiver candidates = %v", c)
	}
}

func TestTorNilReceiverSafety(t *testing.T) {
	// torservice projects status through Effective* on nil-safe shapes;
	// the config helpers must not panic on a nil pointer.
	var nilCfg *TorConfig
	if got := nilCfg.EffectiveEntryMode(); got != TorEntryAuto {
		t.Fatalf("nil entry mode = %q", got)
	}
	if got := nilCfg.EffectiveDataPath(); got != DefaultTorDataPath {
		t.Fatalf("nil data path = %q", got)
	}
	if got := nilCfg.EffectiveEgressThrough(); got != TorEgressNone {
		t.Fatalf("nil egress through = %q", got)
	}
	if got := nilCfg.EffectiveBaitProfile(); got != TorBaitNone {
		t.Fatalf("nil bait = %q", got)
	}
}
