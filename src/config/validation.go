package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/utils"
)

type ValidationField struct {
	Path    string         `json:"path"`
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Params  map[string]any `json:"params,omitempty"`
}

type ValidationError struct {
	Fields []ValidationField
}

func (e *ValidationError) Error() string {
	if e == nil || len(e.Fields) == 0 {
		return "validation failed"
	}
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Path + ": " + f.Message
	}
	return strings.Join(parts, "; ")
}

type validator struct {
	fields []ValidationField
}

func (v *validator) add(path, code, message string, params map[string]any) {
	v.fields = append(v.fields, ValidationField{Path: path, Code: code, Message: message, Params: params})
}

func (v *validator) addf(path, code string, params map[string]any, format string, args ...any) {
	v.add(path, code, fmt.Sprintf(format, args...), params)
}

func (v *validator) hasErrors() bool {
	return len(v.fields) > 0
}

func (v *validator) result() error {
	if !v.hasErrors() {
		return nil
	}
	out := make([]ValidationField, len(v.fields))
	copy(out, v.fields)
	return &ValidationError{Fields: out}
}

func (c *Config) Validate() error {
	v := &validator{}
	c.validateClassifierConfig(v)
	c.validateWarp(v)
	c.validateOpera(v)
	c.validateProton(v)
	if v.hasErrors() {
		return v.result()
	}
	c.System.WebServer.IsEnabled = c.System.WebServer.Port > 0 && c.System.WebServer.Port <= 65535

	hasCert := c.System.WebServer.TLSCert != ""
	hasKey := c.System.WebServer.TLSKey != ""
	if hasCert != hasKey {
		v.add("system.web_server.tls_cert", "tls_pair_required", "both tls_cert and tls_key must be specified together", nil)
		return v.result()
	}
	if hasCert {
		if _, err := os.Stat(c.System.WebServer.TLSCert); err != nil {
			v.addf("system.web_server.tls_cert", "file_not_found", map[string]any{"path": c.System.WebServer.TLSCert}, "TLS certificate file not found: %s", c.System.WebServer.TLSCert)
			return v.result()
		}
		if _, err := os.Stat(c.System.WebServer.TLSKey); err != nil {
			v.addf("system.web_server.tls_key", "file_not_found", map[string]any{"path": c.System.WebServer.TLSKey}, "TLS key file not found: %s", c.System.WebServer.TLSKey)
			return v.result()
		}
	}

	c.validateAdaptiveDNS(v)

	c.checkPortCollisions(v)
	if v.hasErrors() {
		return v.result()
	}

	if _, err := ParseMemoryLimit(c.System.MemoryLimit); err != nil {
		v.addf("system.memory_limit", "invalid_value", map[string]any{"value": c.System.MemoryLimit}, "%v", err)
		return v.result()
	}

	if c.Queue.TCPConnBytesLimit < DefaultConfig.Queue.TCPConnBytesLimit {
		c.Queue.TCPConnBytesLimit = DefaultConfig.Queue.TCPConnBytesLimit
	} else if c.Queue.TCPConnBytesLimit > 100 {
		c.Queue.TCPConnBytesLimit = 100
	}
	if c.Queue.UDPConnBytesLimit < DefaultConfig.Queue.UDPConnBytesLimit {
		c.Queue.UDPConnBytesLimit = DefaultConfig.Queue.UDPConnBytesLimit
	} else if c.Queue.UDPConnBytesLimit > 30 {
		c.Queue.UDPConnBytesLimit = 30
	}

	if c.System.Geo.GeoSitePath != "" && !filepath.IsAbs(c.System.Geo.GeoSitePath) {
		v.addf("system.geo.sitedat_path", "must_be_absolute", map[string]any{"path": c.System.Geo.GeoSitePath}, "geosite path must be an absolute path (got: %q)", c.System.Geo.GeoSitePath)
		return v.result()
	}
	if c.System.Geo.GeoIpPath != "" && !filepath.IsAbs(c.System.Geo.GeoIpPath) {
		v.addf("system.geo.ipdat_path", "must_be_absolute", map[string]any{"path": c.System.Geo.GeoIpPath}, "geoip path must be an absolute path (got: %q)", c.System.Geo.GeoIpPath)
		return v.result()
	}

	if c.System.Logging.Directory != "" {
		if !filepath.IsAbs(c.System.Logging.Directory) {
			v.addf("system.logging.directory", "must_be_absolute", map[string]any{"path": c.System.Logging.Directory}, "log directory must be an absolute path (got: %q)", c.System.Logging.Directory)
			return v.result()
		}
		c.System.Logging.Directory = filepath.Clean(c.System.Logging.Directory)
	}

	for setIdx, set := range c.Sets {
		if set == nil {
			v.add(fmt.Sprintf("sets[%d]", setIdx), "required", "set must not be null", nil)
			return v.result()
		}
		policy := NormalizeDomainPolicy(set.Targets.DomainPolicy)
		switch policy {
		case DomainPolicyInherit, DomainPolicyStrict, DomainPolicyScopedHints, DomainPolicyLegacy, DomainPolicyDisabled:
		default:
			v.addf(fmt.Sprintf("sets[%d].targets.domain_policy", setIdx), "unsupported_mode", map[string]any{"supported": []DomainPolicy{DomainPolicyInherit, DomainPolicyStrict, DomainPolicyScopedHints, DomainPolicyLegacy, DomainPolicyDisabled}}, "set %q: unsupported domain policy %q", set.Name, set.Targets.DomainPolicy)
			return v.result()
		}
		if UnsafeLegacyDomainScope(c, set) && !c.System.Classifier.UnsafeLegacyDomainScopeOverride {
			v.addf(fmt.Sprintf("sets[%d].targets.domain_policy", setIdx), UnsafeLegacyDomainScopeReason, map[string]any{"set": set.Name, "effective_policy": DomainPolicyLegacy, "suggested_policy": DomainPolicyScopedHints}, "set %q uses unsafe legacy DomainOnly scope with fallback targets and an active action", set.Name)
			return v.result()
		}
		if set.Routing.Table < 0 {
			set.Routing.Table = 0
		}
		if set.Routing.IPTTLSeconds <= 0 {
			set.Routing.IPTTLSeconds = DefaultSetConfig.Routing.IPTTLSeconds
		}
		switch set.Routing.Mode {
		case "":
			set.Routing.Mode = RoutingModeInterface
		case RoutingModeProxy, RoutingModeInterface, RoutingModeMTProtoWS:
		case RoutingModeBlock:
			set.Routing.BlockAction = NormalizeBlockAction(set.Routing.BlockAction)
		default:
			v.addf(fmt.Sprintf("sets[%d].routing.mode", setIdx), "invalid_routing_mode", map[string]any{"set": set.Name, "mode": set.Routing.Mode}, "set %q: unknown routing mode %q", set.Name, set.Routing.Mode)
			return v.result()
		}
		set.Routing.EgressInterface = sanitizeIfaceName(set.Routing.EgressInterface)
		for i, src := range set.Routing.SourceInterfaces {
			set.Routing.SourceInterfaces[i] = sanitizeIfaceName(src)
		}

		if set.Routing.Enabled && set.Routing.Mode == RoutingModeProxy {
			if set.Routing.Upstream.Port < 1 || set.Routing.Upstream.Port > 65535 {
				v.addf(fmt.Sprintf("sets[%d].routing.upstream.port", setIdx), "out_of_range", map[string]any{"set": set.Name, "min": 1, "max": 65535}, "set %q: upstream proxy port must be 1-65535", set.Name)
				return v.result()
			}
			h := strings.ToLower(strings.TrimSpace(set.Routing.Upstream.Host))
			if h == "" {
				h = "127.0.0.1"
			}
			if c.System.Socks5.Enabled && set.Routing.Upstream.Port == c.System.Socks5.Port {
				if h == "127.0.0.1" || h == "::1" || h == "localhost" || h == "0.0.0.0" {
					v.addf(fmt.Sprintf("sets[%d].routing.upstream.port", setIdx), "socks5_loop", map[string]any{"set": set.Name}, "set %q: upstream proxy points to b4's own SOCKS5 server (loop)", set.Name)
					return v.result()
				}
			}
		}

		if set.DNS.Enabled && set.DNS.DoHURL != "" && !strings.HasPrefix(strings.ToLower(set.DNS.DoHURL), "https://") {
			v.addf(fmt.Sprintf("sets[%d].dns.doh_url", setIdx), "doh_url_must_be_https", map[string]any{"set": set.Name}, "set %q: DNS-over-HTTPS URL must start with https://", set.Name)
			return v.result()
		}

		if len(set.Fragmentation.SeqOverlapPattern) > 0 {
			set.Fragmentation.SeqOverlapBytes = make([]byte, len(set.Fragmentation.SeqOverlapPattern))
			for i, s := range set.Fragmentation.SeqOverlapPattern {
				s = strings.TrimPrefix(s, "0x")
				b, _ := strconv.ParseUint(s, 16, 8)
				set.Fragmentation.SeqOverlapBytes[i] = byte(b)
			}
		}

		if set.TCP.Duplicate.Enabled {
			if set.TCP.Duplicate.Count < 1 {
				set.TCP.Duplicate.Count = 1
			}
			if set.TCP.Duplicate.Count > 10 {
				set.TCP.Duplicate.Count = 10
			}
			if len(set.Targets.IPs) == 0 && len(set.Targets.GeoIpCategories) == 0 {
				log.Warnf("Set '%s' has duplication enabled but no IP targets configured", set.Name)
			}
		}

		if set.Targets.DomainOnly && set.Routing.Enabled &&
			(len(set.Targets.SNIDomains) > 0 || len(set.Targets.GeoSiteCategories) > 0) {
			log.Warnf("Set '%s' has both domain-only matching and routing enabled: the IPs behind its domains will not be routed (only explicitly listed IP targets are routed)", set.Name)
		}

		if set.TCP.ConnBytesLimit > c.Queue.TCPConnBytesLimit {
			set.TCP.ConnBytesLimit = c.Queue.TCPConnBytesLimit
		}
		if set.UDP.ConnBytesLimit > c.Queue.UDPConnBytesLimit {
			set.UDP.ConnBytesLimit = c.Queue.UDPConnBytesLimit
		}

		if len(set.Targets.GeoSiteCategories) > 0 && c.System.Geo.GeoSitePath == "" {
			v.add(fmt.Sprintf("sets[%d].targets.geosite_categories", setIdx), "geosite_path_missing", "geosite path must be configured to use geosite categories", nil)
			return v.result()
		}

		if len(set.Targets.GeoIpCategories) > 0 && c.System.Geo.GeoIpPath == "" {
			v.add(fmt.Sprintf("sets[%d].targets.geoip_categories", setIdx), "geoip_path_missing", "geoip path must be configured to use geoip categories", nil)
			return v.result()
		}

		if set.MSSClamp.Enabled {
			if set.MSSClamp.Size <= 0 {
				set.MSSClamp.Size = 88
			} else if set.MSSClamp.Size < 10 {
				set.MSSClamp.Size = 10
			}
			if set.MSSClamp.Size > 1460 {
				set.MSSClamp.Size = 1460
			}
			hasIPScope := len(set.Targets.IPs) > 0 || len(set.Targets.GeoIpCategories) > 0
			hasMACScope := len(set.Targets.SourceDevices) > 0 && !set.Targets.SourceDevicesExclude
			if !hasIPScope && !hasMACScope {
				v.addf(fmt.Sprintf("sets[%d].mss_clamp", setIdx), "mss_clamp_scope_required",
					map[string]any{"set": set.Name},
					"set %q: MSS clamp requires IP, GeoIP, or included source device targets (MSS is set on SYN, before SNI/GeoSite can match; excluded devices cannot scope it)", set.Name)
				return v.result()
			}
		}
	}

	c.sanitizeEscalation()

	// Validate global MSS clamp
	if c.Queue.MSSClamp.Enabled {
		if c.Queue.MSSClamp.Size < 10 {
			c.Queue.MSSClamp.Size = 10
		}
		if c.Queue.MSSClamp.Size > 1460 {
			c.Queue.MSSClamp.Size = 1460
		}
	}

	for i := range c.Queue.Devices.Devices {
		d := &c.Queue.Devices.Devices[i]
		d.MAC = strings.ToUpper(strings.TrimSpace(d.MAC))
		if d.MSSClamp > 0 {
			if d.MSSClamp < 10 {
				d.MSSClamp = 10
			}
			if d.MSSClamp > 1460 {
				d.MSSClamp = 1460
			}
		}
	}

	if c.Queue.Threads < 1 {
		v.add("queue.threads", "out_of_range", "threads must be at least 1", nil)
		return v.result()
	}

	if c.Queue.Mode != "" && c.Queue.Mode != "nfqueue" && c.Queue.Mode != "tun" {
		v.add("queue.mode", "invalid", "queue mode must be 'nfqueue' or 'tun'", nil)
		return v.result()
	}

	if c.Queue.Mode == "tun" {
		const tunReservedMarkBits = uint(engine.TunSteerMark | engine.ClientMark | engine.ReinjectMarkBit)
		if m := c.MainInjectedMark(); m&tunReservedMarkBits != 0 {
			v.addf("queue.mark", "mark_conflict", map[string]any{"mark": fmt.Sprintf("0x%x", m)},
				"queue mark 0x%x overlaps reserved TUN mark bits (0x%x steer, 0x%x client, 0x%x reinject); choose a mark clear of those bits",
				m, uint(engine.TunSteerMark), uint(engine.ClientMark), uint(engine.ReinjectMarkBit))
			return v.result()
		}
	} else if c.System.Tables.Masquerade.Enabled {
		if m := c.MainInjectedMark(); m&uint(engine.ClientMark) != 0 {
			v.addf("queue.mark", "mark_conflict", map[string]any{"mark": fmt.Sprintf("0x%x", m)},
				"queue mark 0x%x overlaps the reserved client mark bit (0x%x) used by NAT masquerade; choose a mark clear of that bit",
				m, uint(engine.ClientMark))
			return v.result()
		}
	}

	if c.Queue.StartNum < 0 || c.Queue.StartNum > 65535 {
		v.add("queue.start_num", "out_of_range", "queue-num must be between 0 and 65535", nil)
		return v.result()
	}

	c.Queue.Mark = c.MainInjectedMark()

	maxMark := uint(^uint32(0))
	if c.Queue.Mark > maxMark {
		v.addf("queue.mark", "out_of_range", map[string]any{"mark": fmt.Sprintf("0x%x", c.Queue.Mark)}, "mark value 0x%x exceeds uint32 max", c.Queue.Mark)
		return v.result()
	}
	if c.Queue.Mark > maxMark-2 && c.System.Checker.DiscoveryFlowMark == 0 {
		v.addf("queue.mark", "out_of_range", map[string]any{"mark": fmt.Sprintf("0x%x", c.Queue.Mark)}, "mark value 0x%x is too high for auto-derived discovery marks", c.Queue.Mark)
		return v.result()
	}

	const perSetReachableBits uint32 = 0x27FFF
	if c.Queue.Mark != 0 && uint32(c.Queue.Mark)&^perSetReachableBits == 0 {
		v.addf("queue.mark", "mark_conflict", map[string]any{"mark": fmt.Sprintf("0x%x", c.Queue.Mark)}, "mark value 0x%x conflicts with per-set mark bits {0-14, 17}; bypass rule would catch TPROXY-redirected traffic. Use a value with at least one bit in {15-16, 18-31} (default 0x8000 has bit 15)", c.Queue.Mark)
		return v.result()
	}

	c.System.Checker.DiscoveryFlowMark = c.DiscoveryFlowMark()
	c.System.Checker.DiscoveryInjectedMark = c.DiscoveryInjectedMark()

	if c.System.Checker.DiscoveryFlowMark > maxMark || c.System.Checker.DiscoveryInjectedMark > maxMark {
		v.add("queue.mark", "out_of_range", "discovery mark values exceed uint32 max", nil)
		return v.result()
	}
	if c.Queue.Mark == c.System.Checker.DiscoveryFlowMark ||
		c.Queue.Mark == c.System.Checker.DiscoveryInjectedMark ||
		c.System.Checker.DiscoveryFlowMark == c.System.Checker.DiscoveryInjectedMark {
		v.add("queue.mark", "mark_conflict", "queue marks must be unique: mark, discovery_flow_mark, discovery_injected_mark", nil)
		return v.result()
	}

	for setIdx, set := range c.Sets {
		if set.Id == "" {
			v.add(fmt.Sprintf("sets[%d].id", setIdx), "required", "each set must have a unique non-empty ID", nil)
			return v.result()
		}

		set.UDP.DPortFilter = utils.ValidatePorts(set.UDP.DPortFilter)
		set.TCP.DPortFilter = utils.ValidatePorts(set.TCP.DPortFilter)
	}

	c.LoadCapturePayloads()
	c.BuildTCPPortMap()
	c.BuildSetPortRanges()

	return v.result()
}

// validateWarp checks the built-in WARP/MASQUE transport section. Disabled
// is the shipping default; an explicit endpoint override is validated even
// when disabled so a typo cannot hide until enable day (field session).
func (c *Config) validateWarp(v *validator) {
	w := c.System.Warp
	if w.Endpoint != "" {
		if _, err := w.EffectiveEndpoint(); err != nil {
			v.add("system.warp.endpoint", "invalid_value", err.Error(), nil)
		}
	}
	if !w.Enabled {
		return
	}
	if w.IdentityPath == "" {
		v.add("system.warp.identity_path", "required", "identity_path must be set when warp is enabled", nil)
		return
	}
	if !filepath.IsAbs(w.IdentityPath) {
		v.addf("system.warp.identity_path", "must_be_absolute", map[string]any{"path": w.IdentityPath}, "warp identity_path must be an absolute path (got: %q)", w.IdentityPath)
	}
}

// validateOpera checks the built-in Opera/SurfEasy reserve section. The
// region whitelist (EU/AS/AM; RU never participates — design red line) and
// the control target shape are validated even when disabled so a typo
// cannot hide until enable day.
func (c *Config) validateOpera(v *validator) {
	o := c.System.Opera
	if o.Region != "" {
		if _, err := operaNormalizeRegion(o.Region); err != nil {
			v.add("system.opera.region", "invalid_value", err.Error(), nil)
		}
	}
	if o.ControlTarget != "" {
		if !operaValidControlTarget(o.ControlTarget) {
			v.addf("system.opera.control_target", "invalid_value", map[string]any{"target": o.ControlTarget},
				"control_target must be host:port (got: %q)", o.ControlTarget)
		}
	}
	if !o.Enabled {
		return
	}
	if o.IdentityPath == "" {
		v.add("system.opera.identity_path", "required", "identity_path must be set when opera is enabled", nil)
		return
	}
	if !filepath.IsAbs(o.IdentityPath) {
		v.addf("system.opera.identity_path", "must_be_absolute", map[string]any{"path": o.IdentityPath}, "opera identity_path must be an absolute path (got: %q)", o.IdentityPath)
	}
}

// validateProton checks the E-PROTON reserve section. The structural fields
// are validated ALWAYS (even when disabled — the warp/opera canon: a typo
// cannot hide until enable day); enabled-only requirements follow the opera
// shape (absolute paths).
func (c *Config) validateProton(v *validator) {
	p := c.System.Proton
	if mode := strings.ToLower(strings.TrimSpace(p.Location.Mode)); mode != "" {
		switch mode {
		case "auto":
		case "country":
			// country code required only when enabled (disabled keeps the
			// honest-shape zero config valid).
			if p.Enabled && strings.TrimSpace(p.Location.Country) == "" {
				v.add("system.proton.location.country", "required", "country is required for mode=country", nil)
			}
		case "host":
			if p.Enabled && strings.TrimSpace(p.Location.Host) == "" {
				v.add("system.proton.location.host", "required", "host is required for mode=host", nil)
			}
		default:
			v.addf("system.proton.location.mode", "invalid_value", map[string]any{"mode": p.Location.Mode},
				"location.mode %q invalid (auto|country|host)", p.Location.Mode)
		}
	}
	if p.Port > 0 && p.Port < 1024 {
		// 443/88/4500 are privileged but legal; only <1024 non-catalog pins
		// are suspicious. Catalog ports are always fine.
		known := false
		for _, port := range []uint16{443, 88, 4500, 500} {
			if p.Port == port {
				known = true
			}
		}
		if !known {
			v.addf("system.proton.port", "invalid_value", map[string]any{"port": p.Port},
				"port %d is privileged and outside the Proton catalog; use 0 for the round-robin catalog", p.Port)
		}
	}
	if p.MTU != 0 && (p.MTU < 576 || p.MTU > 9000) {
		v.addf("system.proton.mtu", "invalid_value", map[string]any{"mtu": p.MTU},
			"mtu %d outside the plausible range [576, 9000]", p.MTU)
	}
	for i, name := range p.Obfuscation.SNIPool {
		if !protonValidSNIName(name) {
			v.addf(fmt.Sprintf("system.proton.obfuscation.sni_pool[%d]", i), "invalid_value",
				map[string]any{"name": name},
				"SNI pool name %q must be a valid hostname and not a Proton domain", name)
		}
	}
	switch prof := strings.ToLower(p.Obfuscation.PreferredProfile); prof {
	case "", "proton-quic", "proton-vanilla", "proton-sip", "proton-crlf":
	default:
		v.addf("system.proton.obfuscation.preferred_profile", "invalid_value",
			map[string]any{"profile": p.Obfuscation.PreferredProfile},
			"preferred_profile %q is not a proton catalog id", p.Obfuscation.PreferredProfile)
	}
	if !p.Enabled {
		return
	}
	if p.EffectiveIdentityPath() != DefaultProtonIdentityPath && !filepath.IsAbs(p.IdentityPath) {
		v.addf("system.proton.identity_path", "must_be_absolute", map[string]any{"path": p.IdentityPath},
			"proton identity_path must be an absolute path (got: %q)", p.IdentityPath)
	}
}

// protonValidSNIName mirrors the engine admission rule without importing the
// proton package (dependency direction: protonservice -> config).
func protonValidSNIName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n == "" || len(n) > 253 || !strings.Contains(n, ".") {
		return false
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	for _, bad := range []string{"proton.me", "protonvpn.ch", "protonmail.ch", "protonpro.xyz", "protonvpn.com", "protonmail.com"} {
		if n == bad || strings.HasSuffix(n, "."+bad) {
			return false
		}
	}
	return true
}

// operaNormalizeRegion mirrors the engine whitelist without importing the
// engine from config (dependency direction: engine -> config).
func operaNormalizeRegion(region string) (string, error) {
	r := strings.ToUpper(strings.TrimSpace(region))
	switch r {
	case "EU", "AS", "AM":
		return r, nil
	default:
		return "", fmt.Errorf("region %q outside megaregion whitelist (EU/AS/AM)", region)
	}
}

func operaValidControlTarget(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return false
	}
	p, err := strconv.Atoi(port)
	return err == nil && p > 0 && p < 65536
}

func (c *Config) validateClassifierConfig(v *validator) {
	classifier := &c.System.Classifier
	defaults := DefaultClassifierConfig
	if classifier.SchemaVersion == 0 {
		classifier.SchemaVersion = defaults.SchemaVersion
	}
	if classifier.APIVersion == "" {
		classifier.APIVersion = defaults.APIVersion
	}
	if classifier.DomainOnlyMode == "" {
		classifier.DomainOnlyMode = defaults.DomainOnlyMode
	}
	if classifier.Flags.TCPReassemblyMode == "" {
		classifier.Flags.TCPReassemblyMode = defaults.Flags.TCPReassemblyMode
	}
	if classifier.Flags.TCPHoldReplayMode == "" {
		if classifier.Flags.AutoHoldReplayEnabled {
			classifier.Flags.TCPHoldReplayMode = HoldReplayAuto
		} else {
			classifier.Flags.TCPHoldReplayMode = defaults.Flags.TCPHoldReplayMode
		}
	}

	if classifier.APIVersion != ClassifierAPIV23 {
		v.addf("system.classifier.api_version", "unsupported_api", map[string]any{"supported": ClassifierAPIV23}, "unsupported classifier API version %q", classifier.APIVersion)
	}
	if classifier.SchemaVersion != ClassifierSchemaV23 {
		v.addf("system.classifier.schema_version", "unsupported_schema", map[string]any{"supported": ClassifierSchemaV23}, "unsupported classifier schema version %d", classifier.SchemaVersion)
	}
	switch classifier.DomainOnlyMode {
	case DomainStrict, DomainScopedHints, DomainLegacy, DomainDisabled:
	default:
		v.addf("system.classifier.domain_only_mode", "unsupported_mode", map[string]any{"supported": []string{DomainStrict, DomainScopedHints, DomainLegacy, DomainDisabled}}, "unsupported DomainOnly mode %q", classifier.DomainOnlyMode)
	}
	switch classifier.Flags.TCPReassemblyMode {
	case ReassemblyOff, ReassemblyObserve:
	default:
		v.addf("system.classifier.flags.tcp_reassembly_mode", "unsupported_mode", map[string]any{"supported": []string{ReassemblyOff, ReassemblyObserve}}, "unsupported TCP reassembly mode %q", classifier.Flags.TCPReassemblyMode)
	}
	switch classifier.Flags.TCPHoldReplayMode {
	case HoldReplayOff, HoldReplayObserve, HoldReplayAuto, HoldReplayDebug:
	default:
		v.addf("system.classifier.flags.tcp_hold_replay_mode", "unsupported_mode", map[string]any{"supported": []string{HoldReplayOff, HoldReplayObserve, HoldReplayAuto, HoldReplayDebug}}, "unsupported TCP hold/replay mode %q", classifier.Flags.TCPHoldReplayMode)
	}
	c.validateClassifierRuntimeConfig(v)
}

func (c *Config) checkPortCollisions(v *validator) {
	type portRef struct {
		path string
		port int
	}
	portRangeParams := map[string]any{"min": 1, "max": 65535}
	var refs []portRef
	if c.System.WebServer.Port > 0 && c.System.WebServer.Port <= 65535 {
		refs = append(refs, portRef{"system.web_server.port", c.System.WebServer.Port})
	}
	if c.System.Socks5.Enabled {
		if c.System.Socks5.Port < 1 || c.System.Socks5.Port > 65535 {
			v.add("system.socks5.port", "out_of_range", "port must be between 1 and 65535", portRangeParams)
		} else {
			refs = append(refs, portRef{"system.socks5.port", c.System.Socks5.Port})
		}
	}
	if c.System.MTProto.Enabled {
		if c.System.MTProto.Port < 1 || c.System.MTProto.Port > 65535 {
			v.add("system.mtproto.port", "out_of_range", "port must be between 1 and 65535", portRangeParams)
		} else {
			refs = append(refs, portRef{"system.mtproto.port", c.System.MTProto.Port})
		}
		switch c.System.MTProto.UpstreamMode {
		case "", "tcp", "ws", "auto":
		default:
			v.addf("system.mtproto.upstream_mode", "invalid_value",
				map[string]any{"value": c.System.MTProto.UpstreamMode, "allowed": []string{"tcp", "ws", "auto"}},
				"upstream_mode must be one of tcp, ws, auto (got %q)", c.System.MTProto.UpstreamMode)
		}
		if h := c.System.MTProto.WSEndpointHost; h != "" {
			if strings.HasPrefix(h, "[") || (strings.Contains(h, ":") && net.ParseIP(h) == nil) {
				v.addf("system.mtproto.ws_endpoint_host", "invalid_host",
					map[string]any{"value": h},
					"ws_endpoint_host must be a host or IP without port (got %q)", h)
			}
		}
		if mc := c.System.MTProto.MaxConnections; mc < 0 || mc > 100000 {
			v.addf("system.mtproto.max_connections", "out_of_range",
				map[string]any{"value": mc, "min": 0, "max": 100000},
				"max_connections must be between 0 (default) and 100000 (got %d)", mc)
		}
		if ut := c.System.MTProto.TCPUserTimeoutSec; ut < -1 || ut > 86400 {
			v.addf("system.mtproto.tcp_user_timeout_sec", "out_of_range",
				map[string]any{"value": ut, "min": -1, "max": 86400},
				"tcp_user_timeout_sec must be -1 (disable), 0 (default 120), or up to 86400 (got %d)", ut)
		}
		if it := c.System.MTProto.IdleTimeoutSec; it < -1 || it > 86400 {
			v.addf("system.mtproto.idle_timeout_sec", "out_of_range",
				map[string]any{"value": it, "min": -1, "max": 86400},
				"idle_timeout_sec must be -1 (disable), 0 (default 300), or up to 86400 (got %d)", it)
		}
	}
	for i := 0; i < len(refs); i++ {
		for j := i + 1; j < len(refs); j++ {
			if refs[i].port == refs[j].port {
				v.addf(refs[j].path, "port_in_use", map[string]any{"port": refs[j].port, "conflict": refs[i].path}, "port %d is already used by %s", refs[j].port, refs[i].path)
			}
		}
	}
}

// validateAdaptiveDNS enforces the adaptive DNS config schema (addendum
// §88/§89). Defaults are safe; invalid modes fail validation instead of
// silently guessing.
func (c *Config) validateAdaptiveDNS(v *validator) {
	mode := c.DNSMode
	if mode == "" {
		mode = "current"
	}
	switch mode {
	case "current", "manual", "adaptive", "diagnostic":
	default:
		v.add("dns_mode", "invalid_value", "dns_mode must be current|manual|adaptive|diagnostic", nil)
		return
	}
	p := c.DNSAdaptive
	if p == nil {
		return
	}
	// Adaptive policy is meaningful only outside current mode; enabling it
	// without switching mode is a config error, not silent no-op.
	if p.Enabled && mode == "current" {
		v.add("dns_adaptive.enabled", "invalid_value", "adaptive policy requires dns_mode=manual|adaptive|diagnostic", nil)
	}
	if p.MaxQuickCandidates <= 0 || p.MaxQuickCandidates > 64 {
		v.add("dns_adaptive.max_quick_candidates", "invalid_value", "must be in [1,64]", nil)
	}
	if p.MaxDeepCandidates <= 0 || p.MaxDeepCandidates > 64 {
		v.add("dns_adaptive.max_deep_candidates", "invalid_value", "must be in [1,64]", nil)
	}
	if p.MaxParallelProbes <= 0 || p.MaxParallelProbes > 16 {
		v.add("dns_adaptive.max_parallel_probes", "invalid_value", "must be in [1,16]", nil)
	}
	if p.Cooldown <= 0 || p.FailedSearchCooldown <= 0 {
		v.add("dns_adaptive.cooldown", "invalid_value", "cooldowns must be positive", nil)
	}
	if p.ProfileTTL <= 0 {
		v.add("dns_adaptive.profile_ttl", "invalid_value", "profile ttl must be positive", nil)
	}
	switch p.Preference {
	case "lowest-latency", "balanced", "privacy", "minimum-dependency", "":
	default:
		v.add("dns_adaptive.preference", "invalid_value", "unknown preference", nil)
	}
}
