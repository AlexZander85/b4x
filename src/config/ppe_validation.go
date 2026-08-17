package config

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func (c *Config) validatePPEConfig(v *validator) {
	capture := &c.System.Classifier.Runtime.Capture
	defaults := DefaultClassifierRuntimeConfig.Capture
	if capture.OffloadPolicy == "" {
		capture.OffloadPolicy = defaults.OffloadPolicy
	}
	if isZeroPPEConfig(capture.PPE) {
		capture.PPE = clonePPEConfig(defaults.PPE)
	}
	ppe := &capture.PPE
	if ppe.IPv4 == "" {
		ppe.IPv4 = defaults.PPE.IPv4
	}
	if ppe.IPv6 == "" {
		ppe.IPv6 = defaults.PPE.IPv6
	}
	if ppe.SourceScope == "" {
		ppe.SourceScope = defaults.PPE.SourceScope
	}
	if ppe.ConnskipPackets == 0 {
		ppe.ConnskipPackets = defaults.PPE.ConnskipPackets
	}
	if ppe.ReassertIntervalSec == 0 {
		ppe.ReassertIntervalSec = defaults.PPE.ReassertIntervalSec
	}
	if ppe.SelfTest.Mode == "" {
		ppe.SelfTest.Mode = defaults.PPE.SelfTest.Mode
	}
	if ppe.SelfTest.TimeoutMS == 0 {
		ppe.SelfTest.TimeoutMS = defaults.PPE.SelfTest.TimeoutMS
	}
	ppe.TCPPorts = normalizePPEPorts(ppe.TCPPorts)
	ppe.UDPPorts = normalizePPEPorts(ppe.UDPPorts)
	if len(ppe.TCPPorts) == 0 {
		ppe.TCPPorts = append([]uint16(nil), defaults.PPE.TCPPorts...)
	}
	if len(ppe.UDPPorts) == 0 {
		ppe.UDPPorts = append([]uint16(nil), defaults.PPE.UDPPorts...)
	}

	switch capture.OffloadPolicy {
	case OffloadPolicyDetect, OffloadPolicyExclude, OffloadPolicyDisableGlobal:
	default:
		v.add("system.classifier.runtime.capture.offload_policy", "unsupported_mode", "offload policy must be detect, exclude, or disable-global", nil)
	}
	for path, value := range map[string]string{
		"system.classifier.runtime.capture.ppe.ipv4": ppe.IPv4,
		"system.classifier.runtime.capture.ppe.ipv6": ppe.IPv6,
	} {
		switch value {
		case PPEFamilyAuto, PPEFamilyOn, PPEFamilyOff:
		default:
			v.add(path, "unsupported_mode", "PPE family mode must be auto, on, or off", nil)
		}
	}
	switch ppe.SourceScope {
	case PPESourceManagedDevices, PPESourceAllForwarded:
	default:
		v.add("system.classifier.runtime.capture.ppe.source_scope", "unsupported_scope", "PPE source scope must be managed-devices or all-forwarded", nil)
	}
	if ppe.ConnskipPackets < 2 || ppe.ConnskipPackets > 512 {
		v.addf("system.classifier.runtime.capture.ppe.connskip_packets", "out_of_range", map[string]any{"min": 2, "max": 512}, "connskip window %d must be in [2,512]", ppe.ConnskipPackets)
	}
	if ppe.ReassertIntervalSec < 10 || ppe.ReassertIntervalSec > 3600 {
		v.addf("system.classifier.runtime.capture.ppe.reassert_interval_sec", "out_of_range", map[string]any{"min": 10, "max": 3600}, "reassert interval %d must be in [10,3600]", ppe.ReassertIntervalSec)
	}
	if ppe.TCPEnabled && len(ppe.TCPPorts) == 0 {
		v.add("system.classifier.runtime.capture.ppe.tcp_ports", "required", "TCP PPE exclusion requires at least one port", nil)
	}
	if ppe.QUICEnabled && len(ppe.UDPPorts) == 0 {
		v.add("system.classifier.runtime.capture.ppe.udp_ports", "required", "QUIC PPE exclusion requires at least one port", nil)
	}
	switch ppe.SelfTest.Mode {
	case PPESelfTestStartupAndChange, PPESelfTestManual, PPESelfTestOff:
	default:
		v.add("system.classifier.runtime.capture.ppe.self_test.mode", "unsupported_mode", "self-test mode must be startup-and-change, manual, or off", nil)
	}
	if ppe.SelfTest.TimeoutMS < 250 || ppe.SelfTest.TimeoutMS > 60000 {
		v.addf("system.classifier.runtime.capture.ppe.self_test.timeout_ms", "out_of_range", map[string]any{"min": 250, "max": 60000}, "self-test timeout %d must be in [250,60000]", ppe.SelfTest.TimeoutMS)
	}
	if endpoint := strings.TrimSpace(ppe.SelfTest.ControlledEndpoint); endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme == "" || u.Host == "" {
			v.add("system.classifier.runtime.capture.ppe.self_test.controlled_endpoint", "invalid_url", fmt.Sprintf("invalid controlled endpoint %q", endpoint), nil)
		}
	}
	if endpoint := strings.TrimSpace(ppe.SelfTest.HealthEndpoint); endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme == "" || u.Host == "" {
			v.add("system.classifier.runtime.capture.ppe.self_test.health_endpoint", "invalid_url", fmt.Sprintf("invalid health endpoint %q", endpoint), nil)
		}
	}
	if capture.OffloadPolicy == OffloadPolicyDisableGlobal {
		// This remains an explicit advanced/debug choice. Validation preserves it,
		// but runtime code must never select it as a fallback automatically.
		if ppe.SourceScope != PPESourceAllForwarded {
			v.add("system.classifier.runtime.capture.ppe.source_scope", "global_scope_required", "disable-global requires explicit all-forwarded scope acknowledgement", nil)
		}
	}
}

func clonePPEConfig(in PPEOffloadConfig) PPEOffloadConfig {
	out := in
	out.TCPPorts = append([]uint16(nil), in.TCPPorts...)
	out.UDPPorts = append([]uint16(nil), in.UDPPorts...)
	return out
}

func normalizePPEPorts(in []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(in))
	out := make([]uint16, 0, len(in))
	for _, port := range in {
		if port == 0 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func isZeroPPEConfig(in PPEOffloadConfig) bool {
	return !in.TCPEnabled && !in.QUICEnabled && len(in.TCPPorts) == 0 && len(in.UDPPorts) == 0 &&
		in.ConnskipPackets == 0 && in.IPv4 == "" && in.IPv6 == "" && in.SourceScope == "" &&
		in.ReassertIntervalSec == 0 && in.SelfTest == (PPESelfTestConfig{})
}
