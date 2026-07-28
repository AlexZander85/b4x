package config

import "strings"

func (s classifierRuntimeValidation) validateFallbackPrivacyStrategies() {
	if s.r.Fallback.Policy == "" {
		s.r.Fallback.Policy = s.d.Fallback.Policy
	}
	s.defaultU8(&s.r.Fallback.NativeConfidence, s.d.Fallback.NativeConfidence)
	s.defaultInt(&s.r.Fallback.CooldownSeconds, s.d.Fallback.CooldownSeconds)
	s.defaultInt(&s.r.Fallback.LastGoodTTLSeconds, s.d.Fallback.LastGoodTTLSeconds)
	s.defaultInt(&s.r.Fallback.HealthTTLSeconds, s.d.Fallback.HealthTTLSeconds)
	s.defaultInt(&s.r.Fallback.MaxScopes, s.d.Fallback.MaxScopes)
	s.defaultInt(&s.r.Fallback.MaxIdlePerScope, s.d.Fallback.MaxIdlePerScope)
	s.defaultInt(&s.r.Fallback.MaxUDPSessions, s.d.Fallback.MaxUDPSessions)
	s.defaultInt(&s.r.Fallback.UDPIdleTimeoutSec, s.d.Fallback.UDPIdleTimeoutSec)
	if s.r.Fallback.Capabilities == (FallbackCapabilityConfig{}) {
		s.r.Fallback.Capabilities = s.d.Fallback.Capabilities
	}
	switch s.r.Fallback.Policy {
	case FallbackDirect, FallbackGeneric, FallbackProxy:
	default:
		s.v.add("system.classifier.runtime.fallback.policy", "unsupported_mode", "fallback policy must be direct, generic, or proxy", nil)
	}
	if s.r.Fallback.Enabled {
		if !s.c.System.Classifier.Flags.ProxyFallbackEnabled {
			s.v.add("system.classifier.flags.proxy_fallback_enabled", "flag_required", "proxy fallback runtime requires its feature flag", nil)
		}
		if s.r.Fallback.Policy != FallbackDirect && (s.r.Fallback.BypassMark == 0 || s.r.Fallback.RuleTable <= 0) {
			s.v.add("system.classifier.runtime.fallback", "route_isolation_required", "generic/proxy fallback requires SO_MARK and rule table isolation", nil)
		}
		if s.r.Fallback.Policy == FallbackProxy && strings.TrimSpace(s.r.Fallback.ProxyRouteID) == "" {
			s.v.add("system.classifier.runtime.fallback.proxy_route_id", "required", "proxy route ID is required", nil)
		}
	}
	s.outOfRange("system.classifier.runtime.fallback.max_scopes", s.r.Fallback.MaxScopes, 1, 4096)
	s.outOfRange("system.classifier.runtime.fallback.max_idle_per_scope", s.r.Fallback.MaxIdlePerScope, 1, 32)
	s.outOfRange("system.classifier.runtime.fallback.max_udp_sessions", s.r.Fallback.MaxUDPSessions, 1, 8192)
	s.outOfRange("system.classifier.runtime.fallback.udp_idle_timeout_seconds", s.r.Fallback.UDPIdleTimeoutSec, 1, 300)

	if s.r.Privacy.TelemetryMode == "" {
		s.r.Privacy.TelemetryMode = s.d.Privacy.TelemetryMode
	}
	s.defaultInt(&s.r.Privacy.MetadataRetentionHours, s.d.Privacy.MetadataRetentionHours)
	s.defaultInt(&s.r.Privacy.RawCaptureRetentionMinutes, s.d.Privacy.RawCaptureRetentionMinutes)
	switch s.r.Privacy.TelemetryMode {
	case PrivacyTelemetryRedacted, PrivacyTelemetryLocal, PrivacyTelemetryOff:
	default:
		s.v.add("system.classifier.runtime.privacy.telemetry_mode", "unsupported_mode", "telemetry mode must be redacted, local, or off", nil)
	}
	s.outOfRange("system.classifier.runtime.privacy.metadata_retention_hours", s.r.Privacy.MetadataRetentionHours, 1, 24*90)
	s.outOfRange("system.classifier.runtime.privacy.raw_capture_retention_minutes", s.r.Privacy.RawCaptureRetentionMinutes, 1, 24*60)
	if s.r.Privacy.AutomaticRawUpload {
		s.v.add("system.classifier.runtime.privacy.automatic_raw_upload", "unsupported_unsafe", "automatic raw capture upload is forbidden", nil)
	}
	if s.r.Privacy.IncludeRawInExport && s.r.Privacy.TelemetryMode != PrivacyTelemetryLocal {
		s.v.add("system.classifier.runtime.privacy.include_raw_in_export", "privacy_confirmation_required", "raw export is available only in local telemetry mode and still requires an explicit API confirmation", nil)
	}

	optional := s.r.Strategies.MarkerMultiSplit || s.r.Strategies.MarkerMultiDisorder || s.r.Strategies.HostFakeSplit || s.r.Strategies.FakePayloadCatalog || s.r.Strategies.FakeDSplit || s.r.Strategies.FakeDDisorder || s.r.Strategies.TLSRecordSplit || s.r.Strategies.ControlledRST
	if optional && (!s.c.System.Classifier.Flags.ClassifierV2Enabled || !s.c.System.Classifier.Flags.ActionPlannerV2Enabled || !s.c.System.Classifier.Flags.TransactionalApplyEnabled) {
		s.v.add("system.classifier.runtime.strategies", "core_gate_required", "optional strategies require classifier v2, action planner v2, and transactional apply gates", nil)
	}
}
