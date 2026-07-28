package config

import "strings"

func (c *Config) validateClassifierRuntimeConfig(v *validator) {
	r := &c.System.Classifier.Runtime
	d := DefaultClassifierRuntimeConfig
	if *r == (ClassifierRuntimeConfig{}) {
		*r = d
	}
	if r.ClientIdentity == (ClientIdentityRuntimeConfig{}) {
		r.ClientIdentity = d.ClientIdentity
	}
	if r.Confidence == (ConfidenceRuntimeConfig{}) {
		r.Confidence = d.Confidence
	}
	if r.Hints == (HintStoreRuntimeConfig{}) {
		r.Hints = d.Hints
	}
	if r.Capture == (CaptureRuntimeConfig{}) {
		r.Capture = d.Capture
	}
	if r.Reassembly == (ReassemblyRuntimeConfig{}) {
		r.Reassembly = d.Reassembly
	}
	if r.HoldReplay == (HoldReplayRuntimeConfig{}) {
		r.HoldReplay = d.HoldReplay
	}
	if r.Actions == (ActionBudgetRuntimeConfig{}) {
		r.Actions = d.Actions
	}
	if r.Discovery == (DiscoveryRuntimeConfig{}) {
		r.Discovery = d.Discovery
	}
	if r.FailureInbox == (FailureInboxRuntimeConfig{}) {
		r.FailureInbox = d.FailureInbox
	}
	if r.ClientHelloLab == (ClientHelloLabRuntimeConfig{}) {
		r.ClientHelloLab = d.ClientHelloLab
	}
	if r.Rollout == (RolloutRuntimeConfig{}) {
		r.Rollout = d.Rollout
	}
	if r.Fallback == (FallbackRuntimeConfig{}) {
		r.Fallback = d.Fallback
	}
	if r.Privacy == (PrivacyRuntimeConfig{}) {
		r.Privacy = d.Privacy
	}

	defaultInt := func(value *int, fallback int) {
		if *value <= 0 {
			*value = fallback
		}
	}
	defaultU32 := func(value *uint32, fallback uint32) {
		if *value == 0 {
			*value = fallback
		}
	}
	defaultU64 := func(value *uint64, fallback uint64) {
		if *value == 0 {
			*value = fallback
		}
	}
	defaultU8 := func(value *uint8, fallback uint8) {
		if *value == 0 {
			*value = fallback
		}
	}
	outOfRange := func(path string, value, min, max int) {
		if value < min || value > max {
			v.addf(path, "out_of_range", map[string]any{"min": min, "max": max}, "value %d must be in [%d,%d]", value, min, max)
		}
	}

	defaultInt(&r.ClientIdentity.MaxEntries, d.ClientIdentity.MaxEntries)
	defaultInt(&r.ClientIdentity.TTLSeconds, d.ClientIdentity.TTLSeconds)
	outOfRange("system.classifier.runtime.client_identity.max_entries", r.ClientIdentity.MaxEntries, 64, 65536)
	outOfRange("system.classifier.runtime.client_identity.ttl_seconds", r.ClientIdentity.TTLSeconds, 5, 3600)

	defaultU8(&r.Confidence.Classify, d.Confidence.Classify)
	defaultU8(&r.Confidence.Mutate, d.Confidence.Mutate)
	defaultU8(&r.Confidence.Destructive, d.Confidence.Destructive)
	defaultU8(&r.Confidence.ProxyFallback, d.Confidence.ProxyFallback)
	if !(r.Confidence.ProxyFallback <= r.Confidence.Classify && r.Confidence.Classify <= r.Confidence.Mutate && r.Confidence.Mutate <= r.Confidence.Destructive && r.Confidence.Destructive <= 100) {
		v.add("system.classifier.runtime.confidence", "invalid_threshold_order", "thresholds must satisfy proxy_fallback <= classify <= mutate <= destructive <= 100", nil)
	}

	defaultInt(&r.Hints.MaxEntries, d.Hints.MaxEntries)
	defaultInt(&r.Hints.MaxEntriesPerClient, d.Hints.MaxEntriesPerClient)
	defaultInt(&r.Hints.MaxCandidatesPerKey, d.Hints.MaxCandidatesPerKey)
	defaultInt(&r.Hints.MaxBytesPerClient, d.Hints.MaxBytesPerClient)
	defaultInt(&r.Hints.DNSMaxTTLSeconds, d.Hints.DNSMaxTTLSeconds)
	defaultInt(&r.Hints.QUICTTLSeconds, d.Hints.QUICTTLSeconds)
	defaultInt(&r.Hints.LearnedTTLSeconds, d.Hints.LearnedTTLSeconds)
	outOfRange("system.classifier.runtime.hints.max_entries", r.Hints.MaxEntries, 64, 65536)
	outOfRange("system.classifier.runtime.hints.max_entries_per_client", r.Hints.MaxEntriesPerClient, 1, 1024)
	outOfRange("system.classifier.runtime.hints.max_candidates_per_key", r.Hints.MaxCandidatesPerKey, 1, 64)
	outOfRange("system.classifier.runtime.hints.max_bytes_per_client", r.Hints.MaxBytesPerClient, 4096, 4*1024*1024)
	outOfRange("system.classifier.runtime.hints.dns_max_ttl_seconds", r.Hints.DNSMaxTTLSeconds, 1, 3600)
	outOfRange("system.classifier.runtime.hints.quic_ttl_seconds", r.Hints.QUICTTLSeconds, 1, 600)
	outOfRange("system.classifier.runtime.hints.learned_ttl_seconds", r.Hints.LearnedTTLSeconds, 1, 600)
	if r.Hints.MaxEntriesPerClient > r.Hints.MaxEntries {
		v.add("system.classifier.runtime.hints.max_entries_per_client", "exceeds_global_limit", "per-client hint limit must not exceed global limit", nil)
	}

	defaultU32(&r.Capture.OutgoingPacketLimit, d.Capture.OutgoingPacketLimit)
	defaultU32(&r.Capture.IncomingPacketLimit, d.Capture.IncomingPacketLimit)
	defaultU32(&r.Capture.ProcessedMarkMask, d.Capture.ProcessedMarkMask)
	if r.Capture.ProcessedMark == 0 {
		r.Capture.ProcessedMark = uint32(c.Queue.Mark) | (1 << 27)
	}
	defaultInt(&r.Capture.CandidateQueueOffset, d.Capture.CandidateQueueOffset)
	defaultInt(&r.Capture.ReadinessTimeoutMS, d.Capture.ReadinessTimeoutMS)
	if r.Capture.OutgoingPacketLimit > 4096 || r.Capture.IncomingPacketLimit > 4096 {
		v.add("system.classifier.runtime.capture", "capture_limit", "capture packet limits must be 1..4096", nil)
	}
	if r.Capture.ProcessedMarkMask&(1<<27) == 0 || r.Capture.ProcessedMark&r.Capture.ProcessedMarkMask == 0 {
		v.add("system.classifier.runtime.capture.processed_mark", "invalid_provenance_mark", "processed mark and mask must reserve the generated-packet provenance bit", nil)
	}
	outOfRange("system.classifier.runtime.capture.candidate_queue_offset", r.Capture.CandidateQueueOffset, 1, 1024)
	outOfRange("system.classifier.runtime.capture.readiness_timeout_ms", r.Capture.ReadinessTimeoutMS, 100, 30000)

	defaultInt(&r.Reassembly.MaxFlows, d.Reassembly.MaxFlows)
	defaultInt(&r.Reassembly.MaxBytesPerFlow, d.Reassembly.MaxBytesPerFlow)
	defaultInt(&r.Reassembly.MaxBytesTotal, d.Reassembly.MaxBytesTotal)
	defaultInt(&r.Reassembly.MaxSegments, d.Reassembly.MaxSegments)
	defaultInt(&r.Reassembly.MaxClientHello, d.Reassembly.MaxClientHello)
	defaultInt(&r.Reassembly.TimeoutMS, d.Reassembly.TimeoutMS)
	outOfRange("system.classifier.runtime.reassembly.max_flows", r.Reassembly.MaxFlows, 1, 16384)
	outOfRange("system.classifier.runtime.reassembly.max_bytes_per_flow", r.Reassembly.MaxBytesPerFlow, 2048, 64*1024)
	outOfRange("system.classifier.runtime.reassembly.max_bytes_total", r.Reassembly.MaxBytesTotal, r.Reassembly.MaxBytesPerFlow, 64*1024*1024)
	outOfRange("system.classifier.runtime.reassembly.max_segments", r.Reassembly.MaxSegments, 2, 256)
	outOfRange("system.classifier.runtime.reassembly.max_client_hello", r.Reassembly.MaxClientHello, 2048, 64*1024)
	outOfRange("system.classifier.runtime.reassembly.timeout_ms", r.Reassembly.TimeoutMS, 100, 30000)
	if r.Reassembly.MaxClientHello > r.Reassembly.MaxBytesPerFlow {
		v.add("system.classifier.runtime.reassembly.max_client_hello", "exceeds_flow_budget", "ClientHello cap must not exceed per-flow reassembly budget", nil)
	}

	defaultInt(&r.HoldReplay.MaxFlows, d.HoldReplay.MaxFlows)
	defaultInt(&r.HoldReplay.MaxPacketsPerFlow, d.HoldReplay.MaxPacketsPerFlow)
	defaultInt(&r.HoldReplay.MaxBytesTotal, d.HoldReplay.MaxBytesTotal)
	defaultInt(&r.HoldReplay.TimeoutMS, d.HoldReplay.TimeoutMS)
	outOfRange("system.classifier.runtime.hold_replay.max_flows", r.HoldReplay.MaxFlows, 1, 4096)
	outOfRange("system.classifier.runtime.hold_replay.max_packets_per_flow", r.HoldReplay.MaxPacketsPerFlow, 1, 64)
	outOfRange("system.classifier.runtime.hold_replay.max_bytes_total", r.HoldReplay.MaxBytesTotal, 4096, 16*1024*1024)
	outOfRange("system.classifier.runtime.hold_replay.timeout_ms", r.HoldReplay.TimeoutMS, 50, 5000)
	if !r.HoldReplay.ReleaseOnPressure {
		v.add("system.classifier.runtime.hold_replay.release_on_pressure", "fail_open_required", "hold/replay must release unchanged packets under pressure", nil)
	}

	defaultInt(&r.Actions.MaxWritesPerHello, d.Actions.MaxWritesPerHello)
	defaultInt(&r.Actions.MaxFakeBytes, d.Actions.MaxFakeBytes)
	if r.Actions.MaxAmplification <= 0 {
		r.Actions.MaxAmplification = d.Actions.MaxAmplification
	}
	outOfRange("system.classifier.runtime.actions.max_writes_per_hello", r.Actions.MaxWritesPerHello, 1, 128)
	outOfRange("system.classifier.runtime.actions.max_fake_bytes", r.Actions.MaxFakeBytes, 1, 1024*1024)
	if r.Actions.MaxAmplification < 1 || r.Actions.MaxAmplification > 16 {
		v.add("system.classifier.runtime.actions.max_amplification", "out_of_range", "amplification must be in [1,16]", map[string]any{"min": 1, "max": 16})
	}

	defaultInt(&r.Discovery.SandboxMaxActive, d.Discovery.SandboxMaxActive)
	defaultInt(&r.Discovery.SandboxMaxEvents, d.Discovery.SandboxMaxEvents)
	defaultInt(&r.Discovery.MaxProbes, d.Discovery.MaxProbes)
	defaultInt(&r.Discovery.MaxConcurrency, d.Discovery.MaxConcurrency)
	defaultInt(&r.Discovery.SamplesPerVariant, d.Discovery.SamplesPerVariant)
	defaultInt(&r.Discovery.StableSuccesses, d.Discovery.StableSuccesses)
	defaultInt(&r.Discovery.MaxShadowProbes, d.Discovery.MaxShadowProbes)
	outOfRange("system.classifier.runtime.discovery.sandbox_max_active", r.Discovery.SandboxMaxActive, 1, 64)
	outOfRange("system.classifier.runtime.discovery.sandbox_max_events", r.Discovery.SandboxMaxEvents, 16, 4096)
	outOfRange("system.classifier.runtime.discovery.max_probes", r.Discovery.MaxProbes, 1, 256)
	outOfRange("system.classifier.runtime.discovery.max_concurrency", r.Discovery.MaxConcurrency, 1, 16)
	outOfRange("system.classifier.runtime.discovery.samples_per_variant", r.Discovery.SamplesPerVariant, 1, 16)
	outOfRange("system.classifier.runtime.discovery.stable_successes", r.Discovery.StableSuccesses, 1, 16)
	outOfRange("system.classifier.runtime.discovery.max_shadow_probes", r.Discovery.MaxShadowProbes, 1, 32)
	if !r.Discovery.NoAutomaticApply {
		v.add("system.classifier.runtime.discovery.no_automatic_apply", "manual_promotion_required", "Discovery results must require explicit canary/promotion", nil)
	}

	defaultInt(&r.FailureInbox.MaxCandidates, d.FailureInbox.MaxCandidates)
	defaultInt(&r.FailureInbox.MaxEvidencePerCandidate, d.FailureInbox.MaxEvidencePerCandidate)
	defaultInt(&r.FailureInbox.MaxSetCandidates, d.FailureInbox.MaxSetCandidates)
	defaultInt(&r.FailureInbox.MaxSignals, d.FailureInbox.MaxSignals)
	defaultInt(&r.FailureInbox.MaxReasons, d.FailureInbox.MaxReasons)
	defaultInt(&r.FailureInbox.RetentionSeconds, d.FailureInbox.RetentionSeconds)
	defaultInt(&r.FailureInbox.MinSYNSentAgeMS, d.FailureInbox.MinSYNSentAgeMS)
	outOfRange("system.classifier.runtime.failure_inbox.max_candidates", r.FailureInbox.MaxCandidates, 1, 4096)
	outOfRange("system.classifier.runtime.failure_inbox.max_evidence_per_candidate", r.FailureInbox.MaxEvidencePerCandidate, 1, 64)
	outOfRange("system.classifier.runtime.failure_inbox.retention_seconds", r.FailureInbox.RetentionSeconds, 10, 86400)

	defaultInt(&r.ClientHelloLab.CaptureDurationSeconds, d.ClientHelloLab.CaptureDurationSeconds)
	defaultInt(&r.ClientHelloLab.MaxFlows, d.ClientHelloLab.MaxFlows)
	defaultInt(&r.ClientHelloLab.MaxProfiles, d.ClientHelloLab.MaxProfiles)
	defaultInt(&r.ClientHelloLab.MaxBytesPerFlow, d.ClientHelloLab.MaxBytesPerFlow)
	defaultInt(&r.ClientHelloLab.MaxBytesTotal, d.ClientHelloLab.MaxBytesTotal)
	defaultInt(&r.ClientHelloLab.MaxSegmentsPerFlow, d.ClientHelloLab.MaxSegmentsPerFlow)
	outOfRange("system.classifier.runtime.clienthello_lab.capture_duration_seconds", r.ClientHelloLab.CaptureDurationSeconds, 1, 300)
	outOfRange("system.classifier.runtime.clienthello_lab.max_flows", r.ClientHelloLab.MaxFlows, 1, 256)
	outOfRange("system.classifier.runtime.clienthello_lab.max_profiles", r.ClientHelloLab.MaxProfiles, 1, 256)
	outOfRange("system.classifier.runtime.clienthello_lab.max_bytes_per_flow", r.ClientHelloLab.MaxBytesPerFlow, 2048, 64*1024)
	outOfRange("system.classifier.runtime.clienthello_lab.max_bytes_total", r.ClientHelloLab.MaxBytesTotal, r.ClientHelloLab.MaxBytesPerFlow, 4*1024*1024)
	outOfRange("system.classifier.runtime.clienthello_lab.max_segments_per_flow", r.ClientHelloLab.MaxSegmentsPerFlow, 2, 256)

	defaultInt(&r.Rollout.LastGoodRetentionHours, d.Rollout.LastGoodRetentionHours)
	defaultInt(&r.Rollout.CanaryDurationSeconds, d.Rollout.CanaryDurationSeconds)
	defaultU8(&r.Rollout.CanaryNewFlowPercent, d.Rollout.CanaryNewFlowPercent)
	defaultU64(&r.Rollout.CanaryMinSamples, d.Rollout.CanaryMinSamples)
	defaultU64(&r.Rollout.CanaryMaxFailures, d.Rollout.CanaryMaxFailures)
	if r.Rollout.CanaryMaxFailureRate <= 0 {
		r.Rollout.CanaryMaxFailureRate = d.Rollout.CanaryMaxFailureRate
	}
	defaultInt(&r.Rollout.CooldownSeconds, d.Rollout.CooldownSeconds)
	outOfRange("system.classifier.runtime.rollout.last_good_retention_hours", r.Rollout.LastGoodRetentionHours, 1, 24*90)
	outOfRange("system.classifier.runtime.rollout.canary_duration_seconds", r.Rollout.CanaryDurationSeconds, 1, 3600)
	if r.Rollout.CanaryNewFlowPercent > 100 {
		v.add("system.classifier.runtime.rollout.canary_new_flow_percent", "out_of_range", "canary percentage must be 1..100", nil)
	}
	if r.Rollout.CanaryMaxFailureRate <= 0 || r.Rollout.CanaryMaxFailureRate > 1 {
		v.add("system.classifier.runtime.rollout.canary_max_failure_rate", "out_of_range", "failure rate must be in (0,1]", nil)
	}
	outOfRange("system.classifier.runtime.rollout.cooldown_seconds", r.Rollout.CooldownSeconds, 1, 86400)
	if !r.Rollout.RequireReadiness {
		v.add("system.classifier.runtime.rollout.require_readiness", "readiness_required", "transactional apply must gate on capture/runtime readiness", nil)
	}

	if r.Fallback.Policy == "" {
		r.Fallback.Policy = d.Fallback.Policy
	}
	defaultU8(&r.Fallback.NativeConfidence, d.Fallback.NativeConfidence)
	defaultInt(&r.Fallback.CooldownSeconds, d.Fallback.CooldownSeconds)
	defaultInt(&r.Fallback.LastGoodTTLSeconds, d.Fallback.LastGoodTTLSeconds)
	defaultInt(&r.Fallback.HealthTTLSeconds, d.Fallback.HealthTTLSeconds)
	defaultInt(&r.Fallback.MaxScopes, d.Fallback.MaxScopes)
	defaultInt(&r.Fallback.MaxIdlePerScope, d.Fallback.MaxIdlePerScope)
	defaultInt(&r.Fallback.MaxUDPSessions, d.Fallback.MaxUDPSessions)
	defaultInt(&r.Fallback.UDPIdleTimeoutSec, d.Fallback.UDPIdleTimeoutSec)
	if r.Fallback.Capabilities == (FallbackCapabilityConfig{}) {
		r.Fallback.Capabilities = d.Fallback.Capabilities
	}
	switch r.Fallback.Policy {
	case FallbackDirect, FallbackGeneric, FallbackProxy:
	default:
		v.add("system.classifier.runtime.fallback.policy", "unsupported_mode", "fallback policy must be direct, generic, or proxy", nil)
	}
	if r.Fallback.Enabled {
		if !c.System.Classifier.Flags.ProxyFallbackEnabled {
			v.add("system.classifier.flags.proxy_fallback_enabled", "flag_required", "proxy fallback runtime requires its feature flag", nil)
		}
		if r.Fallback.Policy != FallbackDirect && (r.Fallback.BypassMark == 0 || r.Fallback.RuleTable <= 0) {
			v.add("system.classifier.runtime.fallback", "route_isolation_required", "generic/proxy fallback requires SO_MARK and rule table isolation", nil)
		}
		if r.Fallback.Policy == FallbackProxy && strings.TrimSpace(r.Fallback.ProxyRouteID) == "" {
			v.add("system.classifier.runtime.fallback.proxy_route_id", "required", "proxy route ID is required", nil)
		}
	}
	outOfRange("system.classifier.runtime.fallback.max_scopes", r.Fallback.MaxScopes, 1, 4096)
	outOfRange("system.classifier.runtime.fallback.max_idle_per_scope", r.Fallback.MaxIdlePerScope, 1, 32)
	outOfRange("system.classifier.runtime.fallback.max_udp_sessions", r.Fallback.MaxUDPSessions, 1, 8192)
	outOfRange("system.classifier.runtime.fallback.udp_idle_timeout_seconds", r.Fallback.UDPIdleTimeoutSec, 1, 300)

	if r.Privacy.TelemetryMode == "" {
		r.Privacy.TelemetryMode = d.Privacy.TelemetryMode
	}
	defaultInt(&r.Privacy.MetadataRetentionHours, d.Privacy.MetadataRetentionHours)
	defaultInt(&r.Privacy.RawCaptureRetentionMinutes, d.Privacy.RawCaptureRetentionMinutes)
	switch r.Privacy.TelemetryMode {
	case PrivacyTelemetryRedacted, PrivacyTelemetryLocal, PrivacyTelemetryOff:
	default:
		v.add("system.classifier.runtime.privacy.telemetry_mode", "unsupported_mode", "telemetry mode must be redacted, local, or off", nil)
	}
	outOfRange("system.classifier.runtime.privacy.metadata_retention_hours", r.Privacy.MetadataRetentionHours, 1, 24*90)
	outOfRange("system.classifier.runtime.privacy.raw_capture_retention_minutes", r.Privacy.RawCaptureRetentionMinutes, 1, 24*60)
	if r.Privacy.AutomaticRawUpload {
		v.add("system.classifier.runtime.privacy.automatic_raw_upload", "unsupported_unsafe", "automatic raw capture upload is forbidden", nil)
	}
	if r.Privacy.IncludeRawInExport && r.Privacy.TelemetryMode != PrivacyTelemetryLocal {
		v.add("system.classifier.runtime.privacy.include_raw_in_export", "privacy_confirmation_required", "raw export is available only in local telemetry mode and still requires an explicit API confirmation", nil)
	}

	optional := r.Strategies.MarkerMultiSplit || r.Strategies.MarkerMultiDisorder || r.Strategies.HostFakeSplit || r.Strategies.FakePayloadCatalog || r.Strategies.FakeDSplit || r.Strategies.FakeDDisorder || r.Strategies.TLSRecordSplit || r.Strategies.ControlledRST
	if optional && (!c.System.Classifier.Flags.ClassifierV2Enabled || !c.System.Classifier.Flags.ActionPlannerV2Enabled || !c.System.Classifier.Flags.TransactionalApplyEnabled) {
		v.add("system.classifier.runtime.strategies", "core_gate_required", "optional strategies require classifier v2, action planner v2, and transactional apply gates", nil)
	}
}
