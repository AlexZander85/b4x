package config

func (s classifierRuntimeValidation) validateDiscoveryLabRollout() {
	s.defaultInt(&s.r.Discovery.SandboxMaxActive, s.d.Discovery.SandboxMaxActive)
	s.defaultInt(&s.r.Discovery.SandboxMaxEvents, s.d.Discovery.SandboxMaxEvents)
	s.defaultInt(&s.r.Discovery.MaxProbes, s.d.Discovery.MaxProbes)
	s.defaultInt(&s.r.Discovery.MaxConcurrency, s.d.Discovery.MaxConcurrency)
	s.defaultInt(&s.r.Discovery.SamplesPerVariant, s.d.Discovery.SamplesPerVariant)
	s.defaultInt(&s.r.Discovery.StableSuccesses, s.d.Discovery.StableSuccesses)
	s.defaultInt(&s.r.Discovery.MaxShadowProbes, s.d.Discovery.MaxShadowProbes)
	s.outOfRange("system.classifier.runtime.discovery.sandbox_max_active", s.r.Discovery.SandboxMaxActive, 1, 64)
	s.outOfRange("system.classifier.runtime.discovery.sandbox_max_events", s.r.Discovery.SandboxMaxEvents, 16, 4096)
	s.outOfRange("system.classifier.runtime.discovery.max_probes", s.r.Discovery.MaxProbes, 1, 256)
	s.outOfRange("system.classifier.runtime.discovery.max_concurrency", s.r.Discovery.MaxConcurrency, 1, 16)
	s.outOfRange("system.classifier.runtime.discovery.samples_per_variant", s.r.Discovery.SamplesPerVariant, 1, 16)
	s.outOfRange("system.classifier.runtime.discovery.stable_successes", s.r.Discovery.StableSuccesses, 1, 16)
	s.outOfRange("system.classifier.runtime.discovery.max_shadow_probes", s.r.Discovery.MaxShadowProbes, 1, 32)
	if !s.r.Discovery.NoAutomaticApply {
		s.v.add("system.classifier.runtime.discovery.no_automatic_apply", "manual_promotion_required", "Discovery results must require explicit canary/promotion", nil)
	}

	s.defaultInt(&s.r.FailureInbox.MaxCandidates, s.d.FailureInbox.MaxCandidates)
	s.defaultInt(&s.r.FailureInbox.MaxEvidencePerCandidate, s.d.FailureInbox.MaxEvidencePerCandidate)
	s.defaultInt(&s.r.FailureInbox.MaxSetCandidates, s.d.FailureInbox.MaxSetCandidates)
	s.defaultInt(&s.r.FailureInbox.MaxSignals, s.d.FailureInbox.MaxSignals)
	s.defaultInt(&s.r.FailureInbox.MaxReasons, s.d.FailureInbox.MaxReasons)
	s.defaultInt(&s.r.FailureInbox.RetentionSeconds, s.d.FailureInbox.RetentionSeconds)
	s.defaultInt(&s.r.FailureInbox.MinSYNSentAgeMS, s.d.FailureInbox.MinSYNSentAgeMS)
	s.outOfRange("system.classifier.runtime.failure_inbox.max_candidates", s.r.FailureInbox.MaxCandidates, 1, 4096)
	s.outOfRange("system.classifier.runtime.failure_inbox.max_evidence_per_candidate", s.r.FailureInbox.MaxEvidencePerCandidate, 1, 64)
	s.outOfRange("system.classifier.runtime.failure_inbox.retention_seconds", s.r.FailureInbox.RetentionSeconds, 10, 86400)

	s.defaultInt(&s.r.ClientHelloLab.CaptureDurationSeconds, s.d.ClientHelloLab.CaptureDurationSeconds)
	s.defaultInt(&s.r.ClientHelloLab.MaxFlows, s.d.ClientHelloLab.MaxFlows)
	s.defaultInt(&s.r.ClientHelloLab.MaxProfiles, s.d.ClientHelloLab.MaxProfiles)
	s.defaultInt(&s.r.ClientHelloLab.MaxBytesPerFlow, s.d.ClientHelloLab.MaxBytesPerFlow)
	s.defaultInt(&s.r.ClientHelloLab.MaxBytesTotal, s.d.ClientHelloLab.MaxBytesTotal)
	s.defaultInt(&s.r.ClientHelloLab.MaxSegmentsPerFlow, s.d.ClientHelloLab.MaxSegmentsPerFlow)
	s.outOfRange("system.classifier.runtime.clienthello_lab.capture_duration_seconds", s.r.ClientHelloLab.CaptureDurationSeconds, 1, 300)
	s.outOfRange("system.classifier.runtime.clienthello_lab.max_flows", s.r.ClientHelloLab.MaxFlows, 1, 256)
	s.outOfRange("system.classifier.runtime.clienthello_lab.max_profiles", s.r.ClientHelloLab.MaxProfiles, 1, 256)
	s.outOfRange("system.classifier.runtime.clienthello_lab.max_bytes_per_flow", s.r.ClientHelloLab.MaxBytesPerFlow, 2048, 64*1024)
	s.outOfRange("system.classifier.runtime.clienthello_lab.max_bytes_total", s.r.ClientHelloLab.MaxBytesTotal, s.r.ClientHelloLab.MaxBytesPerFlow, 4*1024*1024)
	s.outOfRange("system.classifier.runtime.clienthello_lab.max_segments_per_flow", s.r.ClientHelloLab.MaxSegmentsPerFlow, 2, 256)

	s.defaultInt(&s.r.Rollout.LastGoodRetentionHours, s.d.Rollout.LastGoodRetentionHours)
	s.defaultInt(&s.r.Rollout.CanaryDurationSeconds, s.d.Rollout.CanaryDurationSeconds)
	s.defaultU8(&s.r.Rollout.CanaryNewFlowPercent, s.d.Rollout.CanaryNewFlowPercent)
	s.defaultU64(&s.r.Rollout.CanaryMinSamples, s.d.Rollout.CanaryMinSamples)
	s.defaultU64(&s.r.Rollout.CanaryMaxFailures, s.d.Rollout.CanaryMaxFailures)
	if s.r.Rollout.CanaryMaxFailureRate <= 0 {
		s.r.Rollout.CanaryMaxFailureRate = s.d.Rollout.CanaryMaxFailureRate
	}
	s.defaultInt(&s.r.Rollout.CooldownSeconds, s.d.Rollout.CooldownSeconds)
	s.outOfRange("system.classifier.runtime.rollout.last_good_retention_hours", s.r.Rollout.LastGoodRetentionHours, 1, 24*90)
	s.outOfRange("system.classifier.runtime.rollout.canary_duration_seconds", s.r.Rollout.CanaryDurationSeconds, 1, 3600)
	if s.r.Rollout.CanaryNewFlowPercent > 100 {
		s.v.add("system.classifier.runtime.rollout.canary_new_flow_percent", "out_of_range", "canary percentage must be 1..100", nil)
	}
	if s.r.Rollout.CanaryMaxFailureRate <= 0 || s.r.Rollout.CanaryMaxFailureRate > 1 {
		s.v.add("system.classifier.runtime.rollout.canary_max_failure_rate", "out_of_range", "failure rate must be in (0,1]", nil)
	}
	s.outOfRange("system.classifier.runtime.rollout.cooldown_seconds", s.r.Rollout.CooldownSeconds, 1, 86400)
	if !s.r.Rollout.RequireReadiness {
		s.v.add("system.classifier.runtime.rollout.require_readiness", "readiness_required", "transactional apply must gate on capture/runtime readiness", nil)
	}
}
