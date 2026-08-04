package monitoring

// Hard-gate producer fixtures for the continuous-blocking monitoring (MON)
// lifecycle (FB-02 MON section, §84-§92 of
// B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0).
// Each test drives the real production guard in
// src/monitoring/hard_gate_producers.go that emits a registered hard-gate
// metric and asserts the counter moved. All fifty-two gates are
// zero-tolerance violation counters, so every fixture is a negative
// fixture: it exercises the violating branch and asserts the counter
// incremented.
//
// These tests are referenced from specs/registries/hard_gates.yaml
// (test_producer / mutation_test / evidence_artifact) and from
// artifacts/remediation/FB02_MON_PRODUCERS.json.

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/observability"
)

func monCounterValue(t *testing.T, name string) uint64 {
	t.Helper()
	snap := observability.Default().Metrics.Snapshot(time.Now())
	var total uint64
	for _, counter := range snap.Counters {
		if counter.Name == name {
			total += counter.Value
		}
	}
	return total
}

func assertMONInc(t *testing.T, name string, trigger func()) {
	t.Helper()
	observability.Default().Metrics.Reset()
	before := monCounterValue(t, name)
	trigger()
	after := monCounterValue(t, name)
	if after <= before {
		t.Fatalf("%s: expected violating branch to increment counter, before=%d after=%d", name, before, after)
	}
}

func monScope() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{
		ClientScope:       monitor.ClientScopeKey{ID: "client-a", Role: "forwarded"},
		ServiceProfileID:  "svc-a",
		ComponentID:       "web",
		DomainIdentityID:  "example.com",
		TargetRole:        "target",
		NetworkContextID:  "wan-a",
		ConfigGeneration:  7,
		IPFamily:          "ipv4",
		DestinationIPHash: "dip-1",
		DestinationPort:   443,
		L4Protocol:        6,
		BindingID:         "bind-1",
		PathMode:          "direct",
	}
}

func monSnapshot() monitor.ClientResolutionSnapshot {
	return monitor.ClientResolutionSnapshot{
		SnapshotID:        "res-1",
		ClientKeyHash:     "ck-a",
		NetworkContextID:  "wan-a",
		ConfigGeneration:  7,
		OriginalQNameHash: "qname-1",
		QueryType:         "A",
		Answers: []monitor.ResolvedEndpoint{
			{IPHash: "ip-1", IPFamily: "ipv4", AddressIndex: 0, TTL: 60},
		},
		AnswerOrder: []uint16{0},
		TTLs:        []uint32{60},
		ObservedAt:  time.Now().Add(-time.Minute),
		ValidUntil:  time.Now().Add(time.Minute),
	}
}

func monReq() monitor.MonitorDiagnosticRequest {
	return monitor.MonitorDiagnosticRequest{
		RequestID:       "req-1",
		TriggerReason:   "test",
		RequestedAt:     time.Now(),
		ResolutionFresh: true,
		VisibilityFresh: true,
		Overlay: monitor.TargetPlanOverlay{
			Scope:                monScope(),
			ResolutionSnapshotID: "res-1",
			TargetHashes:         []string{"t-1"},
			RequiredSources:      []monitor.ObservationSource{monitor.SourceTCPSYN},
			ConfigGeneration:     7,
		},
	}
}

func monProfileReady() detector.BlockingProfile {
	return detector.BlockingProfile{
		ProfileID: "profile-1",
		Status:    detector.ProfileReady,
		Scope:     monScope(),
		Assessment: detector.MonitorAssessmentRef{
			AssessmentID: "assessment-1",
			RequestID:    "req-1",
			Scope:        monScope(),
		},
		Hypothesis:   "transport-degraded",
		EvidenceRefs: []string{"ev-1"},
		ContentHash:  "hash-1",
		CompiledAt:   time.Now(),
	}
}

// ---- §84. Observation and authority gates --------------------------------

func TestMONObservationDirectAction(t *testing.T) {
	assertMONInc(t, observability.MetricMONObservationDirectAction, func() {
		ObservationDirectActionAllowed(monitor.MonitorObservation{ObservationID: "obs-1"}, false)
	})
}

func TestMONProvisionalProfileCompiled(t *testing.T) {
	assertMONInc(t, observability.MetricMONProvisionalProfileCompiled, func() {
		ProvisionalProfileCompiled(monProfileReady(), false)
	})
}

func TestMONPassiveDiscoveryStart(t *testing.T) {
	assertMONInc(t, observability.MetricMONPassiveDiscoveryStart, func() {
		PassiveDiscoveryStart(monitor.AuthorityPassiveMonitoring)
	})
}

func TestMONPassiveWarpEnable(t *testing.T) {
	assertMONInc(t, observability.MetricMONPassiveWarpEnable, func() {
		PassiveWarpEnable(true, false)
	})
}

func TestMONFastLaneAction(t *testing.T) {
	assertMONInc(t, observability.MetricMONFastLaneAction, func() {
		FastLaneActionTaken(true)
	})
}

func TestMONFastLanePromotedAsAuthoritative(t *testing.T) {
	assertMONInc(t, observability.MetricMONFastLanePromotedAsAuthoritative, func() {
		FastLanePromotedAsAuthoritative(true, true)
	})
}

// ---- §85. Scope gates -----------------------------------------------------

func TestMONDestinationOnlyDeepTrigger(t *testing.T) {
	scope := monScope()
	scope.ClientScope = monitor.ClientScopeKey{}
	assertMONInc(t, observability.MetricMONDestinationOnlyDeepTrigger, func() {
		DeepTriggerOnDestinationOnlyScope(scope, monitor.DiagnosticDeep)
	})
}

func TestMONCrossClientMerge(t *testing.T) {
	assertMONInc(t, observability.MetricMONCrossClientMerge, func() {
		CrossClientMergeAllowed(monitor.ClientScopeKey{ID: "a"}, monitor.ClientScopeKey{ID: "b"})
	})
}

func TestMONCrossServiceMerge(t *testing.T) {
	a, b := monScope(), monScope()
	b.ServiceProfileID = "svc-b"
	assertMONInc(t, observability.MetricMONCrossServiceMerge, func() {
		CrossServiceMergeAllowed(a, b)
	})
}

func TestMONCrossComponentMerge(t *testing.T) {
	a, b := monScope(), monScope()
	b.ComponentID = "api"
	assertMONInc(t, observability.MetricMONCrossComponentMerge, func() {
		CrossComponentMergeAllowed(a, b)
	})
}

func TestMONCrossWanEvidenceMerge(t *testing.T) {
	a, b := monScope(), monScope()
	b.NetworkContextID = "wan-b"
	assertMONInc(t, observability.MetricMONCrossWanEvidenceMerge, func() {
		CrossWanEvidenceMergeAllowed(a, b)
	})
}

func TestMONCrossGenerationEvidenceMerge(t *testing.T) {
	a, b := monScope(), monScope()
	b.ConfigGeneration = 8
	assertMONInc(t, observability.MetricMONCrossGenerationEvidenceMerge, func() {
		CrossGenerationEvidenceMergeAllowed(a, b)
	})
}

func TestMONRouterOriginAsForwardedProof(t *testing.T) {
	assertMONInc(t, observability.MetricMONRouterOriginAsForwardedProof, func() {
		RouterOriginAsForwardedProofAllowed(monitor.CorrelationSnapshot{Forwarded: true, RouterOrigin: true})
	})
}

// ---- §86. Temporal gates --------------------------------------------------

func TestMONDupEvidenceIndependence(t *testing.T) {
	assertMONInc(t, observability.MetricMONDupEvidenceIndependence, func() {
		DuplicateEvidenceIndependenceAllowed([]string{"ev-1", "ev-1"})
	})
}

func TestMONTemporalPersistenceNoSeparation(t *testing.T) {
	now := time.Now()
	assertMONInc(t, observability.MetricMONTemporalPersistenceNoSeparation, func() {
		TemporalPersistenceWithoutSeparationAllowed(now, now.Add(time.Second), time.Minute)
	})
}

func TestMONSuccessSuppressorIgnored(t *testing.T) {
	assertMONInc(t, observability.MetricMONSuccessSuppressorIgnored, func() {
		SuccessSuppressorIgnoredAllowed(monitor.MonitorStatus{Suppressed: true})
	})
}

func TestMONRecoveredSubjectNotDemoted(t *testing.T) {
	assertMONInc(t, observability.MetricMONRecoveredSubjectNotDemoted, func() {
		RecoveredSubjectNotDemotedAllowed(monitor.MonitorSubject{Enabled: true}, monitor.HealthRecovered)
	})
}

func TestMONExpiredEvidenceUsed(t *testing.T) {
	now := time.Now()
	assertMONInc(t, observability.MetricMONExpiredEvidenceUsed, func() {
		ExpiredEvidenceUsedAllowed(now, now.Add(-time.Minute))
	})
}

func TestMONDecayDisabledWithoutPolicy(t *testing.T) {
	assertMONInc(t, observability.MetricMONDecayDisabledWithoutPolicy, func() {
		DecayDisabledWithoutPolicyAllowed(false, "")
	})
}

// ---- §87. Resolution gates ------------------------------------------------

func TestMONProbeWithoutResolutionBinding(t *testing.T) {
	assertMONInc(t, observability.MetricMONProbeWithoutResolutionBinding, func() {
		ProbeWithoutResolutionBindingAllowed(monitor.ClientResolutionSnapshot{})
	})
}

func TestMONClientDNSAnswerReplacedSilently(t *testing.T) {
	snap := monSnapshot()
	assertMONInc(t, observability.MetricMONClientDNSAnswerReplacedSilently, func() {
		ClientDNSAnswerReplacedSilentlyAllowed(snap, 2, false)
	})
}

func TestMONCnameTerminalIPMisattributed(t *testing.T) {
	snap := monSnapshot()
	snap.CNAMEChainHashes = []string{"cname-1"}
	assertMONInc(t, observability.MetricMONCnameTerminalIPMisattributed, func() {
		CnameTerminalIPMisattributedAllowed(snap, monitor.ResolvedEndpoint{IPHash: "other-ip"})
	})
}

func TestMONMultiIPPartialFailureHidden(t *testing.T) {
	outcomes := []monitor.AddressOutcome{
		{EndpointHash: "ip-1", TCPOutcome: "ok"},
		{EndpointHash: "ip-2", TCPOutcome: "fail"},
	}
	assertMONInc(t, observability.MetricMONMultiIPPartialFailureHidden, func() {
		MultiIPPartialFailureHiddenAllowed(outcomes, true)
	})
}

func TestMONStaleResolutionExactProof(t *testing.T) {
	snap := monSnapshot()
	snap.ValidUntil = time.Now().Add(-time.Minute)
	assertMONInc(t, observability.MetricMONStaleResolutionExactProof, func() {
		StaleResolutionUsedAsExactProofAllowed(snap, time.Now(), true)
	})
}

// ---- §88. Trigger and resource gates --------------------------------------

func TestMONTriggerWithoutVisibility(t *testing.T) {
	assertMONInc(t, observability.MetricMONTriggerWithoutVisibility, func() {
		TriggerWithoutVisibilityAllowed(false)
	})
}

func TestMONTriggerWithoutBudget(t *testing.T) {
	assertMONInc(t, observability.MetricMONTriggerWithoutBudget, func() {
		TriggerWithoutBudgetAllowed(0, 1)
	})
}

func TestMONTriggerDuringGlobalWanFailure(t *testing.T) {
	assertMONInc(t, observability.MetricMONTriggerDuringGlobalWanFailure, func() {
		TriggerDuringGlobalWanFailureAllowed(true, true)
	})
}

func TestMONTriggerWithStaleHeartbeat(t *testing.T) {
	now := time.Now()
	assertMONInc(t, observability.MetricMONTriggerWithStaleHeartbeat, func() {
		TriggerWithStaleSourceHeartbeatAllowed(now.Add(-time.Hour), now, time.Minute)
	})
}

func TestMONDupConcurrentABDRun(t *testing.T) {
	assertMONInc(t, observability.MetricMONDupConcurrentABDRun, func() {
		DuplicateConcurrentABDRunAllowed([]string{"abd-1"}, "abd-1")
	})
}

func TestMONUnboundedTargetIntake(t *testing.T) {
	assertMONInc(t, observability.MetricMONUnboundedTargetIntake, func() {
		UnboundedTargetIntakeAllowed(monitor.IntakeConfig{})
	})
}

func TestMONUnboundedProbeParallelism(t *testing.T) {
	assertMONInc(t, observability.MetricMONUnboundedProbeParallelism, func() {
		UnboundedProbeParallelismAllowed(8, 0)
	})
}

func TestMONSelfInterference(t *testing.T) {
	assertMONInc(t, observability.MetricMONSelfInterference, func() {
		SelfInterferenceAllowed(1)
	})
}

// ---- §89. Multi-vantage gates ----------------------------------------------

func TestMONReferenceResultAsAuthorization(t *testing.T) {
	assertMONInc(t, observability.MetricMONReferenceResultAsAuthorization, func() {
		ReferenceResultAsActionAuthorizationAllowed(true, false)
	})
}

// ---- §90. ABD/DDI/Discovery gates ------------------------------------------

func TestMONABDRequestWithoutTargetPlan(t *testing.T) {
	req := monReq()
	req.Overlay = monitor.TargetPlanOverlay{}
	assertMONInc(t, observability.MetricMONABDRequestWithoutTargetPlan, func() {
		ABDRequestWithoutTargetPlanAllowed(req)
	})
}

func TestMONABDPartialResultProfileReady(t *testing.T) {
	assertMONInc(t, observability.MetricMONABDPartialResultProfileReady, func() {
		ABDPartialResultProfileReadyAllowed(monitor.ABDRun{State: monitor.RunPartial}, monProfileReady())
	})
}

func TestMONABDResultBypassedDDI(t *testing.T) {
	assertMONInc(t, observability.MetricMONABDResultBypassedDDI, func() {
		ABDResultBypassedDDIAllowed(monitor.ABDResult{Complete: true}, false)
	})
}

func TestMONDiscoveryWithoutAuthProfile(t *testing.T) {
	assertMONInc(t, observability.MetricMONDiscoveryWithoutAuthProfile, func() {
		DiscoveryWithoutAuthoritativeProfileAllowed(monitor.GuidedDiscoveryRequest{})
	})
}

func TestMONDiscoverySkippedMandatoryBaseline(t *testing.T) {
	req := monitor.GuidedDiscoveryRequest{
		AuthoritativeABDRunID: "abd-1",
		MandatoryBaselines:    []string{"direct", "tls"},
	}
	assertMONInc(t, observability.MetricMONDiscoverySkippedMandatoryBaseline, func() {
		DiscoverySkippedMandatoryBaselineAllowed(req, []string{"direct"})
	})
}

func TestMONRecommendationWithoutScope(t *testing.T) {
	assertMONInc(t, observability.MetricMONRecommendationWithoutScope, func() {
		RecommendationWithoutScopeAllowed(monitor.TransportRecommendation{RecommendationID: "rec-1"})
	})
}

func TestMONWarpRecommendationWithoutIPPath(t *testing.T) {
	rec := monitor.TransportRecommendation{RecommendationID: "rec-1", Scope: monScope()}
	assertMONInc(t, observability.MetricMONWarpRecommendationWithoutIPPath, func() {
		WarpRecommendationWithoutIPPathAllowed(rec)
	})
}

// ---- §91. Legacy migration gates -------------------------------------------

func TestMONLegacyWatchdogDirectApply(t *testing.T) {
	assertMONInc(t, observability.MetricMONLegacyWatchdogDirectApply, func() {
		LegacyWatchdogDirectApplyAllowed(true, false)
	})
}

func TestMONLegacyWatchdogUnvalidatedSet(t *testing.T) {
	assertMONInc(t, observability.MetricMONLegacyWatchdogUnvalidatedSet, func() {
		LegacyWatchdogCreatedUnvalidatedSetAllowed(true, false)
	})
}

func TestMONLegacyWatchdogOverwriteNoCanary(t *testing.T) {
	assertMONInc(t, observability.MetricMONLegacyWatchdogOverwriteNoCanary, func() {
		LegacyWatchdogOverwriteWithoutCanaryAllowed(true, false)
	})
}

func TestMONLegacyAPIProjectionMutation(t *testing.T) {
	assertMONInc(t, observability.MetricMONLegacyAPIProjectionMutation, func() {
		LegacyAPIProjectionMutationAllowed(true)
	})
}

func TestMONShadowActiveWriterOverlap(t *testing.T) {
	assertMONInc(t, observability.MetricMONShadowActiveWriterOverlap, func() {
		ShadowActiveWriterOverlapAllowed(true, true)
	})
}

// ---- §92. Reliability/privacy gates ----------------------------------------

func TestMONRequiredEventDropHidden(t *testing.T) {
	assertMONInc(t, observability.MetricMONRequiredEventDropHidden, func() {
		RequiredEventDropHiddenAllowed(3, 1, 2)
	})
}

func TestMONSourceHeartbeatStaleAutoDiagnose(t *testing.T) {
	now := time.Now()
	assertMONInc(t, observability.MetricMONSourceHeartbeatStaleAutoDiagnose, func() {
		SourceHeartbeatStaleAutoDiagnoseAllowed(true, now.Add(-time.Hour), now, time.Minute)
	})
}

func TestMONCheckpointCorruptionFalseReady(t *testing.T) {
	assertMONInc(t, observability.MetricMONCheckpointCorruptionFalseReady, func() {
		CheckpointCorruptionFalseReadyAllowed(monitor.MonitorCheckpoint{CutoverVersion: "v2.3"}, true)
	})
}

func TestMONRestartReusedExpiredLease(t *testing.T) {
	now := time.Now()
	lease := monitor.DiagnosticLease{LeaseID: "lease-1", ExpiresAt: now.Add(-time.Minute)}
	assertMONInc(t, observability.MetricMONRestartReusedExpiredLease, func() {
		RestartReusedExpiredLeaseAllowed(lease, now)
	})
}

func TestMONSensitiveDNSHistoryExport(t *testing.T) {
	assertMONInc(t, observability.MetricMONSensitiveDNSHistoryExport, func() {
		SensitiveDNSHistoryExportAllowed(true, monSnapshot())
	})
}

func TestMONSecretTraceLeak(t *testing.T) {
	assertMONInc(t, observability.MetricMONSecretTraceLeak, func() {
		SecretTraceLeakAllowed(true, false)
	})
}

func TestMONHighCardinalityMetricLabel(t *testing.T) {
	assertMONInc(t, observability.MetricMONHighCardinalityMetricLabel, func() {
		HighCardinalityMetricLabelAllowed(100, 10)
	})
}
