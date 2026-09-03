package detector

// Hard-gate producer fixtures for the adaptive blocking detector (ABD)
// lifecycle (FB-02 ABD section, §39-§42 of
// B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2).
// Each test drives the real production guard in
// src/detector/hard_gate_producers.go that emits a registered hard-gate
// metric and asserts the counter moved. All seventy-nine gates are
// zero-tolerance violation counters, so every fixture is a negative
// fixture: it exercises the violating branch and asserts the counter
// incremented.
//
// These tests are referenced from specs/registries/hard_gates.yaml
// (test_producer / mutation_test / evidence_artifact) and from
// artifacts/remediation/FB02_ABD_PRODUCERS.json.

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/observability"
)

func abdCounterValue(t *testing.T, name string) uint64 {
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

func assertABDInc(t *testing.T, name string, trigger func()) {
	t.Helper()
	observability.Default().Metrics.Reset()
	before := abdCounterValue(t, name)
	trigger()
	after := abdCounterValue(t, name)
	if after <= before {
		t.Fatalf("%s: expected violating branch to increment counter, before=%d after=%d", name, before, after)
	}
}

func abdScope() monitor.MonitorScopeKey {
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

func abdSnapshot() monitor.ClientResolutionSnapshot {
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

func abdProfileReady() BlockingProfile {
	return BlockingProfile{
		ProfileID: "profile-1",
		Status:    ProfileReady,
		Scope:     abdScope(),
		Assessment: MonitorAssessmentRef{
			AssessmentID:     "assessment-1",
			RequestID:        "req-1",
			Scope:            abdScope(),
			ConfigGeneration: 7,
		},
		Hypothesis:   "transport-degraded",
		EvidenceRefs: []string{"ev-1"},
		ContentHash:  "hash-1",
		CompiledAt:   time.Now(),
	}
}

func abdRequest() monitor.MonitorDiagnosticRequest {
	return monitor.MonitorDiagnosticRequest{
		RequestID:       "req-1",
		TriggerReason:   "test",
		RequestedAt:     time.Now(),
		ResolutionFresh: true,
		VisibilityFresh: true,
		Overlay: monitor.TargetPlanOverlay{
			Scope:                abdScope(),
			ResolutionSnapshotID: "res-1",
			TargetHashes:         []string{"t-1"},
			RequiredSources:      []monitor.ObservationSource{monitor.SourceTCPSYN},
			ConfigGeneration:     7,
		},
	}
}

// ---- §39. Detector safety hard gates ---------------------------------------

func TestABDSingleProbeConfirmed(t *testing.T) {
	assertABDInc(t, observability.MetricABDSingleProbeConfirmed, func() {
		SingleProbeConfirmedAllowed(1)
	})
}

func TestABDExceptionStringOnlyConfirmed(t *testing.T) {
	assertABDInc(t, observability.MetricABDExceptionStringOnlyConfirmed, func() {
		ExceptionStringOnlyConfirmedAllowed("conn refused", "")
	})
}

func TestABDStaticTargetOnlyHighConfidence(t *testing.T) {
	assertABDInc(t, observability.MetricABDStaticTargetOnlyHighConfidence, func() {
		StaticTargetOnlyHighConfidenceAllowed(true, true)
	})
}

func TestABDSelfInterference(t *testing.T) {
	assertABDInc(t, observability.MetricABDSelfInterference, func() {
		SelfInterferenceAllowed(2)
	})
}

func TestABDNativePathUnproven(t *testing.T) {
	assertABDInc(t, observability.MetricABDNativePathUnproven, func() {
		NativePathUnprovenAllowed(true, false)
	})
}

func TestABDCaptureInvalidPacketVerdict(t *testing.T) {
	assertABDInc(t, observability.MetricABDCaptureInvalidPacketVerdict, func() {
		CaptureInvalidPacketVerdictAllowed(false)
	})
}

func TestABDControlFailureIgnored(t *testing.T) {
	assertABDInc(t, observability.MetricABDControlFailureIgnored, func() {
		ControlFailureIgnoredAllowed(true, true)
	})
}

func TestABDDupEvidenceConfidenceIncrease(t *testing.T) {
	assertABDInc(t, observability.MetricABDDupEvidenceConfidenceIncrease, func() {
		DuplicateEvidenceConfidenceIncreaseAllowed([]string{"ev-1", "ev-1"}, true)
	})
}

func TestABDCrossComponentEvidenceMerge(t *testing.T) {
	a, b := abdScope(), abdScope()
	b.ComponentID = "api"
	assertABDInc(t, observability.MetricABDCrossComponentEvidenceMerge, func() {
		CrossComponentEvidenceMergeAllowed(a, b)
	})
}

func TestABDCrossGenerationEvidenceMerge(t *testing.T) {
	a, b := abdScope(), abdScope()
	b.ConfigGeneration = 8
	assertABDInc(t, observability.MetricABDCrossGenerationEvidenceMerge, func() {
		CrossGenerationEvidenceMergeAllowed(a, b)
	})
}

func TestABDUnboundedDynamicScan(t *testing.T) {
	assertABDInc(t, observability.MetricABDUnboundedDynamicScan, func() {
		UnboundedDynamicScanAllowed(0)
	})
}

func TestABDResourceBudgetBypass(t *testing.T) {
	assertABDInc(t, observability.MetricABDResourceBudgetBypass, func() {
		ResourceBudgetBypassAllowed(10, 12)
	})
}

func TestABDSensitiveExport(t *testing.T) {
	assertABDInc(t, observability.MetricABDSensitiveExport, func() {
		SensitiveExportAllowed(true, false)
	})
}

func TestABDHostDeadSingleReferenceFailure(t *testing.T) {
	assertABDInc(t, observability.MetricABDHostDeadSingleReferenceFailure, func() {
		HostDeadFromSingleReferenceFailureAllowed(1)
	})
}

func TestABDReferencePathUnhealthyUsed(t *testing.T) {
	assertABDInc(t, observability.MetricABDReferencePathUnhealthyUsed, func() {
		ReferencePathUnhealthyUsedAllowed(false)
	})
}

func TestABDReferencePathAsActionAuth(t *testing.T) {
	assertABDInc(t, observability.MetricABDReferencePathAsActionAuth, func() {
		ReferencePathUsedAsActionAuthorizationAllowed(true, false)
	})
}

func TestABDPartialRunProfileCompiled(t *testing.T) {
	assertABDInc(t, observability.MetricABDPartialRunProfileCompiled, func() {
		PartialRunProfileCompiledAllowed(monitor.ABDRun{State: monitor.RunPartial}, abdProfileReady())
	})
}

func TestABDResumeCrossNetworkContext(t *testing.T) {
	assertABDInc(t, observability.MetricABDResumeCrossNetworkContext, func() {
		ResumeCrossNetworkContextAllowed("wan-a", "wan-b")
	})
}

func TestABDCapacitySelfInterference(t *testing.T) {
	assertABDInc(t, observability.MetricABDCapacitySelfInterference, func() {
		CapacitySelfInterferenceAllowed(5, 6)
	})
}

// ---- §40. DNS/TLS/QUIC hard gates ------------------------------------------

func TestABDDNSSingleResolverSpoof(t *testing.T) {
	assertABDInc(t, observability.MetricABDDNSSingleResolverSpoof, func() {
		DNSSingleResolverSpoofConfirmedAllowed(1)
	})
}

func TestABDDNSCdnVarianceMisclassified(t *testing.T) {
	assertABDInc(t, observability.MetricABDDNSCdnVarianceMisclassified, func() {
		DNSCdnVarianceMisclassifiedAllowed(true, true)
	})
}

func TestABDUnverifiedMITMVerdict(t *testing.T) {
	assertABDInc(t, observability.MetricABDUnverifiedMITMVerdict, func() {
		UnverifiedMITMVerdictAllowed(false)
	})
}

func TestABDTLSAvailabilityIntegrityConflation(t *testing.T) {
	assertABDInc(t, observability.MetricABDTLSAvailabilityIntegrityConflate, func() {
		TLSAvailabilityIntegrityConflationAllowed(true, true)
	})
}

func TestABDTLSFingerprintUnlabeled(t *testing.T) {
	assertABDInc(t, observability.MetricABDTLSFingerprintUnlabeled, func() {
		TLSFingerprintUnlabeledAllowed("")
	})
}

func TestABDQUICSingleTargetGlobalUDP(t *testing.T) {
	assertABDInc(t, observability.MetricABDQUICSingleTargetGlobalUDP, func() {
		QUICSingleTargetGlobalUDPVerdictAllowed(1, true)
	})
}

func TestABDQUICTCPEvidenceConflation(t *testing.T) {
	assertABDInc(t, observability.MetricABDQUICTCPEvidenceConflation, func() {
		QUICTCPEvidenceConflationAllowed(true, true)
	})
}

func TestABDValidAppErrorDPI(t *testing.T) {
	assertABDInc(t, observability.MetricABDValidAppErrorDPI, func() {
		ValidApplicationErrorDPIAllowed(true, true)
	})
}

func TestABDHeadOnlyAvailableVerdict(t *testing.T) {
	assertABDInc(t, observability.MetricABDHeadOnlyAvailableVerdict, func() {
		HeadOnlyAvailableVerdictAllowed(true, true)
	})
}

func TestABDPartialProgressDiscarded(t *testing.T) {
	assertABDInc(t, observability.MetricABDPartialProgressDiscarded, func() {
		PartialProgressDiscardedAllowed(true, false)
	})
}

func TestABDSmallObjectClassifiedThrottled(t *testing.T) {
	assertABDInc(t, observability.MetricABDSmallObjectClassifiedThrottled, func() {
		SmallObjectClassifiedThrottledAllowed(true, false)
	})
}

func TestABDFixed16kbWindowNoProfile(t *testing.T) {
	assertABDInc(t, observability.MetricABDFixed16kbWindowNoProfile, func() {
		Fixed16kbWindowConfirmedWithoutProfileAllowed(true, false)
	})
}

// ---- §41. L4 threshold hard gates -------------------------------------------

func TestABDPacketThresholdAsByte(t *testing.T) {
	assertABDInc(t, observability.MetricABDPacketThresholdAsByte, func() {
		PacketThresholdReportedAsByteThresholdAllowed(true, true)
	})
}

func TestABDByteThresholdAsPacket(t *testing.T) {
	assertABDInc(t, observability.MetricABDByteThresholdAsPacket, func() {
		ByteThresholdReportedAsPacketThresholdAllowed(true, true)
	})
}

func TestABDGsoSkbCountAsWirePacket(t *testing.T) {
	assertABDInc(t, observability.MetricABDGsoSkbCountAsWirePacket, func() {
		GsoSkbCountAsWirePacketAllowed(4, 2)
	})
}

func TestABDSingleOriginL4BudgetConfirmed(t *testing.T) {
	assertABDInc(t, observability.MetricABDSingleOriginL4BudgetConfirmed, func() {
		SingleOriginL4BudgetConfirmedAllowed(1)
	})
}

func TestABDServerHeaderLimitDPI(t *testing.T) {
	assertABDInc(t, observability.MetricABDServerHeaderLimitDPI, func() {
		ServerHeaderLimitDPIDeniedAllowed(true, true)
	})
}

func TestABDRetransmissionAsProgress(t *testing.T) {
	assertABDInc(t, observability.MetricABDRetransmissionAsProgress, func() {
		RetransmissionCountedAsProgressAllowed(3, 3)
	})
}

func TestABDL4ThresholdWithoutControls(t *testing.T) {
	assertABDInc(t, observability.MetricABDL4ThresholdWithoutControls, func() {
		L4ThresholdWithoutControlsAllowed(0)
	})
}

// ---- §42. BlockingProfile and DDI hard gates --------------------------------

func TestABDBlockingProfileWithoutTargetPlan(t *testing.T) {
	assertABDInc(t, observability.MetricABDBlockingProfileWithoutTargetPlan, func() {
		BlockingProfileWithoutTargetPlanAllowed(abdProfileReady(), 0)
	})
}

func TestABDBlockingProfileWithoutNetCtx(t *testing.T) {
	p := abdProfileReady()
	p.Scope.NetworkContextID = ""
	assertABDInc(t, observability.MetricABDBlockingProfileWithoutNetCtx, func() {
		BlockingProfileWithoutNetworkContextAllowed(p)
	})
}

func TestABDBlockingProfileWithoutProvenance(t *testing.T) {
	p := abdProfileReady()
	p.EvidenceRefs = nil
	assertABDInc(t, observability.MetricABDBlockingProfileWithoutProvenance, func() {
		BlockingProfileWithoutProvenanceAllowed(p)
	})
}

func TestABDBlockingProfileMutatedAfterCompile(t *testing.T) {
	assertABDInc(t, observability.MetricABDBlockingProfileMutatedAfterCompile, func() {
		BlockingProfileMutatedAfterCompileAllowed(true, true)
	})
}

func TestABDBlockingProfileHighConfidenceContradiction(t *testing.T) {
	assertABDInc(t, observability.MetricABDBlockingProfileHighConfidenceContradiction, func() {
		BlockingProfileHighConfidenceWithContradictionAllowed(ConfidenceSummary{Contradictions: 1}, true)
	})
}

func TestABDBlockingProfileDirectActionAuth(t *testing.T) {
	assertABDInc(t, observability.MetricABDBlockingProfileDirectActionAuth, func() {
		BlockingProfileDirectActionAuthorizationAllowed(abdProfileReady(), true)
	})
}

func TestABDBlockingProfileDirectProdWrite(t *testing.T) {
	assertABDInc(t, observability.MetricABDBlockingProfileDirectProdWrite, func() {
		BlockingProfileDirectProductionWriteAllowed(abdProfileReady(), true)
	})
}

func TestABDGuidedSearchSkippedBaseline(t *testing.T) {
	prior := DiscoverySearchPrior{Scope: abdScope(), ProfileID: "p-1", CoverageDenominator: 2, MandatoryBaselines: []string{"direct", "tls"}}
	assertABDInc(t, observability.MetricABDGuidedSearchSkippedBaseline, func() {
		GuidedSearchSkippedBaselineAllowed(prior, []string{"direct"})
	})
}

func TestABDGuidedSearchDisabledFullFallback(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchDisabledFullFallback, func() {
		GuidedSearchDisabledFullFallbackAllowed(true)
	})
}

func TestABDGuidedSearchOverrodeBaseline(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchOverrodeBaseline, func() {
		GuidedSearchProfileOverrodeBaselineAllowed(true)
	})
}

func TestABDGuidedSearchUnvalidatedPromotion(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchUnvalidatedPromotion, func() {
		GuidedSearchTargetUnvalidatedPromotionAllowed(false)
	})
}

func TestABDGuidedSearchCrossServiceAction(t *testing.T) {
	a, b := abdScope(), abdScope()
	b.ServiceProfileID = "svc-b"
	assertABDInc(t, observability.MetricABDGuidedSearchCrossServiceAction, func() {
		GuidedSearchCrossServiceActionAllowed(a, b)
	})
}

func TestABDGuidedSearchWhiteSNIDirectPromotion(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchWhiteSNIDirectPromotion, func() {
		GuidedSearchWhiteSNIDirectPromotionAllowed(true, true)
	})
}

func TestABDGuidedSearchFalseSavingsReport(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchFalseSavingsReport, func() {
		GuidedSearchFalseSavingsReportAllowed(10, 3)
	})
}

func TestABDGuidedSearchRequiredComponentUncovered(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchRequiredComponentUncovered, func() {
		GuidedSearchRequiredComponentUncoveredAllowed([]string{"web", "dns"}, []string{"web"})
	})
}

func TestABDGuidedSearchCoverageIgnoredControlRegression(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchCoverageIgnoredControlRegression, func() {
		GuidedSearchCoverageIgnoredControlRegressionAllowed(true, true)
	})
}

func TestABDGuidedSearchCrossServiceSetCover(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchCrossServiceSetCover, func() {
		GuidedSearchCrossServiceSetCoverAllowed(true)
	})
}

func TestABDGuidedSearchExcludedTargetHidden(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchExcludedTargetHidden, func() {
		GuidedSearchExcludedTargetHiddenAllowed([]string{"t-1"}, []string{"t-2"})
	})
}

func TestABDGuidedSearchMoreComplexPreferredNoGain(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchMoreComplexPreferredNoGain, func() {
		GuidedSearchMoreComplexPreferredWithoutGainAllowed(5, 3, 0)
	})
}

func TestABDGuidedSearchUnverifiedShortlist(t *testing.T) {
	assertABDInc(t, observability.MetricABDGuidedSearchUnverifiedShortlist, func() {
		GuidedSearchUnverifiedShortlistPromotionAllowed(false)
	})
}

// ---- §42.1. Monitoring adapter hard gates -----------------------------------

func TestABDMonitorRequestDirectAction(t *testing.T) {
	assertABDInc(t, observability.MetricABDMonitorRequestDirectAction, func() {
		MonitorRequestDirectActionAllowed(abdRequest(), true)
	})
}

func TestABDMonitorRequestWithoutTargetPlan(t *testing.T) {
	req := abdRequest()
	req.Overlay = monitor.TargetPlanOverlay{}
	assertABDInc(t, observability.MetricABDMonitorRequestWithoutTargetPlan, func() {
		MonitorRequestWithoutTargetPlanOverlayAllowed(req)
	})
}

func TestABDMonitorRequestWithoutNetworkCtx(t *testing.T) {
	req := abdRequest()
	req.Overlay.Scope.NetworkContextID = ""
	assertABDInc(t, observability.MetricABDMonitorRequestWithoutNetworkCtx, func() {
		MonitorRequestWithoutNetworkContextAllowed(req)
	})
}

func TestABDMonitorRequestWithoutConfigGen(t *testing.T) {
	req := abdRequest()
	req.Overlay.ConfigGeneration = 0
	assertABDInc(t, observability.MetricABDMonitorRequestWithoutConfigGen, func() {
		MonitorRequestWithoutConfigGenerationAllowed(req)
	})
}

func TestABDMonitorRequestWithoutBudgetToken(t *testing.T) {
	assertABDInc(t, observability.MetricABDMonitorRequestWithoutBudgetToken, func() {
		MonitorRequestWithoutBudgetTokenAllowed("")
	})
}

func TestABDMonitorRequestExpiredAccepted(t *testing.T) {
	now := time.Now()
	assertABDInc(t, observability.MetricABDMonitorRequestExpiredAccepted, func() {
		MonitorRequestExpiredAcceptedAllowed(now, now.Add(-time.Minute))
	})
}

func TestABDProvisionalMonitorProfileCompiled(t *testing.T) {
	assertABDInc(t, observability.MetricABDProvisionalMonitorProfileCompiled, func() {
		ProvisionalMonitorEvidenceProfileCompiledAllowed(true, true)
	})
}

func TestABDPassiveObservationAsIndependentProbe(t *testing.T) {
	assertABDInc(t, observability.MetricABDPassiveObservationAsIndependentProbe, func() {
		PassiveObservationCountedAsIndependentProbeAllowed(true, true)
	})
}

func TestABDMonitorRecurrenceAsIndependence(t *testing.T) {
	assertABDInc(t, observability.MetricABDMonitorRecurrenceAsIndependence, func() {
		MonitorRecurrenceCountedAsIndependenceAllowed(3, 3)
	})
}

func TestABDClientResolutionReplacedSilently(t *testing.T) {
	assertABDInc(t, observability.MetricABDClientResolutionReplacedSilently, func() {
		ClientResolutionReplacedSilentlyAllowed(abdSnapshot(), 2, false)
	})
}

func TestABDProbeWithoutResolutionBinding(t *testing.T) {
	assertABDInc(t, observability.MetricABDProbeWithoutResolutionBinding, func() {
		ProbeWithoutResolutionBindingAllowed(monitor.ClientResolutionSnapshot{})
	})
}

func TestABDCnameTerminalIPMisattributed(t *testing.T) {
	snap := abdSnapshot()
	snap.CNAMEChainHashes = []string{"cname-1"}
	assertABDInc(t, observability.MetricABDCnameTerminalIPMisattributed, func() {
		CnameTerminalIPMisattributedAllowed(snap, monitor.ResolvedEndpoint{IPHash: "other-ip"})
	})
}

func TestABDMultiIPPartialFailureHidden(t *testing.T) {
	outcomes := []monitor.AddressOutcome{
		{EndpointHash: "ip-1", TCPOutcome: "ok"},
		{EndpointHash: "ip-2", TCPOutcome: "fail"},
	}
	assertABDInc(t, observability.MetricABDMultiIPPartialFailureHidden, func() {
		MultiIPPartialFailureHiddenAllowed(outcomes, true)
	})
}

func TestABDStaleClientResolutionUsed(t *testing.T) {
	snap := abdSnapshot()
	snap.ValidUntil = time.Now().Add(-time.Minute)
	assertABDInc(t, observability.MetricABDStaleClientResolutionUsed, func() {
		StaleClientResolutionUsedAllowed(snap, time.Now())
	})
}

func TestABDResultWithoutAssessmentLink(t *testing.T) {
	assertABDInc(t, observability.MetricABDResultWithoutAssessmentLink, func() {
		ResultWithoutMonitorAssessmentLinkAllowed(monitor.ABDResult{RunID: "run-1"})
	})
}

func TestABDResultCrossNetworkContext(t *testing.T) {
	assertABDInc(t, observability.MetricABDResultCrossNetworkContext, func() {
		ResultCrossNetworkContextAllowed("wan-a", "wan-b")
	})
}

func TestABDResultCrossConfigGeneration(t *testing.T) {
	assertABDInc(t, observability.MetricABDResultCrossConfigGeneration, func() {
		ResultCrossConfigGenerationAllowed(7, 8)
	})
}

func TestABDResultCrossMonitoringEpoch(t *testing.T) {
	assertABDInc(t, observability.MetricABDResultCrossMonitoringEpoch, func() {
		ResultCrossMonitoringEpochAllowed("epoch-1", "epoch-2")
	})
}

func TestABDIncompleteRunFinalProfile(t *testing.T) {
	assertABDInc(t, observability.MetricABDIncompleteRunFinalProfile, func() {
		IncompleteRunFinalProfileAllowed(false, true)
	})
}

func TestABDMonitorResultActionAuthorization(t *testing.T) {
	assertABDInc(t, observability.MetricABDMonitorResultActionAuthorization, func() {
		MonitorResultActionAuthorizationAllowed(monitor.ABDResult{RunID: "run-1"}, true)
	})
}

func TestABDMonitorResultDeliveryIdentityMismatch(t *testing.T) {
	a := abdScope()
	b := abdScope()
	b.ClientScope.ID = "client-b"
	assertABDInc(t, observability.MetricABDMonitorResultDeliveryIdentityMismatch, func() {
		MonitorResultDeliveryIdentityMismatchAllowed(a, b)
	})
}
