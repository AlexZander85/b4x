package detector

// Hard-gate producers for the adaptive blocking detector (ABD) lifecycle
// (FB-02 ABD section, §39-§42 of
// B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2).
// Each guard models one mandatory hard gate of the detector pipeline —
// detector safety, DNS/TLS/QUIC classification, L4 thresholds, the
// blocking-profile/DDI chain and the monitoring adapter — reusing the
// evidence-only models in this package and the monitor package.
//
// Every violating branch increments exactly one zero-tolerance counter from
// src/observability/abd.go; fixtures in hard_gate_producers_test.go drive
// each violating branch and assert the counter moved. No guard mutates
// configuration or takes a production action; guards only record whether a
// requested ABD action would violate a mandatory hard gate.

import (
	"strings"
	"time"

	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/observability"
)

func abdInc(name string) {
	observability.Default().Metrics.Inc(name, nil, 1)
}

// ---- §39. Detector safety hard gates ---------------------------------------

// SingleProbeConfirmedAllowed denies confirming a verdict from a single
// probe: confirmation requires independent probes.
func SingleProbeConfirmedAllowed(probeCount int) bool {
	if probeCount <= 1 {
		abdInc(observability.MetricABDSingleProbeConfirmed)
		return false
	}
	return true
}

// ExceptionStringOnlyConfirmedAllowed denies confirming a verdict from an
// exception string alone: exception text is not endpoint evidence.
func ExceptionStringOnlyConfirmedAllowed(exceptionString, packetEvidence string) bool {
	if strings.TrimSpace(exceptionString) != "" && strings.TrimSpace(packetEvidence) == "" {
		abdInc(observability.MetricABDExceptionStringOnlyConfirmed)
		return false
	}
	return true
}

// StaticTargetOnlyHighConfidenceAllowed denies a high-confidence verdict
// from a static target list only: confidence needs live observation.
func StaticTargetOnlyHighConfidenceAllowed(staticOnly, highConfidence bool) bool {
	if staticOnly && highConfidence {
		abdInc(observability.MetricABDStaticTargetOnlyHighConfidence)
		return false
	}
	return true
}

// SelfInterferenceAllowed denies probing own monitored targets (detector
// self-interference).
func SelfInterferenceAllowed(overlappingTargets int) bool {
	if overlappingTargets > 0 {
		abdInc(observability.MetricABDSelfInterference)
		return false
	}
	return true
}

// NativePathUnprovenAllowed denies a verdict that assumes the native path
// without proof of native-path capture.
func NativePathUnprovenAllowed(nativePathAssumed, nativePathProven bool) bool {
	if nativePathAssumed && !nativePathProven {
		abdInc(observability.MetricABDNativePathUnproven)
		return false
	}
	return true
}

// CaptureInvalidPacketVerdictAllowed denies a verdict based on an invalid
// capture packet.
func CaptureInvalidPacketVerdictAllowed(packetValid bool) bool {
	if !packetValid {
		abdInc(observability.MetricABDCaptureInvalidPacketVerdict)
		return false
	}
	return true
}

// ControlFailureIgnoredAllowed denies ignoring a control-plane failure while
// producing a transport verdict.
func ControlFailureIgnoredAllowed(controlFailure, verdictProduced bool) bool {
	if controlFailure && verdictProduced {
		abdInc(observability.MetricABDControlFailureIgnored)
		return false
	}
	return true
}

// DuplicateEvidenceConfidenceIncreaseAllowed denies increasing confidence
// from duplicated evidence.
func DuplicateEvidenceConfidenceIncreaseAllowed(refs []string, confidenceIncreased bool) bool {
	seen := map[string]bool{}
	dup := false
	for _, r := range refs {
		if r == "" {
			continue
		}
		if seen[r] {
			dup = true
			break
		}
		seen[r] = true
	}
	if dup && confidenceIncreased {
		abdInc(observability.MetricABDDupEvidenceConfidenceIncrease)
		return false
	}
	return true
}

// CrossComponentEvidenceMergeAllowed denies merging evidence across
// components.
func CrossComponentEvidenceMergeAllowed(a, b monitor.MonitorScopeKey) bool {
	if a.ComponentID != "" && b.ComponentID != "" && a.ComponentID != b.ComponentID {
		abdInc(observability.MetricABDCrossComponentEvidenceMerge)
		return false
	}
	return true
}

// CrossGenerationEvidenceMergeAllowed denies merging evidence across
// configuration generations.
func CrossGenerationEvidenceMergeAllowed(a, b monitor.MonitorScopeKey) bool {
	if a.ConfigGeneration != 0 && b.ConfigGeneration != 0 && a.ConfigGeneration != b.ConfigGeneration {
		abdInc(observability.MetricABDCrossGenerationEvidenceMerge)
		return false
	}
	return true
}

// UnboundedDynamicScanAllowed denies a dynamic scan without a bounded target
// budget.
func UnboundedDynamicScanAllowed(scanLimit int) bool {
	if scanLimit <= 0 {
		abdInc(observability.MetricABDUnboundedDynamicScan)
		return false
	}
	return true
}

// ResourceBudgetBypassAllowed denies consuming resources beyond the budgeted
// token allocation.
func ResourceBudgetBypassAllowed(budgeted, consumed int) bool {
	if budgeted > 0 && consumed > budgeted {
		abdInc(observability.MetricABDResourceBudgetBypass)
		return false
	}
	return true
}

// SensitiveExportAllowed denies exporting sensitive detector data.
func SensitiveExportAllowed(exported, redacted bool) bool {
	if exported && !redacted {
		abdInc(observability.MetricABDSensitiveExport)
		return false
	}
	return true
}

// HostDeadFromSingleReferenceFailureAllowed denies declaring a host dead
// from a single reference-path failure.
func HostDeadFromSingleReferenceFailureAllowed(referenceFailures int) bool {
	if referenceFailures <= 1 {
		abdInc(observability.MetricABDHostDeadSingleReferenceFailure)
		return false
	}
	return true
}

// ReferencePathUnhealthyUsedAllowed denies using an unhealthy reference path
// as evidence.
func ReferencePathUnhealthyUsedAllowed(pathHealthy bool) bool {
	if !pathHealthy {
		abdInc(observability.MetricABDReferencePathUnhealthyUsed)
		return false
	}
	return true
}

// ReferencePathUsedAsActionAuthorizationAllowed denies treating a reference
// path result as action authorization.
func ReferencePathUsedAsActionAuthorizationAllowed(referenceResult, finalAuth bool) bool {
	if referenceResult && !finalAuth {
		abdInc(observability.MetricABDReferencePathAsActionAuth)
		return false
	}
	return true
}

// PartialRunProfileCompiledAllowed denies compiling a final profile from a
// partial run.
func PartialRunProfileCompiledAllowed(run monitor.ABDRun, profile BlockingProfile) bool {
	if run.State == monitor.RunPartial && profile.Status == ProfileReady {
		abdInc(observability.MetricABDPartialRunProfileCompiled)
		return false
	}
	return true
}

// ResumeCrossNetworkContextAllowed denies resuming a run in a different
// network context.
func ResumeCrossNetworkContextAllowed(a, b string) bool {
	if a != "" && b != "" && a != b {
		abdInc(observability.MetricABDResumeCrossNetworkContext)
		return false
	}
	return true
}

// CapacitySelfInterferenceAllowed denies capacity planning that ignores
// self-interference of own probes.
func CapacitySelfInterferenceAllowed(capacityPlanned int, ownProbeLoad int) bool {
	if capacityPlanned > 0 && ownProbeLoad >= capacityPlanned {
		abdInc(observability.MetricABDCapacitySelfInterference)
		return false
	}
	return true
}

// ---- §40. DNS/TLS/QUIC hard gates ------------------------------------------

// DNSSingleResolverSpoofConfirmedAllowed denies confirming DNS spoofing from
// a single resolver.
func DNSSingleResolverSpoofConfirmedAllowed(resolverCount int) bool {
	if resolverCount <= 1 {
		abdInc(observability.MetricABDDNSSingleResolverSpoof)
		return false
	}
	return true
}

// DNSCdnVarianceMisclassifiedAllowed denies misclassifying CDN IP variance
// as a DNS anomaly.
func DNSCdnVarianceMisclassifiedAllowed(cdnVariance, anomalyDeclared bool) bool {
	if cdnVariance && anomalyDeclared {
		abdInc(observability.MetricABDDNSCdnVarianceMisclassified)
		return false
	}
	return true
}

// UnverifiedMITMVerdictAllowed denies an MITM verdict without verification.
func UnverifiedMITMVerdictAllowed(verified bool) bool {
	if !verified {
		abdInc(observability.MetricABDUnverifiedMITMVerdict)
		return false
	}
	return true
}

// TLSAvailabilityIntegrityConflationAllowed denies conflating TLS
// availability with TLS integrity evidence.
func TLSAvailabilityIntegrityConflationAllowed(availabilityOnly, integrityClaimed bool) bool {
	if availabilityOnly && integrityClaimed {
		abdInc(observability.MetricABDTLSAvailabilityIntegrityConflate)
		return false
	}
	return true
}

// TLSFingerprintUnlabeledAllowed denies using an unlabeled TLS fingerprint.
func TLSFingerprintUnlabeledAllowed(fingerprint string) bool {
	if strings.TrimSpace(fingerprint) == "" {
		abdInc(observability.MetricABDTLSFingerprintUnlabeled)
		return false
	}
	return true
}

// QUICSingleTargetGlobalUDPVerdictAllowed denies a global UDP verdict from a
// single QUIC target.
func QUICSingleTargetGlobalUDPVerdictAllowed(targetCount int, globalVerdict bool) bool {
	if targetCount <= 1 && globalVerdict {
		abdInc(observability.MetricABDQUICSingleTargetGlobalUDP)
		return false
	}
	return true
}

// QUICTCPEvidenceConflationAllowed denies conflation of QUIC and TCP
// evidence into one path verdict.
func QUICTCPEvidenceConflationAllowed(quic, tcp bool) bool {
	if quic && tcp {
		abdInc(observability.MetricABDQUICTCPEvidenceConflation)
		return false
	}
	return true
}

// ValidApplicationErrorDPIAllowed denies classifying a valid application
// error as transport failure via DPI.
func ValidApplicationErrorDPIAllowed(appError, transportFailure bool) bool {
	if appError && transportFailure {
		abdInc(observability.MetricABDValidAppErrorDPI)
		return false
	}
	return true
}

// HeadOnlyAvailableVerdictAllowed denies a verdict from head-only payload.
func HeadOnlyAvailableVerdictAllowed(headOnly, verdict bool) bool {
	if headOnly && verdict {
		abdInc(observability.MetricABDHeadOnlyAvailableVerdict)
		return false
	}
	return true
}

// PartialProgressDiscardedAllowed denies discarding recorded partial
// progress without an explanation.
func PartialProgressDiscardedAllowed(progressRecorded, explained bool) bool {
	if progressRecorded && !explained {
		abdInc(observability.MetricABDPartialProgressDiscarded)
		return false
	}
	return true
}

// SmallObjectClassifiedThrottledAllowed denies classifying a small object as
// throttled without evidence.
func SmallObjectClassifiedThrottledAllowed(classifiedThrottled, evidence bool) bool {
	if classifiedThrottled && !evidence {
		abdInc(observability.MetricABDSmallObjectClassifiedThrottled)
		return false
	}
	return true
}

// Fixed16kbWindowConfirmedWithoutProfileAllowed denies confirming a fixed
// 16KB window without a blocking profile.
func Fixed16kbWindowConfirmedWithoutProfileAllowed(confirmed, hasProfile bool) bool {
	if confirmed && !hasProfile {
		abdInc(observability.MetricABDFixed16kbWindowNoProfile)
		return false
	}
	return true
}

// ---- §41. L4 threshold hard gates -------------------------------------------

// PacketThresholdReportedAsByteThresholdAllowed denies reporting a packet
// threshold as a byte threshold.
func PacketThresholdReportedAsByteThresholdAllowed(unitIsPackets, reportedAsBytes bool) bool {
	if unitIsPackets && reportedAsBytes {
		abdInc(observability.MetricABDPacketThresholdAsByte)
		return false
	}
	return true
}

// ByteThresholdReportedAsPacketThresholdAllowed denies reporting a byte
// threshold as a packet threshold.
func ByteThresholdReportedAsPacketThresholdAllowed(unitIsBytes, reportedAsPackets bool) bool {
	if unitIsBytes && reportedAsPackets {
		abdInc(observability.MetricABDByteThresholdAsPacket)
		return false
	}
	return true
}

// GsoSkbCountAsWirePacketAllowed denies counting GSO skb segments as wire
// packets.
func GsoSkbCountAsWirePacketAllowed(skbCount, wireCount int) bool {
	if skbCount > 0 && wireCount < skbCount {
		abdInc(observability.MetricABDGsoSkbCountAsWirePacket)
		return false
	}
	return true
}

// SingleOriginL4BudgetConfirmedAllowed denies confirming an L4 budget from a
// single origin.
func SingleOriginL4BudgetConfirmedAllowed(originCount int) bool {
	if originCount <= 1 {
		abdInc(observability.MetricABDSingleOriginL4BudgetConfirmed)
		return false
	}
	return true
}

// ServerHeaderLimitDPIDeniedAllowed denies a verdict from a truncated server
// header (header limit hit).
func ServerHeaderLimitDPIDeniedAllowed(headerLimited, verdict bool) bool {
	if headerLimited && verdict {
		abdInc(observability.MetricABDServerHeaderLimitDPI)
		return false
	}
	return true
}

// RetransmissionCountedAsProgressAllowed denies counting retransmissions as
// forward progress.
func RetransmissionCountedAsProgressAllowed(retransmits, progress int) bool {
	if retransmits > 0 && progress <= retransmits {
		abdInc(observability.MetricABDRetransmissionAsProgress)
		return false
	}
	return true
}

// L4ThresholdWithoutControlsAllowed denies an L4 threshold decision without
// control targets.
func L4ThresholdWithoutControlsAllowed(controlCount int) bool {
	if controlCount <= 0 {
		abdInc(observability.MetricABDL4ThresholdWithoutControls)
		return false
	}
	return true
}

// ---- §42. BlockingProfile and DDI hard gates --------------------------------

// BlockingProfileWithoutTargetPlanAllowed denies a blocking profile without
// a target plan.
func BlockingProfileWithoutTargetPlanAllowed(profile BlockingProfile, targetHashes int) bool {
	if profile.Valid() && targetHashes <= 0 {
		abdInc(observability.MetricABDBlockingProfileWithoutTargetPlan)
		return false
	}
	return true
}

// BlockingProfileWithoutNetworkContextAllowed denies a blocking profile
// without a network context.
func BlockingProfileWithoutNetworkContextAllowed(profile BlockingProfile) bool {
	if profile.ProfileID != "" && profile.Status == ProfileReady && strings.TrimSpace(profile.Scope.NetworkContextID) == "" {
		abdInc(observability.MetricABDBlockingProfileWithoutNetCtx)
		return false
	}
	return true
}

// BlockingProfileWithoutProvenanceAllowed denies a blocking profile without
// provenance refs.
func BlockingProfileWithoutProvenanceAllowed(profile BlockingProfile) bool {
	if profile.ProfileID != "" && profile.Status == ProfileReady && len(profile.EvidenceRefs) == 0 {
		abdInc(observability.MetricABDBlockingProfileWithoutProvenance)
		return false
	}
	return true
}

// BlockingProfileMutatedAfterCompileAllowed denies mutating a compiled
// blocking profile.
func BlockingProfileMutatedAfterCompileAllowed(compiled, mutated bool) bool {
	if compiled && mutated {
		abdInc(observability.MetricABDBlockingProfileMutatedAfterCompile)
		return false
	}
	return true
}

// BlockingProfileHighConfidenceWithContradictionAllowed denies a
// high-confidence profile carrying contradictions.
func BlockingProfileHighConfidenceWithContradictionAllowed(conf ConfidenceSummary, highConfidence bool) bool {
	if highConfidence && conf.Contradictions > 0 {
		abdInc(observability.MetricABDBlockingProfileHighConfidenceContradiction)
		return false
	}
	return true
}

// BlockingProfileDirectActionAuthorizationAllowed denies a blocking profile
// authorizing a production action directly.
func BlockingProfileDirectActionAuthorizationAllowed(profile BlockingProfile, actionAuthorized bool) bool {
	if profile.Valid() && actionAuthorized {
		abdInc(observability.MetricABDBlockingProfileDirectActionAuth)
		return false
	}
	return true
}

// BlockingProfileDirectProductionWriteAllowed denies a blocking profile
// writing production state directly.
func BlockingProfileDirectProductionWriteAllowed(profile BlockingProfile, productionWritten bool) bool {
	if profile.Valid() && productionWritten {
		abdInc(observability.MetricABDBlockingProfileDirectProdWrite)
		return false
	}
	return true
}

// GuidedSearchSkippedBaselineAllowed denies a guided search that skips a
// mandatory baseline.
func GuidedSearchSkippedBaselineAllowed(prior DiscoverySearchPrior, executed []string) bool {
	ran := map[string]bool{}
	for _, e := range executed {
		ran[e] = true
	}
	for _, b := range prior.MandatoryBaselines {
		if !ran[b] {
			abdInc(observability.MetricABDGuidedSearchSkippedBaseline)
			return false
		}
	}
	return true
}

// GuidedSearchDisabledFullFallbackAllowed denies disabling the full
// fallback search.
func GuidedSearchDisabledFullFallbackAllowed(disabled bool) bool {
	if disabled {
		abdInc(observability.MetricABDGuidedSearchDisabledFullFallback)
		return false
	}
	return true
}

// GuidedSearchProfileOverrodeBaselineAllowed denies the search profile
// overriding the current baseline.
func GuidedSearchProfileOverrodeBaselineAllowed(overrode bool) bool {
	if overrode {
		abdInc(observability.MetricABDGuidedSearchOverrodeBaseline)
		return false
	}
	return true
}

// GuidedSearchTargetUnvalidatedPromotionAllowed denies promoting an
// unvalidated target.
func GuidedSearchTargetUnvalidatedPromotionAllowed(validated bool) bool {
	if !validated {
		abdInc(observability.MetricABDGuidedSearchUnvalidatedPromotion)
		return false
	}
	return true
}

// GuidedSearchCrossServiceActionAllowed denies a guided-search action across
// services.
func GuidedSearchCrossServiceActionAllowed(a, b monitor.MonitorScopeKey) bool {
	if a.ServiceProfileID != "" && b.ServiceProfileID != "" && a.ServiceProfileID != b.ServiceProfileID {
		abdInc(observability.MetricABDGuidedSearchCrossServiceAction)
		return false
	}
	return true
}

// GuidedSearchWhiteSNIDirectPromotionAllowed denies direct promotion from a
// white SNI match.
func GuidedSearchWhiteSNIDirectPromotionAllowed(whiteSNI, promoted bool) bool {
	if whiteSNI && promoted {
		abdInc(observability.MetricABDGuidedSearchWhiteSNIDirectPromotion)
		return false
	}
	return true
}

// GuidedSearchFalseSavingsReportAllowed denies reporting savings that the
// baseline set does not actually provide.
func GuidedSearchFalseSavingsReportAllowed(reportedSavings, realSavings int) bool {
	if reportedSavings > realSavings {
		abdInc(observability.MetricABDGuidedSearchFalseSavingsReport)
		return false
	}
	return true
}

// GuidedSearchRequiredComponentUncoveredAllowed denies a search result that
// leaves a required component uncovered.
func GuidedSearchRequiredComponentUncoveredAllowed(requiredComponents, coveredComponents []string) bool {
	covered := map[string]bool{}
	for _, c := range coveredComponents {
		covered[c] = true
	}
	for _, c := range requiredComponents {
		if !covered[c] {
			abdInc(observability.MetricABDGuidedSearchRequiredComponentUncovered)
			return false
		}
	}
	return true
}

// GuidedSearchCoverageIgnoredControlRegressionAllowed denies coverage
// decisions that ignore a control regression.
func GuidedSearchCoverageIgnoredControlRegressionAllowed(controlRegression, coverageExpanded bool) bool {
	if controlRegression && coverageExpanded {
		abdInc(observability.MetricABDGuidedSearchCoverageIgnoredControlRegression)
		return false
	}
	return true
}

// GuidedSearchCrossServiceSetCoverAllowed denies a set-cover decision that
// spans services.
func GuidedSearchCrossServiceSetCoverAllowed(coverSpansServices bool) bool {
	if coverSpansServices {
		abdInc(observability.MetricABDGuidedSearchCrossServiceSetCover)
		return false
	}
	return true
}

// GuidedSearchExcludedTargetHiddenAllowed denies hiding an excluded target
// from the coverage report.
func GuidedSearchExcludedTargetHiddenAllowed(excluded []string, reported []string) bool {
	reportedSet := map[string]bool{}
	for _, r := range reported {
		reportedSet[r] = true
	}
	for _, e := range excluded {
		if !reportedSet[e] {
			abdInc(observability.MetricABDGuidedSearchExcludedTargetHidden)
			return false
		}
	}
	return true
}

// GuidedSearchMoreComplexPreferredWithoutGainAllowed denies preferring a
// more complex candidate without measurable gain.
func GuidedSearchMoreComplexPreferredWithoutGainAllowed(complexCandidate, simpleCandidate int, gain float64) bool {
	if complexCandidate > simpleCandidate && gain <= 0 {
		abdInc(observability.MetricABDGuidedSearchMoreComplexPreferredNoGain)
		return false
	}
	return true
}

// GuidedSearchUnverifiedShortlistPromotionAllowed denies promoting from an
// unverified shortlist.
func GuidedSearchUnverifiedShortlistPromotionAllowed(shortlistVerified bool) bool {
	if !shortlistVerified {
		abdInc(observability.MetricABDGuidedSearchUnverifiedShortlist)
		return false
	}
	return true
}

// ---- §42.1. Monitoring adapter hard gates -----------------------------------

// MonitorRequestDirectActionAllowed denies a monitor request taking a direct
// action.
func MonitorRequestDirectActionAllowed(req monitor.MonitorDiagnosticRequest, directAction bool) bool {
	if req.RequestID != "" && directAction {
		abdInc(observability.MetricABDMonitorRequestDirectAction)
		return false
	}
	return true
}

// MonitorRequestWithoutTargetPlanOverlayAllowed denies a monitor request
// without a target plan overlay.
func MonitorRequestWithoutTargetPlanOverlayAllowed(req monitor.MonitorDiagnosticRequest) bool {
	if len(req.Overlay.TargetHashes) == 0 && req.Overlay.ResolutionSnapshotID == "" {
		abdInc(observability.MetricABDMonitorRequestWithoutTargetPlan)
		return false
	}
	return true
}

// MonitorRequestWithoutNetworkContextAllowed denies a monitor request
// without a network context.
func MonitorRequestWithoutNetworkContextAllowed(req monitor.MonitorDiagnosticRequest) bool {
	if strings.TrimSpace(req.Overlay.Scope.NetworkContextID) == "" {
		abdInc(observability.MetricABDMonitorRequestWithoutNetworkCtx)
		return false
	}
	return true
}

// MonitorRequestWithoutConfigGenerationAllowed denies a monitor request
// without a config generation.
func MonitorRequestWithoutConfigGenerationAllowed(req monitor.MonitorDiagnosticRequest) bool {
	if req.Overlay.ConfigGeneration == 0 {
		abdInc(observability.MetricABDMonitorRequestWithoutConfigGen)
		return false
	}
	return true
}

// MonitorRequestWithoutBudgetTokenAllowed denies a monitor request without a
// budget token.
func MonitorRequestWithoutBudgetTokenAllowed(budgetToken string) bool {
	if strings.TrimSpace(budgetToken) == "" {
		abdInc(observability.MetricABDMonitorRequestWithoutBudgetToken)
		return false
	}
	return true
}

// MonitorRequestExpiredAcceptedAllowed denies accepting an expired monitor
// request.
func MonitorRequestExpiredAcceptedAllowed(now, expiresAt time.Time) bool {
	if !expiresAt.IsZero() && !now.Before(expiresAt) {
		abdInc(observability.MetricABDMonitorRequestExpiredAccepted)
		return false
	}
	return true
}

// ProvisionalMonitorEvidenceProfileCompiledAllowed denies compiling a
// profile from provisional monitor evidence.
func ProvisionalMonitorEvidenceProfileCompiledAllowed(provisional, compiledReady bool) bool {
	if provisional && compiledReady {
		abdInc(observability.MetricABDProvisionalMonitorProfileCompiled)
		return false
	}
	return true
}

// PassiveObservationCountedAsIndependentProbeAllowed denies counting a
// passive observation as an independent active probe.
func PassiveObservationCountedAsIndependentProbeAllowed(passiveObserved, countedAsProbe bool) bool {
	if passiveObserved && countedAsProbe {
		abdInc(observability.MetricABDPassiveObservationAsIndependentProbe)
		return false
	}
	return true
}

// MonitorRecurrenceCountedAsIndependenceAllowed denies counting monitor
// recurrence as evidence independence.
func MonitorRecurrenceCountedAsIndependenceAllowed(recurrences, families int) bool {
	if recurrences > 0 && families >= recurrences {
		abdInc(observability.MetricABDMonitorRecurrenceAsIndependence)
		return false
	}
	return true
}

// ClientResolutionReplacedSilentlyAllowed denies replacing a client
// resolution without a recorded event.
func ClientResolutionReplacedSilentlyAllowed(snapshot monitor.ClientResolutionSnapshot, observedCount int, recorded bool) bool {
	if len(snapshot.Answers) != observedCount && !recorded {
		abdInc(observability.MetricABDClientResolutionReplacedSilently)
		return false
	}
	return true
}

// ProbeWithoutResolutionBindingAllowed denies probing without a resolution
// binding.
func ProbeWithoutResolutionBindingAllowed(snapshot monitor.ClientResolutionSnapshot) bool {
	if snapshot.SnapshotID == "" {
		abdInc(observability.MetricABDProbeWithoutResolutionBinding)
		return false
	}
	return true
}

// CnameTerminalIPMisattributedAllowed denies misattributing the CNAME
// terminal IP.
func CnameTerminalIPMisattributedAllowed(snapshot monitor.ClientResolutionSnapshot, endpoint monitor.ResolvedEndpoint) bool {
	for _, a := range snapshot.Answers {
		if a.IPHash == endpoint.IPHash {
			return true
		}
	}
	if len(snapshot.CNAMEChainHashes) > 0 && endpoint.IPHash != "" {
		abdInc(observability.MetricABDCnameTerminalIPMisattributed)
		return false
	}
	return true
}

// MultiIPPartialFailureHiddenAllowed denies hiding partial failure across a
// multi-IP set.
func MultiIPPartialFailureHiddenAllowed(outcomes []monitor.AddressOutcome, reportedSuccess bool) bool {
	partial := false
	for _, o := range outcomes {
		if strings.Contains(o.TCPOutcome, "fail") || strings.Contains(o.TLSOutcome, "fail") {
			partial = true
			break
		}
	}
	if partial && reportedSuccess {
		abdInc(observability.MetricABDMultiIPPartialFailureHidden)
		return false
	}
	return true
}

// StaleClientResolutionUsedAllowed denies using a stale client resolution.
func StaleClientResolutionUsedAllowed(snapshot monitor.ClientResolutionSnapshot, now time.Time) bool {
	if !snapshot.ValidUntil.IsZero() && !now.Before(snapshot.ValidUntil) {
		abdInc(observability.MetricABDStaleClientResolutionUsed)
		return false
	}
	return true
}

// ResultWithoutMonitorAssessmentLinkAllowed denies a result without a
// monitor assessment link.
func ResultWithoutMonitorAssessmentLinkAllowed(result monitor.ABDResult) bool {
	if result.RunID != "" && len(result.EvidenceRefs) == 0 {
		abdInc(observability.MetricABDResultWithoutAssessmentLink)
		return false
	}
	return true
}

// ResultCrossNetworkContextAllowed denies a result crossing network
// contexts.
func ResultCrossNetworkContextAllowed(a, b string) bool {
	if a != "" && b != "" && a != b {
		abdInc(observability.MetricABDResultCrossNetworkContext)
		return false
	}
	return true
}

// ResultCrossConfigGenerationAllowed denies a result crossing config
// generations.
func ResultCrossConfigGenerationAllowed(a, b uint64) bool {
	if a != 0 && b != 0 && a != b {
		abdInc(observability.MetricABDResultCrossConfigGeneration)
		return false
	}
	return true
}

// ResultCrossMonitoringEpochAllowed denies a result crossing monitoring
// epochs.
func ResultCrossMonitoringEpochAllowed(a, b string) bool {
	if a != "" && b != "" && a != b {
		abdInc(observability.MetricABDResultCrossMonitoringEpoch)
		return false
	}
	return true
}

// IncompleteRunFinalProfileAllowed denies finalizing a profile from an
// incomplete run.
func IncompleteRunFinalProfileAllowed(runComplete, profileFinal bool) bool {
	if !runComplete && profileFinal {
		abdInc(observability.MetricABDIncompleteRunFinalProfile)
		return false
	}
	return true
}

// MonitorResultActionAuthorizationAllowed denies a monitor result
// authorizing an action.
func MonitorResultActionAuthorizationAllowed(result monitor.ABDResult, actionAuthorized bool) bool {
	if result.RunID != "" && actionAuthorized {
		abdInc(observability.MetricABDMonitorResultActionAuthorization)
		return false
	}
	return true
}

// MonitorResultDeliveryIdentityMismatchAllowed denies delivering a result
// whose identity does not match the recipient scope.
func MonitorResultDeliveryIdentityMismatchAllowed(resultScope, deliveryScope monitor.MonitorScopeKey) bool {
	if resultScope.ClientScope.ID != "" && resultScope.ClientScope.ID != deliveryScope.ClientScope.ID {
		abdInc(observability.MetricABDMonitorResultDeliveryIdentityMismatch)
		return false
	}
	return true
}
