package monitoring

// Hard-gate producers for the continuous-blocking monitoring (MON)
// lifecycle (FB-02 MON section, §84-§92 of
// B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0).
// Each guard models one mandatory hard gate of the MON pipeline —
// observation authority, scope isolation, temporal separation, resolution
// binding, trigger/resource budgeting, multi-vantage evidence, the
// ABD/DDI/discovery chain, legacy-migration safety and
// reliability/privacy — reusing the evidence-only models in the monitor and
// detector packages.
//
// Every violating branch increments exactly one zero-tolerance counter from
// src/observability/mon.go; fixtures in hard_gate_producers_test.go drive
// each violating branch and assert the counter moved. No guard mutates
// configuration or takes a production action; guards only record whether a
// requested MON action would violate a mandatory hard gate.

import (
	"strings"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/observability"
)

func monInc(name string) {
	observability.Default().Metrics.Inc(name, nil, 1)
}

// ---- §84. Observation and authority gates --------------------------------

// ObservationDirectActionAllowed denies any action taken directly on an
// observation without the ABD escalation chain: a monitor observation must
// never authorize a direct production action by itself.
func ObservationDirectActionAllowed(obs monitor.MonitorObservation, viaEscalation bool) bool {
	if obs.ObservationID != "" && !viaEscalation {
		monInc(observability.MetricMONObservationDirectAction)
		return false
	}
	return true
}

// ProvisionalProfileCompiled denies compiling a blocking profile from a
// non-authoritative (provisional) ABD run: only authoritative runs may
// produce a ready profile.
func ProvisionalProfileCompiled(profile detector.BlockingProfile, authoritative bool) bool {
	if !authoritative && profile.Status == detector.ProfileReady {
		monInc(observability.MetricMONProvisionalProfileCompiled)
		return false
	}
	return true
}

// PassiveDiscoveryStart denies starting a discovery run from passive-only
// evidence: discovery requires an authoritative ABD input.
func PassiveDiscoveryStart(authority monitor.EvidenceAuthority) bool {
	if authority != monitor.AuthorityAuthoritativeABD {
		monInc(observability.MetricMONPassiveDiscoveryStart)
		return false
	}
	return true
}

// PassiveWarpEnable denies enabling the WARP transport from passive-only
// evidence: WARP promotion requires an authoritative profile.
func PassiveWarpEnable(warpEnabled, authoritative bool) bool {
	if warpEnabled && !authoritative {
		monInc(observability.MetricMONPassiveWarpEnable)
		return false
	}
	return true
}

// FastLaneActionTaken denies every fast-lane action: the fast lane is a
// provisional-only path that must never take a production action.
func FastLaneActionTaken(fastLane bool) bool {
	if fastLane {
		monInc(observability.MetricMONFastLaneAction)
		return false
	}
	return true
}

// FastLanePromotedAsAuthoritative denies promoting a fast-lane outcome to
// the authoritative evidence authority: only the ABD chain may produce
// authoritative evidence.
func FastLanePromotedAsAuthoritative(fastLane, authoritative bool) bool {
	if fastLane && authoritative {
		monInc(observability.MetricMONFastLanePromotedAsAuthoritative)
		return false
	}
	return true
}

// ---- §85. Scope gates -----------------------------------------------------

// DeepTriggerOnDestinationOnlyScope denies a deep diagnostic trigger on a
// destination-only scope (no client identity): deep runs require the full
// scope so the ABD evidence graph stays client-bounded.
func DeepTriggerOnDestinationOnlyScope(scope monitor.MonitorScopeKey, kind monitor.DiagnosticKind) bool {
	if kind == monitor.DiagnosticDeep && scope.ClientScope.ID == "" && scope.ClientScope.Role == "" {
		monInc(observability.MetricMONDestinationOnlyDeepTrigger)
		return false
	}
	return true
}

// CrossClientMergeAllowed denies merging observations from two distinct
// clients into one evidence set: the ABD graph is per-client.
func CrossClientMergeAllowed(a, b monitor.ClientScopeKey) bool {
	if a.ID != "" && b.ID != "" && a.ID != b.ID {
		monInc(observability.MetricMONCrossClientMerge)
		return false
	}
	return true
}

// CrossServiceMergeAllowed denies merging evidence across service profiles.
func CrossServiceMergeAllowed(a, b monitor.MonitorScopeKey) bool {
	if a.ServiceProfileID != "" && b.ServiceProfileID != "" && a.ServiceProfileID != b.ServiceProfileID {
		monInc(observability.MetricMONCrossServiceMerge)
		return false
	}
	return true
}

// CrossComponentMergeAllowed denies merging evidence across components.
func CrossComponentMergeAllowed(a, b monitor.MonitorScopeKey) bool {
	if a.ComponentID != "" && b.ComponentID != "" && a.ComponentID != b.ComponentID {
		monInc(observability.MetricMONCrossComponentMerge)
		return false
	}
	return true
}

// CrossWanEvidenceMergeAllowed denies merging evidence observed on two
// different WAN intervals (network contexts).
func CrossWanEvidenceMergeAllowed(a, b monitor.MonitorScopeKey) bool {
	if a.NetworkContextID != "" && b.NetworkContextID != "" && a.NetworkContextID != b.NetworkContextID {
		monInc(observability.MetricMONCrossWanEvidenceMerge)
		return false
	}
	return true
}

// CrossGenerationEvidenceMergeAllowed denies merging evidence from two
// different configuration generations.
func CrossGenerationEvidenceMergeAllowed(a, b monitor.MonitorScopeKey) bool {
	if a.ConfigGeneration != 0 && b.ConfigGeneration != 0 && a.ConfigGeneration != b.ConfigGeneration {
		monInc(observability.MetricMONCrossGenerationEvidenceMerge)
		return false
	}
	return true
}

// RouterOriginAsForwardedProofAllowed denies presenting a router-origin
// observation as a forwarded-client proof: forwarded evidence must carry a
// real forwarded client identity.
func RouterOriginAsForwardedProofAllowed(snap monitor.CorrelationSnapshot) bool {
	if snap.Forwarded && snap.RouterOrigin {
		monInc(observability.MetricMONRouterOriginAsForwardedProof)
		return false
	}
	return true
}

// ---- §86. Temporal gates --------------------------------------------------

// DuplicateEvidenceIndependenceAllowed denies counting a duplicated
// evidence reference as an independent evidence family.
func DuplicateEvidenceIndependenceAllowed(refs []string) bool {
	seen := map[string]bool{}
	for _, r := range refs {
		if r == "" {
			continue
		}
		if seen[r] {
			monInc(observability.MetricMONDupEvidenceIndependence)
			return false
		}
		seen[r] = true
	}
	return true
}

// TemporalPersistenceWithoutSeparationAllowed denies treating two events
// closer than the required separation as temporally persistent evidence.
func TemporalPersistenceWithoutSeparationAllowed(a, b time.Time, separation time.Duration) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	if separation > 0 && d < separation && !a.IsZero() && !b.IsZero() {
		monInc(observability.MetricMONTemporalPersistenceNoSeparation)
		return false
	}
	return true
}

// SuccessSuppressorIgnoredAllowed denies acting on a status while a success
// suppressor is active: suppressed status must never be consumed as health.
func SuccessSuppressorIgnoredAllowed(status monitor.MonitorStatus) bool {
	if status.Suppressed {
		monInc(observability.MetricMONSuccessSuppressorIgnored)
		return false
	}
	return true
}

// RecoveredSubjectNotDemotedAllowed denies keeping a recovered subject at
// full priority: a recovered subject must be demoted (disabled) until
// re-promotion through the ABD chain.
func RecoveredSubjectNotDemotedAllowed(subject monitor.MonitorSubject, health monitor.HealthState) bool {
	if health == monitor.HealthRecovered && subject.Enabled {
		monInc(observability.MetricMONRecoveredSubjectNotDemoted)
		return false
	}
	return true
}

// ExpiredEvidenceUsedAllowed denies using evidence past its expiry.
func ExpiredEvidenceUsedAllowed(now, expiresAt time.Time) bool {
	if !expiresAt.IsZero() && !now.Before(expiresAt) {
		monInc(observability.MetricMONExpiredEvidenceUsed)
		return false
	}
	return true
}

// DecayDisabledWithoutPolicyAllowed denies disabling evidence decay without
// an explicit decay policy: unbounded retention without a policy is a
// privacy and correctness violation.
func DecayDisabledWithoutPolicyAllowed(decayEnabled bool, policy string) bool {
	if !decayEnabled && strings.TrimSpace(policy) == "" {
		monInc(observability.MetricMONDecayDisabledWithoutPolicy)
		return false
	}
	return true
}

// ---- §87. Resolution gates ------------------------------------------------

// ProbeWithoutResolutionBindingAllowed denies probing a target that has no
// resolution binding: every probe must reference a client resolution
// snapshot.
func ProbeWithoutResolutionBindingAllowed(snapshot monitor.ClientResolutionSnapshot) bool {
	if snapshot.SnapshotID == "" {
		monInc(observability.MetricMONProbeWithoutResolutionBinding)
		return false
	}
	return true
}

// ClientDNSAnswerReplacedSilentlyAllowed denies replacing a client DNS
// answer without a recorded replacement event: any divergence between the
// observed answers and the stored resolution must be explicit.
func ClientDNSAnswerReplacedSilentlyAllowed(snapshot monitor.ClientResolutionSnapshot, observedCount int, replacementRecorded bool) bool {
	if len(snapshot.Answers) != observedCount && !replacementRecorded {
		monInc(observability.MetricMONClientDNSAnswerReplacedSilently)
		return false
	}
	return true
}

// CnameTerminalIPMisattributedAllowed denies attributing the terminal CNAME
// answer IP to the original query name: the CNAME chain must stay attached
// to the answer.
func CnameTerminalIPMisattributedAllowed(snapshot monitor.ClientResolutionSnapshot, endpoint monitor.ResolvedEndpoint) bool {
	for _, a := range snapshot.Answers {
		if a.IPHash == endpoint.IPHash {
			return true
		}
	}
	if len(snapshot.CNAMEChainHashes) > 0 && endpoint.IPHash != "" {
		monInc(observability.MetricMONCnameTerminalIPMisattributed)
		return false
	}
	return true
}

// MultiIPPartialFailureHiddenAllowed denies reporting success while part of
// a multi-IP address set failed: partial failure must be visible.
func MultiIPPartialFailureHiddenAllowed(outcomes []monitor.AddressOutcome, reportedSuccess bool) bool {
	partial := false
	for _, o := range outcomes {
		if strings.Contains(o.TCPOutcome, "fail") || strings.Contains(o.TLSOutcome, "fail") {
			partial = true
			break
		}
	}
	if partial && reportedSuccess {
		monInc(observability.MetricMONMultiIPPartialFailureHidden)
		return false
	}
	return true
}

// StaleResolutionUsedAsExactProofAllowed denies using an expired resolution
// snapshot as exact endpoint proof.
func StaleResolutionUsedAsExactProofAllowed(snapshot monitor.ClientResolutionSnapshot, now time.Time, exact bool) bool {
	if exact && !snapshot.ValidUntil.IsZero() && !now.Before(snapshot.ValidUntil) {
		monInc(observability.MetricMONStaleResolutionExactProof)
		return false
	}
	return true
}

// ---- §88. Trigger and resource gates --------------------------------------

// TriggerWithoutVisibilityAllowed denies triggering a diagnostic while the
// visibility snapshot is stale or absent.
func TriggerWithoutVisibilityAllowed(visibilityFresh bool) bool {
	if !visibilityFresh {
		monInc(observability.MetricMONTriggerWithoutVisibility)
		return false
	}
	return true
}

// TriggerWithoutBudgetAllowed denies triggering a diagnostic when the
// lease budget is exhausted.
func TriggerWithoutBudgetAllowed(available, needed int) bool {
	if needed > 0 && available < needed {
		monInc(observability.MetricMONTriggerWithoutBudget)
		return false
	}
	return true
}

// TriggerDuringGlobalWanFailureAllowed denies triggering client diagnostics
// while a global WAN failure is declared: the failure is not client-local.
func TriggerDuringGlobalWanFailureAllowed(globalWanFailure, trigger bool) bool {
	if trigger && globalWanFailure {
		monInc(observability.MetricMONTriggerDuringGlobalWanFailure)
		return false
	}
	return true
}

// TriggerWithStaleSourceHeartbeatAllowed denies triggering diagnostics from
// a source whose heartbeat is older than maxAge.
func TriggerWithStaleSourceHeartbeatAllowed(heartbeat, now time.Time, maxAge time.Duration) bool {
	if !heartbeat.IsZero() && maxAge > 0 && now.Sub(heartbeat) > maxAge {
		monInc(observability.MetricMONTriggerWithStaleHeartbeat)
		return false
	}
	return true
}

// DuplicateConcurrentABDRunAllowed denies starting an ABD run whose
// idempotency key already has an active run.
func DuplicateConcurrentABDRunAllowed(activeKeys []string, key string) bool {
	for _, k := range activeKeys {
		if k == key {
			monInc(observability.MetricMONDupConcurrentABDRun)
			return false
		}
	}
	return true
}

// UnboundedTargetIntakeAllowed denies an intake configuration without a
// bounded subject budget: the demand inbox must be bounded.
func UnboundedTargetIntakeAllowed(cfg monitor.IntakeConfig) bool {
	if cfg.MaxSubjects <= 0 || cfg.MaxPerClient <= 0 {
		monInc(observability.MetricMONUnboundedTargetIntake)
		return false
	}
	return true
}

// UnboundedProbeParallelismAllowed denies probe parallelism beyond the
// configured limit (a limit of zero means unbounded).
func UnboundedProbeParallelismAllowed(parallel, limit int) bool {
	if limit <= 0 || parallel > limit {
		monInc(observability.MetricMONUnboundedProbeParallelism)
		return false
	}
	return true
}

// SelfInterferenceAllowed denies overlapping own-target probes: probing
// your own monitored targets is self-interference.
func SelfInterferenceAllowed(overlappingTargets int) bool {
	if overlappingTargets > 0 {
		monInc(observability.MetricMONSelfInterference)
		return false
	}
	return true
}

// ---- §89. Multi-vantage gates ----------------------------------------------

// ReferenceResultAsActionAuthorizationAllowed denies treating a reference
// (baseline) result as the authorization for a production action: only a
// final action authorization may authorize.
func ReferenceResultAsActionAuthorizationAllowed(referenceResult, finalAuthorization bool) bool {
	if referenceResult && !finalAuthorization {
		monInc(observability.MetricMONReferenceResultAsAuthorization)
		return false
	}
	return true
}

// ---- §90. ABD/DDI/Discovery gates ------------------------------------------

// ABDRequestWithoutTargetPlanAllowed denies an ABD request that has no
// target plan overlay: the ABD run must know its targets up front.
func ABDRequestWithoutTargetPlanAllowed(req monitor.MonitorDiagnosticRequest) bool {
	if len(req.Overlay.TargetHashes) == 0 && req.Overlay.ResolutionSnapshotID == "" {
		monInc(observability.MetricMONABDRequestWithoutTargetPlan)
		return false
	}
	return true
}

// ABDPartialResultProfileReadyAllowed denies compiling a ready blocking
// profile from a partial ABD run.
func ABDPartialResultProfileReadyAllowed(run monitor.ABDRun, profile detector.BlockingProfile) bool {
	if run.State == monitor.RunPartial && profile.Status == detector.ProfileReady {
		monInc(observability.MetricMONABDPartialResultProfileReady)
		return false
	}
	return true
}

// ABDResultBypassedDDIAllowed denies consuming a complete ABD result that
// skipped the DDI guided-discovery stage.
func ABDResultBypassedDDIAllowed(result monitor.ABDResult, ddiRequested bool) bool {
	if result.Complete && !ddiRequested {
		monInc(observability.MetricMONABDResultBypassedDDI)
		return false
	}
	return true
}

// DiscoveryWithoutAuthoritativeProfileAllowed denies guided discovery
// without an authoritative ABD run reference.
func DiscoveryWithoutAuthoritativeProfileAllowed(req monitor.GuidedDiscoveryRequest) bool {
	if req.AuthoritativeABDRunID == "" {
		monInc(observability.MetricMONDiscoveryWithoutAuthProfile)
		return false
	}
	return true
}

// DiscoverySkippedMandatoryBaselineAllowed denies a guided discovery run
// that did not execute every mandatory baseline.
func DiscoverySkippedMandatoryBaselineAllowed(req monitor.GuidedDiscoveryRequest, executed []string) bool {
	ran := map[string]bool{}
	for _, e := range executed {
		ran[e] = true
	}
	for _, b := range req.MandatoryBaselines {
		if !ran[b] {
			monInc(observability.MetricMONDiscoverySkippedMandatoryBaseline)
			return false
		}
	}
	return true
}

// RecommendationWithoutScopeAllowed denies a transport recommendation that
// carries no valid scope.
func RecommendationWithoutScopeAllowed(rec monitor.TransportRecommendation) bool {
	if !rec.Scope.Valid() {
		monInc(observability.MetricMONRecommendationWithoutScope)
		return false
	}
	return true
}

// WarpRecommendationWithoutIPPathAllowed denies a WARP transport
// recommendation that carries no IP-path evidence.
func WarpRecommendationWithoutIPPathAllowed(rec monitor.TransportRecommendation) bool {
	if len(rec.PathEvidence) == 0 {
		monInc(observability.MetricMONWarpRecommendationWithoutIPPath)
		return false
	}
	return true
}

// ---- §91. Legacy migration gates -------------------------------------------

// LegacyWatchdogDirectApplyAllowed denies the legacy watchdog adapter
// applying a change directly, without the validation chain.
func LegacyWatchdogDirectApplyAllowed(applied, throughValidation bool) bool {
	if applied && !throughValidation {
		monInc(observability.MetricMONLegacyWatchdogDirectApply)
		return false
	}
	return true
}

// LegacyWatchdogCreatedUnvalidatedSetAllowed denies the legacy watchdog
// creating a routing set that was never validated.
func LegacyWatchdogCreatedUnvalidatedSetAllowed(created, validated bool) bool {
	if created && !validated {
		monInc(observability.MetricMONLegacyWatchdogUnvalidatedSet)
		return false
	}
	return true
}

// LegacyWatchdogOverwriteWithoutCanaryAllowed denies the legacy watchdog
// overwriting a live set without a passing canary milestone.
func LegacyWatchdogOverwriteWithoutCanaryAllowed(overwrote, canaryPassed bool) bool {
	if overwrote && !canaryPassed {
		monInc(observability.MetricMONLegacyWatchdogOverwriteNoCanary)
		return false
	}
	return true
}

// LegacyAPIProjectionMutationAllowed denies mutating the monitor status
// projection through the legacy API path: the projection is read-only by
// contract (the HTTP API is the only mutation path).
func LegacyAPIProjectionMutationAllowed(mutated bool) bool {
	if mutated {
		monInc(observability.MetricMONLegacyAPIProjectionMutation)
		return false
	}
	return true
}

// ShadowActiveWriterOverlapAllowed denies having shadow and active writers
// write the same state simultaneously.
func ShadowActiveWriterOverlapAllowed(shadow, active bool) bool {
	if shadow && active {
		monInc(observability.MetricMONShadowActiveWriterOverlap)
		return false
	}
	return true
}

// ---- §92. Reliability/privacy gates ----------------------------------------

// RequiredEventDropHiddenAllowed denies silently dropping required events
// without reflecting the drop in the reported counters.
func RequiredEventDropHiddenAllowed(dropped, reported, required int) bool {
	if dropped > 0 && reported < required {
		monInc(observability.MetricMONRequiredEventDropHidden)
		return false
	}
	return true
}

// SourceHeartbeatStaleAutoDiagnoseAllowed denies auto-diagnosing a source
// whose heartbeat is stale: stale sources must not trigger diagnostics
// automatically.
func SourceHeartbeatStaleAutoDiagnoseAllowed(autoDiagnosed bool, heartbeat, now time.Time, maxAge time.Duration) bool {
	if autoDiagnosed && !heartbeat.IsZero() && maxAge > 0 && now.Sub(heartbeat) > maxAge {
		monInc(observability.MetricMONSourceHeartbeatStaleAutoDiagnose)
		return false
	}
	return true
}

// CheckpointCorruptionFalseReadyAllowed denies treating a corrupted
// checkpoint as ready for cutover.
func CheckpointCorruptionFalseReadyAllowed(checkpoint monitor.MonitorCheckpoint, corrupted bool) bool {
	if corrupted && checkpoint.CutoverVersion != "" {
		monInc(observability.MetricMONCheckpointCorruptionFalseReady)
		return false
	}
	return true
}

// RestartReusedExpiredLeaseAllowed denies reusing a diagnostic lease that
// expired before the process restarted.
func RestartReusedExpiredLeaseAllowed(lease monitor.DiagnosticLease, now time.Time) bool {
	if !lease.ExpiresAt.IsZero() && !now.Before(lease.ExpiresAt) {
		monInc(observability.MetricMONRestartReusedExpiredLease)
		return false
	}
	return true
}

// SensitiveDNSHistoryExportAllowed denies exporting DNS history that
// carries a client resolution snapshot: query names are sensitive.
func SensitiveDNSHistoryExportAllowed(exported bool, snapshot monitor.ClientResolutionSnapshot) bool {
	if exported && snapshot.OriginalQNameHash != "" {
		monInc(observability.MetricMONSensitiveDNSHistoryExport)
		return false
	}
	return true
}

// SecretTraceLeakAllowed denies exporting a trace that still carries raw
// secret material (unredacted).
func SecretTraceLeakAllowed(exported, redacted bool) bool {
	if exported && !redacted {
		monInc(observability.MetricMONSecretTraceLeak)
		return false
	}
	return true
}

// HighCardinalityMetricLabelAllowed denies exporting a metric whose label
// cardinality exceeds the configured limit.
func HighCardinalityMetricLabelAllowed(labelCount, limit int) bool {
	if limit > 0 && labelCount > limit {
		monInc(observability.MetricMONHighCardinalityMetricLabel)
		return false
	}
	return true
}
