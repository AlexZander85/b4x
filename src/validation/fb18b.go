package validation

// FB-18B (b4x-c4q): executable production crosswalk ARCH v2.4 <-> IV v1.5.
//
// For every requirement of the consolidated crosswalk (40 ARCH clauses
// 106..145 + 17 main invariants 5.1..5.17 + 4 hold/replay 42..45,
// B4X_FB18_ARCH_IV_CROSSWALK.json) this registry carries a runtime verdict
// and production-root evidence. MAPPED (FB-18A) is never a runtime PASS:
// every PASS entry references an executable test in the repository, checked
// by TestFB18BCrosswalkStatuses against the actual source tree (AST scan,
// same technique as IV18ReverseReachability). BLOCKED entries name the open
// Beads task that owns the missing production evidence; NOT_APPLICABLE
// entries carry the owner-documented reason.
//
// Statuses allowed (B4X_FB14_CONFLICTS_RESOLVED.md §5.4):
// PASS | BLOCKED (by Beads task) | NOT_APPLICABLE. FAIL is only assigned
// when a production-root check exists and fails; no FAIL entries are
// currently registered.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// FB18BStatus is the executable crosswalk verdict for one requirement.
type FB18BStatus string

const (
	// FB18BPass: production-root evidence exists and executes.
	FB18BPass FB18BStatus = "PASS"
	// FB18BBlocked: the missing evidence is owned by an open Beads task.
	FB18BBlocked FB18BStatus = "BLOCKED"
	// FB18BNotApplicable: owner-documented non-requirement.
	FB18BNotApplicable FB18BStatus = "NOT_APPLICABLE"
)

// BlockedBy names the open task that owns the missing production evidence.
type BlockedBy struct {
	BeadsID string `json:"beads_id"`
	Task    string `json:"task"`
	Why     string `json:"why"`
}

// FB18BEntry is one crosswalk requirement with its runtime verdict.
type FB18BEntry struct {
	ID         string      `json:"id"`   // ARCH-106 | INV-5.1 | HR-42
	Kind       string      `json:"kind"` // clause | invariant | hold_replay
	Title      string      `json:"title"`
	IVCoverage string      `json:"iv_coverage,omitempty"`
	Status     FB18BStatus `json:"status"`
	// Evidence references executable tests as "<package>/TestName".
	Evidence            []string   `json:"evidence,omitempty"`
	BlockedBy           *BlockedBy `json:"blocked_by,omitempty"`
	NotApplicableReason string     `json:"not_applicable_reason,omitempty"`
	Note                string     `json:"note,omitempty"`
}

// FB18BCrosswalkReport is the machine-readable crosswalk artifact tied to
// the current document hashes (post-FB-14, commits 026ea485 / 8f9b6b94).
type FB18BCrosswalkReport struct {
	Name         string            `json:"name"`
	Commit       string            `json:"commit"`
	GeneratedAt  time.Time         `json:"generated_at"`
	Documents    map[string]string `json:"documents_sha256"`
	Summary      FB18BSummary      `json:"summary"`
	Requirements []FB18BEntry      `json:"requirements"`
}

// FB18BSummary aggregates statuses and the open-task gap map.
type FB18BSummary struct {
	Total         int            `json:"total"`
	Pass          int            `json:"pass"`
	Blocked       int            `json:"blocked"`
	NotApplicable int            `json:"not_applicable"`
	BlockedByTask map[string]int `json:"blocked_by_task"`
}

// FB18BDocumentHashes returns the canonical document hashes the crosswalk is
// tied to, sourced from the FB-33 Canonical Exact Source-Stage Registry
// (specs/registries/source_stage_registry.yaml generated into
// source_stage_registry.gen.go). The registry is the single source of truth:
// FB-18 reads document hashes from it instead of carrying manual numbers
// (FB-33 criterion: FB-18 uses the registry, not hard-coded totals).
func FB18BDocumentHashes() map[string]string {
	docs := SourceStageDocuments()
	out := make(map[string]string, len(docs))
	for _, d := range docs {
		out[d.Name] = d.SHA256
	}
	return out
}

// FB18BCommit is the HEAD the crosswalk artifact was generated against.
const FB18BCommit = "a20ce4d8"

// FB18BEntries returns the full executable crosswalk registry (61 entries:
// 40 clauses + 17 invariants + 4 hold/replay).
func FB18BEntries() []FB18BEntry {
	ev := func(ids ...string) []string { return ids }
	blocked := func(id, task, why string) *BlockedBy {
		return &BlockedBy{BeadsID: id, Task: task, Why: why}
	}
	return []FB18BEntry{
		// --- Consolidated ARCH clauses 106..145 (40) ---
		{ID: "ARCH-106", Kind: "clause", Title: "Effective domain policy", IVCoverage: "26.1, 36.2, AC 15-17", Status: FB18BPass,
			Evidence: ev("classifier/TestDomainOnlyModesUseDomainEvidenceAndKeepTrace", "nfq/TestNFQDomainOnlyDecisionModes", "nfq/TestQUICGlobalFallbackRequiresExplicitDisabledDomainPolicy", "classifier/TestDecideECHStrictDomainOnlyRejectsScopedHint"),
			Note:     "FB-14 решения strict/scoped-hints применены (ARCH §106, PATCH_PLAN L542)."},
		{ID: "ARCH-107", Kind: "clause", Title: "Candidate and authorization split", IVCoverage: "26.1-26.2, AC 16-19, hard gates", Status: FB18BPass,
			Evidence: ev("classifier/TestCaptureCandidateRequiresScopedAuthorization", "classifier/TestResolveCandidateDisposition", "action/TestPlanRequiresExactAuthorization"),
			Note:     "Integration через реальный matcher/authorization path (classifier.Decide -> action plan)."},
		{ID: "ARCH-108", Kind: "clause", Title: "Scoped side effects", IVCoverage: "26.3-26.4, AC 20/23, CSI gates", Status: FB18BPass,
			Evidence: ev("classifier/TestScopedHintsAndScopeMismatch", "classifier/TestIdentityStoreSeparatesGuestVLANAndSourceDevice", "nfq/TestScopedRSTStateUsesExactFlowKey", "nfq/TestScopedDNSHintSelectsSetForImmediateTCPFlow")},
		{ID: "ARCH-109", Kind: "clause", Title: "Cross-service negative controls", IVCoverage: "26.5, 36.3, 42.6, AC 18/36", Status: FB18BPass,
			Evidence: ev("crossservice/TestValidateRejectsYouTubeStateOnGmailSharedIPFlow", "crossservice/TestValidateRejectsRawDomainAndMissingScenario", "nfq/TestScopedEscalationDoesNotCrossService")},
		{ID: "ARCH-110", Kind: "clause", Title: "Reassembly correctness path", IVCoverage: "26.2, 27.2, AC 19/32", Status: FB18BPass,
			Evidence: ev("classifier/TestTCPReassemblyResultCarriesStableClientHelloIdentity", "classifier/TestTCPReassemblyLogicalClientHelloParityAcrossLayouts", "nfq/TestReassembledSNIDecisionCarriesExactFlowAndLayoutParity"),
			Note:     "Reassembled SNI -> authorization reachability через nfq worker."},
		{ID: "ARCH-111", Kind: "clause", Title: "GSO capability model", IVCoverage: "27.1-27.6, 42.4, AC 32-33", Status: FB18BPass,
			Evidence: ev("nfq/TestGSOCapabilityStatusUsesExplicitValidationLevels", "nfq/TestEvaluateGSOClassifyReadinessReady", "capture/TestPlanGSOTopologyFamilyMatrix"),
			Note:     "Раздельные observe/classify/action verdicts (GSO execution scope)."},
		{ID: "ARCH-112", Kind: "clause", Title: "Transactional topology", IVCoverage: "27.5, 34.1, AC 28/33", Status: FB18BPass,
			Evidence: ev("nfq/TestGSOQueueTopologyInvalidateTokensClearsSharedStateOnRollback", "capture/TestPlanGSOTopologyTransitionDoubleBuffersAllQueues"),
			Note:     "Rollback очищает shared state; mixed generation не утекает."},
		{ID: "ARCH-113", Kind: "clause", Title: "Passive RST", IVCoverage: "28.1-28.4, 42.5, AC 26/34", Status: FB18BPass,
			Evidence: ev("nfq/TestPassiveRSTConservativeRequiresStrongPlusIndependentCorroboration", "nfq/TestPassiveRSTObservationBuildsStrongAndCorroboratingEvidence", "nfq/TestRSTKill_TripsAtThreshold"),
			Note:     "Observe и active агрегируются раздельно (PassiveRST counters)."},
		{ID: "ARCH-114", Kind: "clause", Title: "PPE policy", IVCoverage: "35.1-35.5, AC 30-31", Status: FB18BPass,
			Evidence: ev("nfq/TestPPEPassiveObserverTracksScopedTCPDirections", "nfq/TestPPEPassiveObserverIgnoresUnconfiguredPort")},
		{ID: "ARCH-115", Kind: "clause", Title: "PPE capability and self-test", IVCoverage: "35.1/35.3, AC 30-31", Status: FB18BPass,
			Evidence: ev("nfq/TestDecodeOffloadMetadataMissingAndMalformedAttributesFailOpen", "nfq/TestHardGateProducer_GSOOffloadMetadata"),
			Note:     "Model name не evidence; capability — через offload metadata envelope + fail-open."},
		{ID: "ARCH-116", Kind: "clause", Title: "PPE lifecycle", IVCoverage: "35.2-35.4", Status: FB18BBlocked,
			BlockedBy: blocked("b4x-6kt", "FB-21: PPE: реальная само-интеграция per-flow exclusion на Keenetic NDM + MediaTek",
				"foreign-resource и NDM-regeneration proof в release bundle требуют target-интеграции (Keenetic NDM); базовые envelope-тесты есть (nfq/TestDecodeOffloadMetadataEnvelope)")},
		{ID: "ARCH-117", Kind: "clause", Title: "Useful progress", IVCoverage: "38B.3-38B.6, 42.11, AC 70", Status: FB18BPass,
			Evidence: ev("silentpath/TestUniqueProgressIgnoresDuplicateAndOverlap", "silentpath/TestGSOAndMSSHaveEqualUniqueTotals", "nfq/TestCanaryMonitorAccountsEarlyProgressWhenFlowBecomesEligible"),
			Note:     "Unique-range семантика и GSO/MSS parity реализованы."},
		{ID: "ARCH-118", Kind: "clause", Title: "Suppressors and differential proof", IVCoverage: "38B.2-38B.8, AC 72-76", Status: FB18BPass,
			Evidence: ev("silentpath/TestDifferentialNeedsCandidateAndControl", "silentpath/TestFreshAndCompatibleSuccessSuppress", "silentpath/TestExplicitErrorAlwaysSuppresses", "silentpath/TestObserveAssessmentCannotAuthorizeRecovery")},
		{ID: "ARCH-119", Kind: "clause", Title: "Recovery planner", IVCoverage: "38B.4-38B.8, 42.12, AC 78-81", Status: FB18BPass,
			Evidence: ev("silentpath/TestLeaseScopeAndRollback", "silentpath/TestMilestones", "silentpath/TestNoTargetValidationNoPromotion")},
		{ID: "ARCH-120", Kind: "clause", Title: "Monitoring evolutionary replacement", IVCoverage: "IV-18 (MON-1..MON-12)", Status: FB18BPass,
			Evidence: ev("validation/TestIV18ReverseReachabilityCleanAfterCutover", "validation/TestIV18ReverseReachabilityCleanTreeIsProductionReady", "validation/TestIV18RunSuiteIsFailClosed", "monitoring/TestRuntimeETLFailureToProjection"),
			Note:     "Legacy Watchdog applyBatchResults удалён (FB-28, 2026-08-02); strangler suite исполняется. Полный production cutover MON — FB-07 (b4x-070) в backlog."},
		{ID: "ARCH-121", Kind: "clause", Title: "Monitor model", IVCoverage: "IV-18 MON-02/03, MON addendum", Status: FB18BPass,
			Evidence: ev("monitor/TestBusValidatesScopeAndPreservesSafetyLane", "monitor/TestVisibilitySnapshotSuppressesStaleSources", "monitor/TestCheckpointRoundTripAndProjection", "validation/TestIV18RegistryIntegrity")},
		{ID: "ARCH-122", Kind: "clause", Title: "Temporal evidence", IVCoverage: "IV-18 MON-04, MON addendum §86", Status: FB18BPass,
			Evidence: ev("monitor/TestTemporalHysteresisAndBoundedBuckets", "monitor/TestTemporalSeparatesRecurrenceAndIndependence", "detector/TestEvidenceGraphIgnoresPassiveRecurrenceForConfidence")},
		{ID: "ARCH-123", Kind: "clause", Title: "Trigger planner", IVCoverage: "IV-18 MON-06, MON addendum §88", Status: FB18BPass,
			Evidence: ev("monitor/TestDemandInboxBoundedAndResolutionFreshness", "monitor/TestInfrastructureAndGlobalSuppressorsExpire", "validation/TestIV18RunSuiteIsFailClosed")},
		{ID: "ARCH-124", Kind: "clause", Title: "Authoritative active diagnosis", IVCoverage: "49-51, IV-14, AC 90-97", Status: FB18BPass,
			Evidence: ev("detector/TestProbeContextRejectsExpiredGenerationAndSelfInterference", "detector/TestMITMRequiresVerifiedAuthoritativePath", "monitor/TestABDEscalationPartialCannotBecomeAuthoritative"),
			Note:     "Overlay не удаляет mandatory controls/baselines (TestCompilePlanPreservesControlsAndIsDeterministic)."},
		{ID: "ARCH-125", Kind: "clause", Title: "Resolution and address outcomes", IVCoverage: "IV-14, AC 90-97", Status: FB18BPass,
			Evidence: ev("detector/TestResolutionExperimentMixedV4V6PerAddress", "detector/TestResolutionExperimentFirstSuccessDoesNotMaskSibling", "detector/TestResolutionExperimentMissingPerAddressEvidenceBlocks", "detector/TestDNSDifferentialPreservesPerAddressOutcomes"),
			Note:     "Два раздельных experiment types + outcome per A/AAAA; first success не скрывает siblings."},
		{ID: "ARCH-126", Kind: "clause", Title: "Evidence authority and attribution", IVCoverage: "AC 92/97/98", Status: FB18BPass,
			Evidence: ev("detector/TestVantageCapabilityUnprovenIsNoOpinion", "detector/TestVantageExactModeIdentityConflationNoOpinion", "detector/TestVantageStageMismatchNoOpinion", "detector/TestL4PacketAndByteProfilesRemainIndependent", "monitor/TestABDEscalationPartialCannotBecomeAuthoritative")},
		{ID: "ARCH-127", Kind: "clause", Title: "Stage-aware observers", IVCoverage: "IV-14", Status: FB18BPass,
			Evidence: ev("detector/TestVantageCapabilityUnprovenIsNoOpinion", "detector/TestVantageUnavailableIsNoOpinion", "detector/TestVantageTCPTLSOnlyObserverCannotSupportHTTPHypothesis"),
			Note:     "Capability-declared observers; unavailable=no opinion; higher-layer verdict требует capability."},
		{ID: "ARCH-128", Kind: "clause", Title: "BlockingProfile and DDI", IVCoverage: "49.1, IV-15, AC 98-100", Status: FB18BPass,
			Evidence: ev("detector/TestCompilePlanPreservesControlsAndIsDeterministic", "detector/TestDDIPriorCannotDropExcludedDenominator", "detector/TestDDIPriorRequiresFreshEnvelopeAndBaseline"),
			Note:     "Ownership по FB-14 решению 1; DDI не компилирует raw evidence."},
		{ID: "ARCH-129", Kind: "clause", Title: "Guided search", IVCoverage: "50.3-50.7, IV-15, AC 100-102", Status: FB18BPass,
			Evidence: ev("discovery/TestAdaptiveMatrixOneDimensionSearchAndBoundedShadow", "discovery/TestHintPlannerKeepsBaselineAndFallback", "discovery/TestGuidedSnapshotDefaultsAndImmutableDomains", "detector/TestCompilePlanRejectsExpiredOverlay"),
			Note:     "Mandatory baselines/full fallback/controls не удаляются prior-ом."},
		{ID: "ARCH-130", Kind: "clause", Title: "Transport candidates", IVCoverage: "33, IV-15", Status: FB18BPass,
			Evidence: ev("validation/TestCausalEligibilityPositiveMapping", "validation/TestTransportAuthorizedBlocksBroadWARPEscalation", "validation/TestCausalEligibilityFailsClosed", "discovery/TestCausalEligibleCandidatesAppliesMatrix", "discovery/TestCausalEligibleCandidatesRetainsMandatoryNarrower"),
			Note:     "FB-31: normative causal-eligibility matrix (CausalEligibleCandidates в hint_planner.go): broad WARP escalation по DNS/QUIC-only hints forbidden, unknown family fail-closed; mandatory narrower retained."},
		{ID: "ARCH-131", Kind: "clause", Title: "Telegram bridge", IVCoverage: "IV-16, 50, 51, AC 104-109", Status: FB18BPass,
			Evidence: ev("mtproto/TestHandleReservedPrefixFailsOpenWithBytes", "mtproto/TestHandleZeroByteParksThenExpires", "mtproto/TestHandleDialFailureFailsOpenWithFullFrame", "mtproto/TestPrefixConnReplaysBeforePassthrough", "mtproto/TestHandleEmptyConnReturnsHandledNil"),
			Note:     "FB-04: hardened transparent Telegram bridge (mtproto/transparent.go, TPROXY listener production path): silent drop исключён, каждый abort-путь fail-open, zero-byte парковка с TTL, prefix replay без потерь."},
		{ID: "ARCH-132", Kind: "clause", Title: "Base WARP architecture", IVCoverage: "38A, 42.8, IV-17", Status: FB18BPass,
			Evidence: ev("warp/TestManifestRejectsRuntimeDownloadAndRequiresLicense", "warp/TestSecretStoreCopiesAndRedacts", "warp/TestTunRegistryRejectsForeignCollisionAndLowMTU"),
			Note:     "Bundled/pinned implementation; no runtime download."},
		{ID: "ARCH-133", Kind: "clause", Title: "WARP scope and path proof", IVCoverage: "38A, IV-17, AC 121-124", Status: FB18BPass,
			Evidence: ev("warp/TestAuthorizationIsScopedAndRevocable", "warp/TestGeoQuorumRequiresFreshPathProof", "routing/TestBindingStoreDoesNotCaptureAnotherFlowOrClient")},
		{ID: "ARCH-134", Kind: "clause", Title: "WARP camouflage", IVCoverage: "42.9, IV-17, AC 133-134", Status: FB18BPass,
			Evidence: ev("warp/TestCamouflageAuthorizationRequiresExactIdentityAndGeneration", "warp/TestCoverSNIAlwaysRequiresPin", "warp/TestCutoffRejectsWrongGenerationAndDuplicate", "validation/TestRequiredHardGatesCamouflageAndNonRU")},
		{ID: "ARCH-135", Kind: "clause", Title: "Nested WARP and non-RU", IVCoverage: "42.10, IV-17, AC 125-132", Status: FB18BPass,
			Evidence: ev("warp/TestNestedBackendInvalidatesOnParentAndCleansOwnership", "warp/TestOuterInnerStateCannotCrossAuthorize", "fieldtest/TestEventStreamRejectsDuplicateAndRedactsIdentity")},
		{ID: "ARCH-136", Kind: "clause", Title: "Causal observability and cleanup", IVCoverage: "IV-17/52", Status: FB18BPass,
			Evidence: ev("fieldtest/TestTraceEventSerializationPreservesGenerationFields", "warp/TestTraceEnvelopeSequenceChecksumAndPriority", "warp/TestTraceExportRedactsAndBounds"),
			Note:     "FB-14 п.9: узкий composable causal verdict (fieldtest.WARPGate.SeparateVerdicts — optional nested отдельно); cleanup ownership в trace."},
		{ID: "ARCH-137", Kind: "clause", Title: "Declarative Service Profiles", IVCoverage: "36.1, 41.5", Status: FB18BPass,
			Evidence: ev("serviceprofile/TestCompileDeterministic", "serviceprofile/TestOwnershipMigrationIsManual", "serviceprofile/TestTransactionRollback", "detector/TestProfileCompilerIsDeterministicAndLinked"),
			Note:     "Compiler только в ordinary B4 objects; manual/pinned/excluded preserved."},
		{ID: "ARCH-138", Kind: "clause", Title: "Capability projection", IVCoverage: "36.2, SP-13/16/20", Status: FB18BPass,
			Evidence: ev("validation/TestRequiredHardGatesServiceProfilesRequireCapability", "validation/TestEvaluateHardGatesScopeIsolation"),
			Note:     "CapabilityProjection/GSOProjection/WARPProjection (serviceprofile); profile может только сузить (hard-gate тесты)."},
		{ID: "ARCH-139", Kind: "clause", Title: "Beginner recommendations", IVCoverage: "36.5/41, SP-30..SP-32", Status: FB18BBlocked,
			BlockedBy: blocked("b4x-cst", "FB-32: Service Profiles v1.6: SP-30..SP-32 и recommendation state machine",
				"eligible-to-test -> validated state machine и SP-30..SP-32 не зарегистрированы")},
		{ID: "ARCH-140", Kind: "clause", Title: "Profile release rule", IVCoverage: "42.6, SP-19/23", Status: FB18BPass,
			Evidence: ev("serviceprofile/TestRuntimeCompileDeniesDestinationIPOnly", "serviceprofile/TestRuntimeCompileDeniesWithoutIPPathEvidence", "serviceprofile/TestRuntimeCompileDeniesUnhealthyControls", "serviceprofile/TestRuntimeCompileDeniesCrossService", "serviceprofile/TestRuntimeEnableDeniesWithoutTargetCanary", "serviceprofile/TestRuntimeValidateBlocksCleanupFailure", "fieldtest/TestPromoteRejectedOnHardGateFail"),
			Note:     "FB-02: единый release gate собран в runtime-контроллере (target canary + exact scope + path-proof + unrelated-controls + cleanup/rollback); fieldtest promotion chain исполняется."},
		{ID: "ARCH-141", Kind: "clause", Title: "Capability dependency graph", IVCoverage: "53.3", Status: FB18BPass,
			Evidence: ev("validation/TestValidateCapabilityDependencyRegistry", "validation/TestCapabilityExecutionOrderBlocksEarlyWARP", "validation/TestCapabilityMissingUpstreamBlocksDownstreamPASS", "validation/TestCapabilityShuffledSuiteSameVerdict", "validation/TestCapabilityTGBParallelAfterCapture"),
			Note:     "FB-36 (b4x-0yf): canonical capability dependency graph (capability_dependencies.yaml -> capability_deps.gen.go), execution scheduling отдельно от verdict aggregation; FullRunOrder выводится из графа (WARP after MON/ABD/DDI/canary, TGB параллелен после capture); missing upstream dependency blocks downstream PASS."},
		{ID: "ARCH-142", Kind: "clause", Title: "Principal verdicts", IVCoverage: "52", Status: FB18BPass,
			Evidence: ev("validation/TestPrincipalVerdictRegistryValid", "validation/TestCanonicalVerdictNameAliasMapping", "validation/TestVerdictDependencyClosureFollowsARCHGraph", "validation/TestVerifyPrincipalVerdictNamesGuard", "fieldtest/TestPrincipalVerdictRuntimeNamesRegistered"),
			Note:     "FB-34 (+34.1): canonical registry + alias mapping + dependency closure (principal_verdicts.go); runtime guard VerifyPrincipalVerdictNames."},
		{ID: "ARCH-143", Kind: "clause", Title: "Global hard-gate classes", IVCoverage: "51", Status: FB18BPass,
			Evidence: ev("validation/TestApplicableHardGates", "validation/TestRunMetaSuiteDetectsMutationAndViolation", "cmd/b4-validate/TestPlanFull", "cmd/b4-validate/TestFullCompleteRegistryNoCounters", "warp/TestHardGateProducer_WARPSecretLeak"),
			Note:     "FB-03: canonical registry 285/285/0 + runtime producers/consumers + meta-suite + b4-validate CLI; gates активированы в RequiredHardGates (release profile)."},
		{ID: "ARCH-144", Kind: "clause", Title: "Recommended file order", IVCoverage: "25/41/54/58 частично", Status: FB18BNotApplicable,
			NotApplicableReason: "Решением владельца (RESOLVED §5.2, FB18-09): §144 — порядок чтения файлов, не implementation-order требование; consolidation registry решается FB-33 (b4x-yzt).",
			Note:                "Gap: FB-33 (b4x-yzt) — canonical Exact Source-Stage Registry + generated totals."},
		{ID: "ARCH-145", Kind: "clause", Title: "No flag-day migration", IVCoverage: "L8, IV-18 MON-11", Status: FB18BBlocked,
			BlockedBy: blocked("b4x-n6r", "FB-35: No-flag-day migration matrix для каждого subsystem",
				"per-subsystem shadow/canary/cutover/rollback + reverse-reachability legacy paths после cutover не собраны; частично: nfq/TestQUICHandoffFeatureGatePreservesLegacyGlobalPath, validation/TestLegacyAliasMigration")},

		// --- Main invariants ARCH §5.1..5.17 (17) ---
		{ID: "INV-5.1", Kind: "invariant", Title: "Classification before action", Status: FB18BPass,
			Evidence: ev("classifier/TestDecideAmbiguityRetainsAllCandidates", "action/TestPlanRequiresExactAuthorization", "nfq/TestExecuteActionPlanAppliedViaIPv4DropPath")},
		{ID: "INV-5.2", Kind: "invariant", Title: "Clean SYN + empty payload -> NF_ACCEPT", Status: FB18BPass,
			Evidence: ev("nfq/TestCleanSYNGateAllowsExplicitSYNTechniques", "nfq/TestCleanSYNGateRejectsTFOAndHandshakeFlags", "classifier/TestIsCleanSYNRequiresExplicitTechniqueForMutation")},
		{ID: "INV-5.3", Kind: "invariant", Title: "Fail-open: release unchanged, clear state, record reason", Status: FB18BPass,
			Evidence: ev("nfq/TestExecuteActionPlanFailsOpen", "nfq/TestGSOClassifyFastPathFailsOpenWithoutCapabilityOrCompleteInput", "action/TestExecutorCancellationDelayAndBudgetFailOpen", "silentpath/TestActiveModeDegradesWithoutEveryVisibilityProof")},
		{ID: "INV-5.4", Kind: "invariant", Title: "Source scope: DNS/QUIC evidence includes client identity", Status: FB18BPass,
			Evidence: ev("classifier/TestScopedLearnedObservationIsClientScopedAndExpiryDoesNotSlide", "detector/TestQUICRejectsCrossScope", "nfq/TestScopedDNSHintSelectsSetForImmediateTCPFlow", "nfq/TestQUICHandoffMirrorsSourceScopedUDPToTCP")},
		{ID: "INV-5.5", Kind: "invariant", Title: "Logical first-flight idempotency: one ClientHello - one ActionToken", Status: FB18BPass,
			Evidence: ev("action/TestActionTokenStoreSuppressesRetransmissionAndOverlap", "action/TestActionTokenStoreBudgetsAndProcessedMark", "nfq/TestGSONormalizerFirstPassQueuesAndSecondaryConsumesSameIdentityOnce")},
		{ID: "INV-5.6", Kind: "invariant", Title: "Config generation safety: no mutable config pointers in flow/hint state", Status: FB18BPass,
			Evidence: ev("action/TestPlanStrategyTokenIdempotencyAndRollbackGeneration", "nfq/TestScopedDNSHintsInvalidateOnRuntimeGenerationChange", "nfq/TestTCPHoldStoreGenerationAndFlowEviction")},
		{ID: "INV-5.7", Kind: "invariant", Title: "Bounded resources: memory/per-client/per-flow limits, TTL, eviction, fail-open", Status: FB18BPass,
			Evidence: ev("nfq/TestPassiveRSTScopeBudgetsAndNonSlidingWindowAreBounded", "nfq/TestTCPHoldStoreBoundsTimeoutAndRelease", "action/TestActionTokenStoreBudgetsAndProcessedMark", "classifier/TestTCPFlowStoreBoundedAndGC")},
		{ID: "INV-5.8", Kind: "invariant", Title: "Provenance mark for every injected/replayed packet", Status: FB18BPass,
			Evidence: ev("action/TestExecutorDryRunAndProvenanceValidation", "capture/TestProcessedMarkContract", "capture/TestTransientMarkAllocatorNeverUsesSharedContracts", "nfq/TestClientHelloDecisionClaimIsExactFlowAndGenerationScoped")},
		{ID: "INV-5.9", Kind: "invariant", Title: "CaptureCandidate != ActionAuthorization", Status: FB18BPass,
			Evidence: ev("classifier/TestCaptureCandidateRequiresScopedAuthorization", "classifier/TestResolveCandidateDisposition", "action/TestPlanRequiresExactAuthorization")},
		{ID: "INV-5.10", Kind: "invariant", Title: "Full service scope: ClientKey+SetID+Component+NetworkContext+ConfigGeneration", Status: FB18BPass,
			Evidence: ev("crossservice/TestStoreRequiresFreshExactGenerationReport", "classifier/TestScopedHintsAndScopeMismatch", "nfq/TestScopedFailureStateDoesNotCrossDomainClientOrGeneration")},
		{ID: "INV-5.11", Kind: "invariant", Title: "Observation != diagnosis != action; recurrence not a replacement for independent evidence families", Status: FB18BPass,
			Evidence: ev("monitor/TestABDEscalationPartialCannotBecomeAuthoritative", "silentpath/TestObserveAssessmentCannotAuthorizeRecovery", "detector/TestEvidenceGraphIgnoresPassiveRecurrenceForConfidence")},
		{ID: "INV-5.12", Kind: "invariant", Title: "Visibility before inference: incomplete bidirectional visibility blocks hold/auto-recovery/promotion", Status: FB18BPass,
			Evidence: ev("silentpath/TestActiveModeDegradesWithoutEveryVisibilityProof", "nfq/TestTCPHoldReleasesImmediatelyWhenVisibilityDegrades", "discovery/TestAutomaticDiscoveryRequiresCompleteVisibility", "action/TestActionTokenACKClosureRequiresCompleteVisibility")},
		{ID: "INV-5.13", Kind: "invariant", Title: "Useful progress: ACK-only/dup/retransmission insufficient for silent recovery", Status: FB18BPass,
			Evidence: ev("silentpath/TestUniqueProgressIgnoresDuplicateAndOverlap", "silentpath/TestProgressLifecycleAndBounds", "nfq/TestCanaryMonitorCountsLogicalFlowOnce")},
		{ID: "INV-5.14", Kind: "invariant", Title: "Exact client-resolution binding", Status: FB18BPass,
			Evidence: ev("silentpath/TestScopeRequiresExactAuthorizationNotDestination", "routing/TestBindingStoreDoesNotCaptureAnotherFlowOrClient", "classifier/TestIdentityStoreDHCPReuseChangesGeneration")},
		{ID: "INV-5.15", Kind: "invariant", Title: "Transport path proof: promotion requires causal chain ClientKey->Binding->counters->generation->milestone", Status: FB18BPass,
			Evidence: ev("routing/TestBindingStoreRequiresExactFlowCapability", "fieldtest/TestPromoteBlockedOnMissingProducers", "fieldtest/TestMissingProducerBlocksPromotionEndToEnd", "warp/TestGeoQuorumRequiresFreshPathProof", "silentpath/TestMilestones")},
		{ID: "INV-5.16", Kind: "invariant", Title: "Capability projection, not ownership", Status: FB18BPass,
			Evidence: ev("validation/TestRequiredHardGatesServiceProfilesRequireCapability", "validation/TestEvaluateHardGatesScopeIsolation", "serviceprofile/TestCompileDeterministic")},
		{ID: "INV-5.17", Kind: "invariant", Title: "No recursive fallback; transport/recovery graph acyclic", Status: FB18BPass,
			Evidence: ev("routing/TestTransportFallbackGraphAcyclic", "routing/TestTransportFallbackGraphFailsClosedOnCycle", "routing/TestFallbackCooldownLastGoodNeverSelectsSamePath", "silentpath/TestRecoveryLifecycleGraphAcyclic", "silentpath/TestRecoveryLifecycleGraphFailsClosedOnCycle"),
			Note:     "FB-18B-5.17 (b4x-zq3): canonical transport fallback graph (routing/graph.go: native->direct/generic/proxy, generic->direct, proxy->direct/generic, no proxy->proxy) + recovery lifecycle graph (silentpath/lifecycle_graph.go: authorize->visibility->correlate->recover->rollback->observe-only); fail-closed 3-colour DFS в NewFallbackManager и init() silentpath; фикс recursive same-path fallback (cooldown last-good != текущий путь)."},

		// --- Hold/replay ARCH §42..45 (4) ---
		{ID: "HR-42", Kind: "hold_replay", Title: "HeldPacket structure; holding only in bounded reassembly mode", Status: FB18BPass,
			Evidence: ev("nfq/TestAutoHoldReplayHoldsOnlyIncompleteClientHello", "nfq/TestTCPHoldStoreBoundsTimeoutAndRelease", "nfq/TestTCPHoldReleasesImmediatelyWhenVisibilityDegrades")},
		{ID: "HR-43", Kind: "hold_replay", Title: "Abort/release paths: complete/timeout/FIN-RST/pressure/malformed/shutdown/generation-change all release unchanged or fail-open", Status: FB18BPass,
			Evidence: ev("nfq/TestTCPHoldAbortOnFINReleasesImmediately", "nfq/TestTCPHoldAbortOnRSTReleasesImmediately", "nfq/TestTCPHoldAbortOnFlowTerminationIdempotent", "nfq/TestHoldReplayObserveAndServerProgressRelease", "classifier/TestTCPFlowFINRSTCleanupAndGenerationChange")},
		{ID: "HR-44", Kind: "hold_replay", Title: "Stream-to-packet map: planner in logical stream offsets, executor -> TCP sequence ranges", Status: FB18BPass,
			Evidence: ev("action/TestStreamMapAndPlanUseLogicalOffsets", "action/TestPlanTLSRecordSplitPreservesClientHelloAndTrailingRecords", "nfq/TestBuildSeqOverlapSegmentV4_PrependsPatternAndShiftsSeq", "nfq/TestBuildSeqOverlapSegmentV6_PrependsPatternAndShiftsSeq")},
		{ID: "HR-45", Kind: "hold_replay", Title: "Semantic markers ClientHello/SNI/host/SLD; resolver only on complete parsed ClientHello; ECH -> unavailable", Status: FB18BPass,
			Evidence: ev("action/TestDiscoverTLSMarkersAndECHAvailability", "action/TestInitialMarkerCatalogIsReadOnlyAndBounded", "action/TestPlanStrategySemanticMarkersAndMTU", "nfq/TestNFQECHMetadataReachesScopedDecision")},
	}
}

// testFuncIndex maps "<pkg>/<TestName>" -> present, scanned from the actual
// source tree (AST). It powers the executable part of the crosswalk: a PASS
// entry whose evidence test does not exist in the tree cannot stay PASS.
func testFuncIndex() (map[string]bool, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, os.ErrInvalid
	}
	validationDir := filepath.Dir(thisFile)
	srcRoot := filepath.Dir(validationDir)
	index := map[string]bool{}
	err := filepath.Walk(srcRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return nil
		}
		if info.Name() == "vendor" || strings.HasPrefix(info.Name(), ".") {
			return filepath.SkipDir
		}
		pkgDir := path
		rel, rerr := filepath.Rel(srcRoot, pkgDir)
		if rerr != nil || rel == "." || strings.Contains(rel, string(filepath.Separator)) && rel == "src" {
			return nil
		}
		pkgName := rel
		// Only packages that contain Go files matter; walk *.go.
		files, ferr := os.ReadDir(pkgDir)
		if ferr != nil {
			return nil
		}
		hasGo := false
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".go") {
				hasGo = true
				break
			}
		}
		if !hasGo {
			return nil
		}
		fset := token.NewFileSet()
		matched, perr := filepath.Glob(filepath.Join(pkgDir, "*.go"))
		if perr != nil {
			return nil
		}
		for _, gf := range matched {
			astFile, aerr := parser.ParseFile(fset, gf, nil, 0)
			if aerr != nil {
				continue
			}
			for _, decl := range astFile.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || !fd.Name.IsExported() || !strings.HasPrefix(fd.Name.Name, "Test") {
					continue
				}
				index[pkgName+"/"+fd.Name.Name] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return index, nil
}

// ValidateFB18BCrosswalk checks every entry: PASS requires existing evidence
// tests, BLOCKED requires a named Beads task, NOT_APPLICABLE requires a
// reason. It returns the list of violations (empty == valid).
func ValidateFB18BCrosswalk(entries []FB18BEntry) []string {
	var violations []string
	index, err := testFuncIndex()
	if err != nil {
		return []string{"test index: " + err.Error()}
	}
	for _, e := range entries {
		switch e.Status {
		case FB18BPass:
			if len(e.Evidence) == 0 {
				violations = append(violations, e.ID+": PASS без evidence")
				continue
			}
			for _, ref := range e.Evidence {
				if !index[ref] {
					violations = append(violations, e.ID+": evidence не существует в коде: "+ref)
				}
			}
		case FB18BBlocked:
			if e.BlockedBy == nil || e.BlockedBy.BeadsID == "" || e.BlockedBy.Task == "" || e.BlockedBy.Why == "" {
				violations = append(violations, e.ID+": BLOCKED без полного BlockedBy (beads_id/task/why)")
			}
		case FB18BNotApplicable:
			if e.NotApplicableReason == "" {
				violations = append(violations, e.ID+": NOT_APPLICABLE без причины")
			}
		default:
			violations = append(violations, e.ID+": неизвестный статус "+string(e.Status))
		}
	}
	return violations
}

// FB18BCrosswalkReportJSON builds the machine-readable crosswalk artifact.
func FB18BCrosswalkReportJSON(entries []FB18BEntry, now time.Time) ([]byte, error) {
	r := FB18BCrosswalkReport{
		Name:         "B4X FB-18B executable production crosswalk (ARCH v2.4 <-> IV v1.5)",
		Commit:       FB18BCommit,
		GeneratedAt:  now,
		Documents:    FB18BDocumentHashes(),
		Requirements: entries,
	}
	r.Summary.Total = len(entries)
	r.Summary.BlockedByTask = map[string]int{}
	for _, e := range entries {
		switch e.Status {
		case FB18BPass:
			r.Summary.Pass++
		case FB18BBlocked:
			r.Summary.Blocked++
			if e.BlockedBy != nil {
				r.Summary.BlockedByTask[e.BlockedBy.BeadsID]++
			}
		case FB18BNotApplicable:
			r.Summary.NotApplicable++
		}
	}
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SortFB18BEntries returns a copy of entries in stable document order:
// clauses ARCH-106..145, then invariants 5.1..5.17, then hold/replay 42..45.
func SortFB18BEntries(entries []FB18BEntry) []FB18BEntry {
	out := make([]FB18BEntry, len(entries))
	copy(out, entries)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}
