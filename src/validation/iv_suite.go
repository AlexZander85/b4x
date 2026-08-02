package validation

import (
	"sort"
	"time"
)

// FB-28 (b4x-pp4): IV-18 Continuous Monitoring conformance suite.
//
// The suite registers the mandatory monitoring scenarios MON-1..MON-12 and
// the field projections FT-MON-A..FT-MON-J as canonical requirements
// (B4X_AUDIT_FIX_TASKS v2.md §FB-28; ARCH-120:123). Coverage maps each
// requirement to executed monitor tests; a requirement without coverage is
// fail-closed: the suite verdict cannot be PASS while missing coverage
// exists, mirroring the meta-suite semantics (missing evidence is never PASS).

const (
	// IV18SuiteID is the canonical implementation-validation suite identifier.
	IV18SuiteID = "IV-18"

	iv18Stage     = "iv-18"
	iv18MONSuite  = "iv-18-mon"
	iv18FTSuite   = "iv-18-ft"
	iv18MONSource = "B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md"
	iv18FTSource  = "B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md"
	iv18TaskSource = "B4X_AUDIT_FIX_TASKS v2.md §FB-28"
)

// IV18Result is the machine-readable suite execution result (FB-28
// acceptance: a registered suite that executes and never false-passes).
type IV18Result struct {
	SuiteID            string                `json:"suite_id"`
	Registered         int                   `json:"registered_requirements"`
	Covered            int                   `json:"covered_requirements"`
	MissingCoverage    []string              `json:"missing_coverage,omitempty"`
	ProductionReady    bool                  `json:"production_ready"`
	LegacyMutatingHits []ReachabilityHit     `json:"legacy_mutating_hits,omitempty"`
	BlockedDependencies []ProductionDependency `json:"blocked_dependencies,omitempty"`
	Verdict            Verdict               `json:"verdict"`
	CheckedAt          time.Time             `json:"checked_at"`
}

// IV18Requirements returns the canonical IV-18 requirement list
// (MON-1..MON-12, FT-MON-A..FT-MON-J). Every requirement is blocking:
// monitoring conformance is P0-NORMATIVE for the monitoring release scope.
func IV18Requirements() []Requirement {
	return []Requirement{
		{ID: "IV-18-MON-01", Description: "ObservationBus bounded ingestion and backpressure", Source: iv18MONSource + " §85", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-02", Description: "full scope subjects and assessments (client/service/component/WAN keys)", Source: iv18MONSource + " §85", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-03", Description: "resolution snapshots (exact endpoint, independent current resolution)", Source: iv18MONSource + " §87", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-04", Description: "temporal buckets, recurrence, decay, independence, contradictions", Source: iv18MONSource + " §86", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-05", Description: "source health (heartbeat freshness, stale source suppression)", Source: iv18MONSource + " §88, §92", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-06", Description: "quick/deep trigger budgets and suppressors (bounded, expiring)", Source: iv18MONSource + " §88", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-07", Description: "production chain MON -> ABD -> DDI (fresh authoritative inputs only)", Source: iv18MONSource + " §90", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-08", Description: "no passive observation -> direct mutation (authority separation)", Source: iv18MONSource + " §84", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-09", Description: "reverse reachability: legacy Watchdog mutating path unreachable for MON_PRODUCTION_READY", Source: iv18MONSource + " §91", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-10", Description: "restart, storage pressure, privacy, meta-mutations safety", Source: iv18MONSource + " §92", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-11", Description: "event-driven cutover and rollback (strangler lifecycle)", Source: iv18MONSource + " §91", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-MON-12", Description: "observation/authority gate conformance (all §84 gates == 0 while observing passively)", Source: iv18MONSource + " §84", Stage: iv18Stage, Suite: iv18MONSuite, Blocking: true},
		{ID: "IV-18-FT-MON-A", Description: "field: bounded ingestion under production load", Source: iv18FTSource + " / " + iv18TaskSource, Stage: iv18Stage, Suite: iv18FTSuite, Blocking: true},
		{ID: "IV-18-FT-MON-B", Description: "field: multi-device subject/assessment scope", Source: iv18FTSource + " / " + iv18TaskSource, Stage: iv18Stage, Suite: iv18FTSuite, Blocking: true},
		{ID: "IV-18-FT-MON-C", Description: "field: per-address A/AAAA resolution outcomes", Source: iv18FTSource + " / " + iv18TaskSource, Stage: iv18Stage, Suite: iv18FTSuite, Blocking: true},
		{ID: "IV-18-FT-MON-D", Description: "field: temporal recurrence and decay behavior", Source: iv18FTSource + " / " + iv18TaskSource, Stage: iv18Stage, Suite: iv18FTSuite, Blocking: true},
		{ID: "IV-18-FT-MON-E", Description: "field: source heartbeat health across devices", Source: iv18FTSource + " / " + iv18TaskSource, Stage: iv18Stage, Suite: iv18FTSuite, Blocking: true},
		{ID: "IV-18-FT-MON-F", Description: "field: quick/deep trigger budgets under real traffic", Source: iv18FTSource + " / " + iv18TaskSource, Stage: iv18Stage, Suite: iv18FTSuite, Blocking: true},
		{ID: "IV-18-FT-MON-G", Description: "field: MON -> ABD -> DDI chain end-to-end", Source: iv18FTSource + " / " + iv18TaskSource, Stage: iv18Stage, Suite: iv18FTSuite, Blocking: true},
		{ID: "IV-18-FT-MON-H", Description: "field: passive observation never mutates directly", Source: iv18FTSource + " / " + iv18TaskSource, Stage: iv18Stage, Suite: iv18FTSuite, Blocking: true},
		{ID: "IV-18-FT-MON-I", Description: "field: legacy Watchdog reachability monitored", Source: iv18FTSource + " / " + iv18TaskSource, Stage: iv18Stage, Suite: iv18FTSuite, Blocking: true},
		{ID: "IV-18-FT-MON-J", Description: "field: cutover/rollback and telemetry privacy", Source: iv18FTSource + " / " + iv18TaskSource, Stage: iv18Stage, Suite: iv18FTSuite, Blocking: true},
	}
}

// IV18Coverage maps every IV-18 requirement to the executed monitor tests
// that prove it (unit-level evidence; field projections reuse the invariants
// until field runs are registered as artifacts).
func IV18Coverage() []Coverage {
	return []Coverage{
		{RequirementID: "IV-18-MON-01", TestID: "TestBusValidatesScopeAndPreservesSafetyLane", Verdict: "unit"},
		{RequirementID: "IV-18-MON-01", TestID: "TestSchedulerOverloadIsBounded", Verdict: "unit"},
		{RequirementID: "IV-18-MON-02", TestID: "TestDemandInboxBoundedAndResolutionFreshness", Verdict: "unit"},
		{RequirementID: "IV-18-MON-03", TestID: "TestCorrelationKeepsAddressFailuresAndDoesNotTreatSYNACKAsSuccess", Verdict: "unit"},
		{RequirementID: "IV-18-MON-04", TestID: "TestTemporalSeparatesRecurrenceAndIndependence", Verdict: "unit"},
		{RequirementID: "IV-18-MON-04", TestID: "TestTemporalHysteresisAndBoundedBuckets", Verdict: "unit"},
		{RequirementID: "IV-18-MON-05", TestID: "TestVisibilitySnapshotSuppressesStaleSources", Verdict: "unit"},
		{RequirementID: "IV-18-MON-06", TestID: "TestInfrastructureAndGlobalSuppressorsExpire", Verdict: "unit"},
		{RequirementID: "IV-18-MON-06", TestID: "TestSchedulerCoalescesAndLeases", Verdict: "unit"},
		{RequirementID: "IV-18-MON-07", TestID: "TestDDIAndDiscoveryRequireFreshAuthoritativeInputs", Verdict: "unit"},
		{RequirementID: "IV-18-MON-07", TestID: "TestRecommendationRequiresIPPathEvidence", Verdict: "unit"},
		{RequirementID: "IV-18-MON-07", TestID: "TestABDEscalationRejectsScopeMismatch", Verdict: "unit"},
		{RequirementID: "IV-18-MON-08", TestID: "TestABDEscalationPartialCannotBecomeAuthoritative", Verdict: "unit"},
		{RequirementID: "IV-18-MON-09", TestID: "TestIV18ReverseReachabilityBlocksProductionReadyWhileLegacyReachable", Verdict: "unit"},
		{RequirementID: "IV-18-MON-09", TestID: "TestLegacyForceCheckOnlyQueuesBoundedDiagnostic", Verdict: "unit"},
		{RequirementID: "IV-18-MON-10", TestID: "TestCheckpointRoundTripAndProjection", Verdict: "unit"},
		{RequirementID: "IV-18-MON-11", TestID: "TestCanaryRollbackIsObservationOnly", Verdict: "unit"},
		{RequirementID: "IV-18-MON-12", TestID: "TestIV18GateConformanceZeroToleranceAtZeroCounters", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-A", TestID: "TestSchedulerOverloadIsBounded", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-B", TestID: "TestDemandInboxBoundedAndResolutionFreshness", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-C", TestID: "TestCorrelationKeepsAddressFailuresAndDoesNotTreatSYNACKAsSuccess", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-C", TestID: "TestDemandInboxBoundedAndResolutionFreshness", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-D", TestID: "TestTemporalSeparatesRecurrenceAndIndependence", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-E", TestID: "TestVisibilitySnapshotSuppressesStaleSources", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-F", TestID: "TestInfrastructureAndGlobalSuppressorsExpire", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-G", TestID: "TestDDIAndDiscoveryRequireFreshAuthoritativeInputs", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-G", TestID: "TestRecommendationRequiresIPPathEvidence", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-H", TestID: "TestABDEscalationPartialCannotBecomeAuthoritative", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-I", TestID: "TestIV18ReverseReachabilityBlocksProductionReadyWhileLegacyReachable", Verdict: "unit"},
		{RequirementID: "IV-18-FT-MON-J", TestID: "TestCanaryRollbackIsObservationOnly", Verdict: "unit"},
	}
}

// IV18Registry returns the suite as a canonical Registry value (hashable,
// orphan-reportable) so IV-18 participates in the same integrity tooling as
// the hard-gate registry.
func IV18Registry() Registry {
	return Registry{
		Version:      RegistryVersion,
		AddendumHash: "fb28-iv18-monitoring-conformance",
		Requirements: IV18Requirements(),
		Coverage:     IV18Coverage(),
	}
}

// IV18MissingCoverage lists requirement IDs that have no executed coverage.
func IV18MissingCoverage() []string {
	return IV18Registry().Orphans(map[string]bool{iv18Stage: true})
}

// RunIV18Suite executes the suite as a registry/meta conformance check
// (FB-28 acceptance: "registered CLI/API suite executes"). The verdict is
// fail-closed: PASS only when every registered requirement has executed
// coverage, the legacy mutating path is unreachable
// (legacy_mutating_reachability == 0), AND no production dependency of the
// cutover is missing. Removing the legacy path alone never produces a false
// PASS: while the production monitoring chain or /api/monitor/v1 is not yet
// wired the verdict is BLOCKED with the blocked dependencies listed
// (owner decision 2026-08-02).
func RunIV18Suite() IV18Result {
	requirements := IV18Requirements()
	missing := IV18MissingCoverage()
	reach := IV18ReverseReachability("")
	blockedDeps := IV18ProductionDependenciesBlocked()
	verdict := Pass
	if len(missing) > 0 || !reach.ProductionReady || len(blockedDeps) > 0 {
		verdict = Blocked
	}
	sort.Strings(missing)
	return IV18Result{
		SuiteID:            IV18SuiteID,
		Registered:         len(requirements),
		Covered:            len(requirements) - len(missing),
		MissingCoverage:    missing,
		ProductionReady:    reach.ProductionReady && len(blockedDeps) == 0,
		LegacyMutatingHits: reach.Hits,
		BlockedDependencies: blockedDeps,
		Verdict:            verdict,
		CheckedAt:          time.Now().UTC(),
	}
}
