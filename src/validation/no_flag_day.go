package validation

// FB-35 (b4x-n6r): canonical no-flag-day migration matrix (ARCH §145, L8,
// IV-18 MON-11).
//
// Every large subsystem must follow observe/shadow/canary/cutover phases.
// Compatibility surfaces remain until parity and rollback are proven, and
// legacy unsafe direct-apply paths are disabled before the new subsystem is
// declared production-ready (§145). This registry is the single source of
// truth that maps each applicable subsystem to its current migration phase
// and, for cutover-complete subjects, the reverse-reachability artifact that
// proves the legacy mutating path is unreachable from production code.
//
// The registry is executable: TestNoFlagDayMigrationMatrixValid checks the
// structural invariants, TestNoFlagDayMatrixEvidenceExists verifies every
// referenced evidence test exists in the source tree (AST scan), and
// TestNoFlagDayCutoverReverseReachability* run the real reverse-reachability
// probes over the production tree / a seeded fixture (same scan reused via
// ReverseReachabilityFor).

// MigrationStatus is the current phase of one migration subject.
type MigrationStatus string

const (
	// MigrationShadowActive: the new subsystem runs beside the legacy
	// surface (feature-gated), compatibility is preserved, parity is being
	// collected, no cutover yet.
	MigrationShadowActive MigrationStatus = "shadow_active"
	// MigrationCutoverComplete: the production path switched to the new
	// subsystem and the legacy mutating path is provably unreachable
	// (reverse reachability clean); rollback is a config flip, not a code
	// restore.
	MigrationCutoverComplete MigrationStatus = "cutover_complete"
)

// MigrationSubject is one row of the matrix: a large subsystem and its
// current migration phase with executable evidence.
type MigrationSubject struct {
	// ID is a stable unique identifier of the subsystem migration.
	ID string
	// Title is a short human-readable description (legacy -> new).
	Title string
	// Status is the current phase of the migration.
	Status MigrationStatus
	// LegacyMutatingSymbol names a production symbol of the legacy mutating
	// direct-apply path that must be unreachable after cutover. It is the
	// reverse-reachability probe used by
	// TestNoFlagDayCutoverReverseReachabilityClean ("" when the subject has
	// no removed mutating symbol, e.g. shadow-only).
	LegacyMutatingSymbol string
	// NewPathSymbols lists production symbols that must exist once the new
	// subsystem is production-ready. It is the forward-reachability probe
	// (productionCallExists) used by the cutover reverse-reachability test.
	NewPathSymbols []string
	// Evidence lists executable tests (as "<pkg>/<TestName>") that prove the
	// subject's migration phase (shadow parity, cutover, rollback).
	Evidence []string
}

// MigrationMatrix is the canonical ARCH §145 migration matrix. The registry
// is checked structurally by TestNoFlagDayMigrationMatrixValid: every subject
// must carry at least one runnable evidence test; cutover subjects must also
// define the legacy mutating symbol they remove and the new production
// symbols that replace it.
func MigrationMatrix() []MigrationSubject {
	return []MigrationSubject{
		{
			ID:     "monitoring",
			Title:  "ContinuousBlockingMonitor over legacy Watchdog (FB-28, IV-18 MON-11 §57.1)",
			Status: MigrationCutoverComplete,
			// applyBatchResults (src/watchdog/applier.go) was the last legacy
			// direct-apply path; FB-28 cutover removed it (2026-08-02).
			LegacyMutatingSymbol: "applyBatchResults",
			NewPathSymbols:       []string{"monitor.NewObservationBus", "monitor.NewDiagnosticScheduler"},
			Evidence: []string{
				"validation/TestIV18ReverseReachabilityCleanAfterCutover",
				"validation/TestIV18ReverseReachabilitySeededReactivationCaught",
				"validation/TestIV18ProductionDependenciesFailClosed",
				"http/handler/TestWatchdogCutoverMutatingEndpointsGone",
				"http/handler/TestWatchdogPreCutoverMutatingNotGone",
				"http/handler/TestWatchdogCutoverStatusServesMonitoringProjection",
				"http/handler/TestWatchdogCutoverStatusWithoutRuntime",
			},
		},
		{
			ID:     "nfq-quic-handoff",
			Title:  "QUIC->TCP handoff: source-scoped hints (feature-gated) beside legacy global learned-IP path",
			Status: MigrationShadowActive,
			Evidence: []string{
				"nfq/TestQUICHandoffFeatureGatePreservesLegacyGlobalPath",
				"nfq/TestQUICHandoffMirrorsSourceScopedUDPToTCP",
			},
		},
		{
			ID:     "nfq-tcp-reassembly",
			Title:  "NFQ TCP reassembly: observe-only feature-gated path (legacy immediate forwarding preserved)",
			Status: MigrationShadowActive,
			Evidence: []string{
				"nfq/TestNFQTCPReassemblyIsObserveOnlyAndFeatureGated",
			},
		},
		{
			ID:     "hard-gate-alias-migration",
			Title:  "Legacy hard-gate metric names: canonical registry + compat aliases (no double count, no flag-day rename)",
			Status: MigrationShadowActive,
			Evidence: []string{
				"validation/TestLegacyAliasMigration",
				"validation/TestEvaluateHardGatesAliasDoesNotDoubleCount",
			},
		},
	}
}

// MigrationStatuses enumerates the allowed matrix statuses (structural
// invariant for TestNoFlagDayMigrationMatrixValid).
func MigrationStatuses() []MigrationStatus {
	return []MigrationStatus{MigrationShadowActive, MigrationCutoverComplete}
}
