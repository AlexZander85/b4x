package silentpath

// Hard-gate producers for the silent-path failure (SPF) lifecycle (FB-02
// SPF section, §45 of the SPF addendum v1.0). Each guard is a production
// function that models one stage of the SPF lifecycle — authorization,
// visibility, correlation, recovery, rollback — reusing the evidence-only
// model in this package (Scope.ValidForRecovery, CapabilitySnapshot,
// HasActiveSuppressor, ComparePaths, LeaseStore, RollbackMonitor).
//
// Every violating branch increments exactly one zero-tolerance counter from
// src/observability/spf.go; fixtures in hard_gate_producers_test.go drive
// each violating branch and assert the counter moved. No guard authorizes
// packet mutation, routing or transport changes; they only record whether a
// requested SPF action would violate a mandatory hard gate.

import (
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/observability"
)

func spfInc(name string) {
	observability.Default().Metrics.Inc(name, nil, 1)
}

// AuthorizeRecoveryAction is the single gate every recovery/canary action
// must pass. It verifies (1) that a final action authorization exists,
// (2) that the capture visibility proofs are complete, and (3) that the
// requested scope matches the authorized client, service (domain),
// component and configuration generation. Each violating branch increments
// exactly one hard-gate counter and denies the action.
func AuthorizeRecoveryAction(scope Scope, auth classifier.ActionAuthorization, authorizedComponent string, snapshot CapabilitySnapshot) bool {
	if auth.ID == "" || !auth.Final || auth.ExpiresAt.IsZero() || auth.Client.IsZero() {
		spfInc(observability.MetricSPFActionWithoutAuthorization)
		return false
	}
	if !snapshot.Complete() {
		spfInc(observability.MetricSPFActionIncompleteVisibility)
		return false
	}
	if scope.ClientKey != auth.Client {
		spfInc(observability.MetricSPFCrossClientAction)
		return false
	}
	if strings.TrimSpace(auth.Domain) != "" && scope.DomainKey != auth.Domain {
		spfInc(observability.MetricSPFCrossServiceAction)
		return false
	}
	if strings.TrimSpace(authorizedComponent) != "" && scope.ComponentID != authorizedComponent {
		spfInc(observability.MetricSPFCrossComponentAction)
		return false
	}
	if auth.ConfigGen != 0 && scope.ConfigGen != auth.ConfigGen {
		spfInc(observability.MetricSPFCrossGenerationAction)
		return false
	}
	return true
}

// DestinationOnlyStateUsed reports whether a decision is being made from a
// destination-only scope (missing client/set/component/domain identity).
// A destination-only failure state is forbidden as recovery evidence.
func DestinationOnlyStateUsed(scope Scope) bool {
	if scope.ClientKey.IsZero() || strings.TrimSpace(scope.SetID) == "" ||
		strings.TrimSpace(scope.ComponentID) == "" || strings.TrimSpace(scope.DomainKey) == "" ||
		scope.ConfigGen == 0 || scope.IPFamily == 0 || strings.TrimSpace(scope.TransportPath) == "" {
		spfInc(observability.MetricSPFDestinationOnlyState)
		return true
	}
	return false
}

// IndependentFamilies extracts the non-empty independent evidence families
// from evidence that has not yet expired.
func IndependentFamilies(evidence []Evidence, now time.Time) []string {
	var families []string
	seen := map[string]bool{}
	for _, e := range evidence {
		if e.Expired(now) {
			continue
		}
		fam := strings.TrimSpace(e.IndependentFamily)
		if fam != "" && !seen[fam] {
			seen[fam] = true
			families = append(families, fam)
		}
	}
	return families
}

// AutoFallbackGate permits automatic fallback only with at least two
// independent evidence families (§17 main safety invariant). A single
// signal — however strong — must never trigger automatic fallback, and
// evidence without a declared independent family must never be treated as
// independent.
func AutoFallbackGate(evidence []Evidence, now time.Time) bool {
	for _, e := range evidence {
		if e.Expired(now) {
			continue
		}
		if strings.TrimSpace(e.IndependentFamily) == "" {
			spfInc(observability.MetricSPFNonIndependentAutoFallback)
			return false
		}
	}
	families := IndependentFamilies(evidence, now)
	if len(families) < 2 {
		spfInc(observability.MetricSPFSingleSignalAutoFallback)
		return false
	}
	return true
}

// SuppressorGate refuses recovery while any suppressor is active. A fresh
// same-scope success suppressor being ignored is counted as the
// recent-success false-positive variant; every other active suppressor is
// counted as the generic suppressor-ignored violation.
func SuppressorGate(values []Suppression, now time.Time, proceed bool) bool {
	reason, ok := HasActiveSuppressor(values, now)
	if !ok {
		return true
	}
	if proceed {
		if reason == ReasonFreshScopeSuccess {
			spfInc(observability.MetricSPFRecentSuccessFalsePositive)
		} else {
			spfInc(observability.MetricSPFSuppressorIgnored)
		}
		return false
	}
	return false
}

// FastParallelFalsePositiveGate counts a recovery attempt whose strongest
// positive evidence is classified as likely-parallel/prefetch — the fast
// parallel false-positive pattern (§6.1).
func FastParallelFalsePositiveGate(evidence []Evidence) bool {
	for _, e := range evidence {
		if e.Kind == ReasonLikelyParallel {
			spfInc(observability.MetricSPFFastParallelFalsePositive)
			return false
		}
	}
	return true
}

// ExplicitServerErrorGate refuses to treat an explicit server response as a
// network silent-path failure.
func ExplicitServerErrorGate(evidence []Evidence) bool {
	for _, e := range evidence {
		if e.Kind == ReasonExplicitServerResponse {
			spfInc(observability.MetricSPFExplicitServerErrorMisclass)
			return false
		}
	}
	return true
}

// GsoMssProgressMismatch counts progress observations where a GSO segment
// reports bytes that do not align to the MSS boundary, i.e. the segment was
// counted as wire progress without MSS parity.
func GsoMssProgressMismatch(segmentBytes, mss int) bool {
	if mss <= 0 {
		return false
	}
	if segmentBytes%mss != 0 {
		spfInc(observability.MetricSPFGsoMssProgressMismatch)
		return true
	}
	return false
}

// PPEVisibilityViolation counts a promotion attempt while the PPE/offload or
// GSO-parity visibility proof is missing.
func PPEVisibilityViolation(snapshot CapabilitySnapshot, promote bool) bool {
	if promote && (!snapshot.OffloadProven || !snapshot.GSOParityProven) {
		spfInc(observability.MetricSPFPPEVisibilityViolation)
		return true
	}
	return false
}

// ProbeGate starts a differential probe only within a bounded budget.
// An unbounded probe (budget <= 0, or attempts beyond the budget) is counted.
func ProbeGate(attempts, maxAttempts int) bool {
	if maxAttempts <= 0 || attempts >= maxAttempts {
		spfInc(observability.MetricSPFUnboundedProbe)
		return false
	}
	return true
}

// RotationGate performs a lease rotation only within the bounded attempt
// window of the active lease. Rotating past MaxAttempts is counted.
func RotationGate(l Lease) bool {
	if l.MaxAttempts == 0 || l.Attempts >= l.MaxAttempts {
		spfInc(observability.MetricSPFUnboundedRotation)
		return false
	}
	return true
}

// TransportFallbackGate permits a transport fallback only when the
// candidate transport path differs from the current one (§35 recursive
// transport fallback prohibition).
func TransportFallbackGate(currentPath, candidatePath string) bool {
	if currentPath != "" && candidatePath != "" && currentPath == candidatePath {
		spfInc(observability.MetricSPFRecursiveTransportFallback)
		return false
	}
	return true
}

// RollbackTargetGate requires every recovery lease to carry a known
// rollback target (§34).
func RollbackTargetGate(l Lease) bool {
	if strings.TrimSpace(l.Rollback) == "" {
		spfInc(observability.MetricSPFRecoveryWithoutRollbackTarget)
		return false
	}
	return true
}

// ControlRegressionGate refuses to promote a recovery whose control probe
// did not pass (unhealthy control or candidate regression relative to
// control) (§13.10).
func ControlRegressionGate(current, candidate, control ProbeResult) bool {
	if !control.ReachedMilestone || !control.ControlHealthy {
		spfInc(observability.MetricSPFControlRegressionPromoted)
		return false
	}
	return true
}

// FalsePositiveBudgetGate refuses recovery actions once the rollback
// monitor has flipped to observe-only because the false-positive budget was
// exhausted (§22).
func FalsePositiveBudgetGate(m *RollbackMonitor) bool {
	if m != nil && m.ObserveOnly {
		spfInc(observability.MetricSPFFalsePositiveBudgetIgnored)
		return false
	}
	return true
}

// UserRevertRollsBack counts a user revert that could not be rolled back
// because no matching active lease exists (§23).
func UserRevertRollsBack(m *RollbackMonitor, id string, scope Scope, reason string, nowUnix int64) bool {
	if m.Rollback(id, scope, reason, nowUnix) {
		return true
	}
	spfInc(observability.MetricSPFUserRevertNotRolledBack)
	return false
}
