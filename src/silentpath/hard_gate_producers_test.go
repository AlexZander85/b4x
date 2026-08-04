package silentpath

// Hard-gate producer fixtures for the silent-path failure (SPF) lifecycle
// (FB-02 SPF section, §45 of the SPF addendum v1.0). Each test drives the
// real production guard in src/silentpath/hard_gate_producers.go that emits
// a registered hard-gate metric and asserts the counter moved. All
// twenty-two gates are zero-tolerance violation counters, so every fixture
// is a negative fixture: it exercises the violating branch and asserts the
// counter incremented.
//
// These tests are referenced from specs/registries/hard_gates.yaml
// (test_producer / mutation_test / evidence_artifact) and from
// artifacts/remediation/FB02_SILENTPATH_PRODUCERS.json.

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/observability"
)

func spfClient(ip string) classifier.ClientKey {
	return classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr(ip), IfIndex: 2, VLAN: 10}
}

func spfCounterValue(t *testing.T, name string) uint64 {
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

func assertSPFInc(t *testing.T, name string, trigger func()) {
	t.Helper()
	observability.Default().Metrics.Reset()
	before := spfCounterValue(t, name)
	trigger()
	after := spfCounterValue(t, name)
	if after <= before {
		t.Fatalf("%s: expected violating branch to increment counter, before=%d after=%d", name, before, after)
	}
}

func spfAuth(now time.Time) classifier.ActionAuthorization {
	return classifier.ActionAuthorization{
		ID:        "auth-1",
		Client:    spfClient("192.0.2.10"),
		SetID:     "set-a",
		Domain:    "example.com",
		ConfigGen: 7,
		Final:     true,
		ExpiresAt: now.Add(time.Hour),
	}
}

func spfScope() Scope {
	return Scope{
		ClientKey:     spfClient("192.0.2.10"),
		SetID:         "set-a",
		ComponentID:   "web",
		DomainKey:     "example.com",
		ConfigGen:     7,
		IPFamily:      4,
		TransportPath: "direct",
	}
}

func spfCompleteSnapshot() CapabilitySnapshot {
	return CapabilitySnapshot{IncomingComplete: true, OutgoingComplete: true, QueueHealthy: true, GSOParityProven: true, OffloadProven: true}
}

func spfEvidence(kind ReasonCode, family string) Evidence {
	return Evidence{Kind: kind, IndependentFamily: family, ExpiresAt: time.Now().Add(time.Hour)}
}

func TestHardGateProducer_SPFActionWithoutAuthorization(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFActionWithoutAuthorization, func() {
		now := time.Now()
		auth := spfAuth(now)
		auth.Final = false
		AuthorizeRecoveryAction(spfScope(), auth, "web", spfCompleteSnapshot())
	})
}

func TestHardGateProducer_SPFActionIncompleteVisibility(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFActionIncompleteVisibility, func() {
		AuthorizeRecoveryAction(spfScope(), spfAuth(time.Now()), "web", CapabilitySnapshot{IncomingComplete: true})
	})
}

func TestHardGateProducer_SPFDestinationOnlyState(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFDestinationOnlyState, func() {
		scope := spfScope()
		scope.ClientKey = classifier.ClientKey{}
		DestinationOnlyStateUsed(scope)
	})
}

func TestHardGateProducer_SPFCrossClientAction(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFCrossClientAction, func() {
		scope := spfScope()
		scope.ClientKey = spfClient("192.0.2.11")
		AuthorizeRecoveryAction(scope, spfAuth(time.Now()), "web", spfCompleteSnapshot())
	})
}

func TestHardGateProducer_SPFCrossServiceAction(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFCrossServiceAction, func() {
		scope := spfScope()
		scope.DomainKey = "other.example"
		AuthorizeRecoveryAction(scope, spfAuth(time.Now()), "web", spfCompleteSnapshot())
	})
}

func TestHardGateProducer_SPFCrossComponentAction(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFCrossComponentAction, func() {
		AuthorizeRecoveryAction(spfScope(), spfAuth(time.Now()), "api", spfCompleteSnapshot())
	})
}

func TestHardGateProducer_SPFCrossGenerationAction(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFCrossGenerationAction, func() {
		scope := spfScope()
		scope.ConfigGen = 8
		AuthorizeRecoveryAction(scope, spfAuth(time.Now()), "web", spfCompleteSnapshot())
	})
}

func TestHardGateProducer_SPFSingleSignalAutoFallback(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFSingleSignalAutoFallback, func() {
		AutoFallbackGate([]Evidence{spfEvidence(ReasonRetransmissionBurst, "transport-retransmission")}, time.Now())
	})
}

func TestHardGateProducer_SPFNonIndependentAutoFallback(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFNonIndependentAutoFallback, func() {
		ev := []Evidence{
			spfEvidence(ReasonRetransmissionBurst, "transport-retransmission"),
			spfEvidence(ReasonNoUniqueProgress, "transport-retransmission"),
			spfEvidence(ReasonRetryObserved, ""),
		}
		AutoFallbackGate(ev, time.Now())
	})
}

func TestHardGateProducer_SPFSuppressorIgnored(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFSuppressorIgnored, func() {
		now := time.Now()
		values := []Suppression{{Reason: ReasonResourcePressure, ExpiresAt: now.Add(time.Minute)}}
		SuppressorGate(values, now, true)
	})
}

func TestHardGateProducer_SPFFastParallelFalsePositive(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFFastParallelFalsePositive, func() {
		FastParallelFalsePositiveGate([]Evidence{spfEvidence(ReasonLikelyParallel, "retry/application")})
	})
}

func TestHardGateProducer_SPFRecentSuccessFalsePositive(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFRecentSuccessFalsePositive, func() {
		now := time.Now()
		values := []Suppression{FreshSuccessSuppressor(now, time.Minute)}
		SuppressorGate(values, now, true)
	})
}

func TestHardGateProducer_SPFExplicitServerErrorMisclassified(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFExplicitServerErrorMisclass, func() {
		ExplicitServerErrorGate([]Evidence{spfEvidence(ReasonExplicitServerResponse, "protocol-milestone")})
	})
}

func TestHardGateProducer_SPFGsoMssProgressMismatch(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFGsoMssProgressMismatch, func() {
		GsoMssProgressMismatch(2900, 1460)
	})
}

func TestHardGateProducer_SPFPPEVisibilityViolation(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFPPEVisibilityViolation, func() {
		snap := spfCompleteSnapshot()
		snap.OffloadProven = false
		PPEVisibilityViolation(snap, true)
	})
}

func TestHardGateProducer_SPFUnboundedProbe(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFUnboundedProbe, func() {
		ProbeGate(2, 2)
	})
}

func TestHardGateProducer_SPFUnboundedRotation(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFUnboundedRotation, func() {
		RotationGate(Lease{ID: "l", Attempts: 3, MaxAttempts: 3})
	})
}

func TestHardGateProducer_SPFRecursiveTransportFallback(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFRecursiveTransportFallback, func() {
		TransportFallbackGate("warp", "warp")
	})
}

func TestHardGateProducer_SPFRecoveryWithoutRollbackTarget(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFRecoveryWithoutRollbackTarget, func() {
		RollbackTargetGate(Lease{ID: "l", Scope: spfScope(), ConfigGen: 7, From: "1.1.1.1", To: "2.2.2.2", ExpiresAt: time.Now().Add(time.Minute), Attempts: 1, MaxAttempts: 3})
	})
}

func TestHardGateProducer_SPFControlRegressionPromoted(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFControlRegressionPromoted, func() {
		ControlRegressionGate(
			ProbeResult{Path: "current", ReachedMilestone: true, ControlHealthy: true},
			ProbeResult{Path: "candidate", ReachedMilestone: true, ControlHealthy: true},
			ProbeResult{Path: "control", ReachedMilestone: false, ControlHealthy: false},
		)
	})
}

func TestHardGateProducer_SPFFalsePositiveBudgetIgnored(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFFalsePositiveBudgetIgnored, func() {
		m := NewRollbackMonitor(NewLeaseStore(), Budget{MaxRollbacks: 1, Rollbacks: 1})
		m.ObserveOnly = true
		FalsePositiveBudgetGate(m)
	})
}

func TestHardGateProducer_SPFUserRevertNotRolledBack(t *testing.T) {
	assertSPFInc(t, observability.MetricSPFUserRevertNotRolledBack, func() {
		m := NewRollbackMonitor(NewLeaseStore(), Budget{MaxRollbacks: 3})
		UserRevertRollsBack(m, "missing-lease", spfScope(), "user_disable", time.Now().Unix())
	})
}
