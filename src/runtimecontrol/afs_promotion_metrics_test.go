package runtimecontrol

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

func runtimeSynthesisCounterValue(name string) uint64 {
	snapshot := observability.Default().Metrics.Snapshot(time.Now())
	for _, sample := range snapshot.Counters {
		if sample.Name == name {
			return sample.Value
		}
	}
	return 0
}

func requireRuntimeSynthesisCounter(t *testing.T, name string) {
	t.Helper()
	if runtimeSynthesisCounterValue(name) == 0 {
		t.Fatalf("zero-tolerance counter %q was not raised", name)
	}
}

func TestSynthesizedPromotionZeroToleranceCounters(t *testing.T) {
	now := time.Unix(34000, 0)
	canary := validSynthesizedCanary()

	t.Run("without-action-authorization", func(t *testing.T) {
		observability.Default().Metrics.Reset()
		proof := validSynthesizedPromotionProof(now)
		proof.ActionAuthorizationID = ""
		if err := proof.validatePrepare(now, canary); err == nil {
			t.Fatal("promotion proof without ActionAuthorization was accepted")
		}
		requireRuntimeSynthesisCounter(t, observability.MetricSynthesisWithoutActionAuthorization)
	})

	t.Run("missing-mandatory-control", func(t *testing.T) {
		observability.Default().Metrics.Reset()
		proof := validSynthesizedPromotionProof(now)
		proof.UnrelatedControlRefs = nil
		if err := proof.validatePrepare(now, canary); err == nil {
			t.Fatal("promotion proof without unrelated control was accepted")
		}
		requireRuntimeSynthesisCounter(t, observability.MetricSynthesisMissingMandatoryControl)
	})

	t.Run("rollback-not-ready", func(t *testing.T) {
		observability.Default().Metrics.Reset()
		proof := validSynthesizedPromotionProof(now)
		proof.RollbackReady = false
		if err := proof.validatePrepare(now, canary); err == nil {
			t.Fatal("promotion proof without rollback readiness was accepted")
		}
		requireRuntimeSynthesisCounter(t, observability.MetricSynthesisPromotionWithoutRollbackReady)
	})

	t.Run("cleanup-not-ready", func(t *testing.T) {
		observability.Default().Metrics.Reset()
		proof := validSynthesizedPromotionProof(now)
		proof.CleanupReady = false
		if err := proof.validatePrepare(now, canary); err == nil {
			t.Fatal("promotion proof without cleanup readiness was accepted")
		}
		requireRuntimeSynthesisCounter(t, observability.MetricSynthesisCleanupIncomplete)
	})

	t.Run("router-origin-without-forwarded-canary", func(t *testing.T) {
		observability.Default().Metrics.Reset()
		proof := validSynthesizedPromotionProof(now)
		proof.SourceClientRole = "router-origin"
		outcome := CanaryOutcome{Passed: false, Samples: 3, StartedAt: now, CompletedAt: now.Add(time.Second)}
		if err := proof.validatePromote(now.Add(time.Second), canary, outcome, true); err == nil {
			t.Fatal("router-origin winner without passed forwarded canary was accepted")
		}
		requireRuntimeSynthesisCounter(t, observability.MetricSynthesisRouterOriginPromotedNoAndroid)
	})

	t.Run("transactional-rollback-state-missing", func(t *testing.T) {
		observability.Default().Metrics.Reset()
		proof := validSynthesizedPromotionProof(now)
		outcome := CanaryOutcome{Passed: true, Samples: 3, StartedAt: now, CompletedAt: now.Add(time.Second)}
		if err := proof.validatePromote(now.Add(time.Second), canary, outcome, false); err == nil {
			t.Fatal("promotion without transactional rollback state was accepted")
		}
		requireRuntimeSynthesisCounter(t, observability.MetricSynthesisPromotionWithoutRollbackReady)
	})
}
