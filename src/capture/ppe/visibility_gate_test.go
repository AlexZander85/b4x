package ppe

import (
	"sync/atomic"
	"testing"
)

func TestVisibilityGateBlocksDependentFeaturesUntilPASS(t *testing.T) {
	gate := NewVisibilityGate()
	if !gate.Decision(VisibilityFeaturePromotion).Allowed {
		t.Fatal("unenforced gate blocked existing platform")
	}
	var releases atomic.Int64
	cancel := gate.SubscribeBlocked(func(CaptureVisibilitySnapshot) { releases.Add(1) })
	defer cancel()
	gate.EnsureRequired("gen-1", "self-test required")
	for _, feature := range []VisibilityFeature{VisibilityFeatureReassembly, VisibilityFeatureHoldReplay, VisibilityFeatureACKReplay, VisibilityFeatureAutomaticDiscovery, VisibilityFeatureCanary, VisibilityFeaturePromotion} {
		if gate.Decision(feature).Allowed {
			t.Fatalf("feature %s allowed without proof", feature)
		}
	}
	if !gate.Decision(VisibilityFeatureObserve).Allowed || !gate.Decision(VisibilityFeatureStatelessMutation).Allowed {
		t.Fatal("safe fail-open features were blocked")
	}
	gate.PublishSelfTest(CaptureVisibilityResult{Verdict: VerdictPASS, ProductionReady: true})
	if !gate.Decision(VisibilityFeaturePromotion).Allowed {
		t.Fatal("PASS did not enable promotion")
	}
	gate.Degrade("gen-1", "rules disappeared")
	if gate.Decision(VisibilityFeatureHoldReplay).Allowed || releases.Load() < 2 {
		t.Fatalf("degradation did not block/release: releases=%d", releases.Load())
	}
}

func TestVisibilityGateDoesNotPromoteLimitedOrInconclusiveResults(t *testing.T) {
	for _, verdict := range []SelfTestVerdict{VerdictPASSWithLimitations, VerdictFAIL, VerdictUNSUPPORTED, VerdictINCONCLUSIVE} {
		gate := NewVisibilityGate()
		gate.EnsureRequired("gen", "required")
		gate.PublishSelfTest(CaptureVisibilityResult{Verdict: verdict, TCPBidirectionalComplete: true})
		if gate.Decision(VisibilityFeaturePromotion).Allowed {
			t.Fatalf("verdict %s enabled promotion", verdict)
		}
	}
}
