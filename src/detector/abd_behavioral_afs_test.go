package detector

import (
	"testing"
	"time"
)

func TestClassifyFourWayBehaviorOperatorSignals(t *testing.T) {
	tests := []struct {
		name       string
		r1, r2     BehaviorOutcome
		r3, r4     BehaviorOutcome
		want       string
		conclusive bool
	}{
		{
			name: "supports bypass",
			r1: BehaviorOutcomeOK, r2: BehaviorOutcomeFail,
			r3: BehaviorOutcomeOK, r4: BehaviorOutcomeOK,
			want: "mutation-bypass-signal", conclusive: true,
		},
		{
			name: "penalizes control-sensitive mutation",
			r1: BehaviorOutcomeOK, r2: BehaviorOutcomeFail,
			r3: BehaviorOutcomeFail, r4: BehaviorOutcomeFail,
			want: "mutation-breaks-control", conclusive: true,
		},
		{
			name: "excludes target regression",
			r1: BehaviorOutcomeOK, r2: BehaviorOutcomeOK,
			r3: BehaviorOutcomeOK, r4: BehaviorOutcomeFail,
			want: "mutation-target-regression", conclusive: true,
		},
		{
			name: "unhealthy reference is inconclusive",
			r1: BehaviorOutcomeFail, r2: BehaviorOutcomeFail,
			r3: BehaviorOutcomeOK, r4: BehaviorOutcomeOK,
			want: "control-unhealthy", conclusive: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, conclusive := ClassifyFourWayBehavior(tc.r1, tc.r2, tc.r3, tc.r4)
			if got != tc.want || conclusive != tc.conclusive {
				t.Fatalf("classification=(%q,%t), want=(%q,%t)", got, conclusive, tc.want, tc.conclusive)
			}
		})
	}
}

func TestBehaviorFeaturesFromAttemptsEmitsPenalty(t *testing.T) {
	interpretation, conclusive := ClassifyFourWayBehavior(
		BehaviorOutcomeOK,
		BehaviorOutcomeFail,
		BehaviorOutcomeFail,
		BehaviorOutcomeFail,
	)
	attempts := []BehaviorAttemptSummary{{
		ProbeID:           "control-sensitive-split",
		Attempt:           1,
		OperatorFamily:    OperatorTCPSplit,
		ReferenceBaseline: BehaviorOutcomeOK,
		TargetBaseline:    BehaviorOutcomeFail,
		ReferenceMutated:  BehaviorOutcomeFail,
		TargetMutated:     BehaviorOutcomeFail,
		Interpretation:    interpretation,
		Conclusive:        conclusive,
		ObservedAt:        time.Unix(1, 0),
		EvidenceRefs:      []string{"r1", "r2", "r3", "r4"},
	}}

	features, confidence, noise := behaviorFeaturesFromAttempts(attempts)
	if len(features) != 1 {
		t.Fatalf("features=%d, want 1", len(features))
	}
	feature := features[0]
	if feature.State != "control-sensitive" || len(feature.Penalizes) != 1 || feature.Penalizes[0] != OperatorTCPSplit {
		t.Fatalf("unexpected penalty feature: %+v", feature)
	}
	if len(feature.Supports) != 0 || len(feature.Excludes) != 0 {
		t.Fatalf("control-sensitive feature must only penalize: %+v", feature)
	}
	if confidence != 1 || noise != 0 {
		t.Fatalf("confidence/noise=(%v,%v), want=(1,0)", confidence, noise)
	}
}
