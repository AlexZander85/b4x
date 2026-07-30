package silentpath

import (
	"testing"
	"time"
)

func TestClassifierNeedsIndependentFamilies(t *testing.T) {
	n := time.Now()
	one := Classify(FailureBeforeServerHello, Scope{}, []Evidence{{IndependentFamily: "progress-time", ExpiresAt: n.Add(time.Second)}}, nil, n)
	if one.Confidence != ConfidenceSuspicion {
		t.Fatal(one)
	}
	two := Classify(FailureBeforeServerHello, Scope{}, []Evidence{{IndependentFamily: "progress-time"}, {IndependentFamily: "retry"}}, nil, n)
	if two.Confidence != ConfidenceCorrelated {
		t.Fatal(two)
	}
	bad := Classify(FailureBeforeServerHello, Scope{}, two.PositiveEvidence, []Suppression{{Reason: ReasonControlUnhealthy}}, n)
	if bad.Confidence != ConfidenceNone {
		t.Fatal(bad)
	}
}
