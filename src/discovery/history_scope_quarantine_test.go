package discovery

import (
	"testing"
	"time"
)

// TestQuarantineSynthesizedWinnersForScopeInvalidatesAll is the operator
// revert-to-catalog contract (AFS §73): every persisted winner on the exact
// Monitor scope becomes permanently ineligible, other scopes are untouched,
// and the operation is idempotent.
func TestQuarantineSynthesizedWinnersForScopeInvalidatesAll(t *testing.T) {
	now := time.Unix(22000, 0)
	scope := synthesizedWinnerTestScope()
	key := synthesizedWinnerTestKey(scope)
	history := &DiscoveryHistory{}

	for i, jitter := range []string{"0", "2"} {
		promoted := now.Add(time.Duration(i) * time.Minute)
		record := SynthesizedWinnerRecord{
			Compatibility: key,
			Candidate:     synthesizedWinnerTestCandidate(t, scope, jitter, promoted),
			EvidenceRefs:  []string{"be-a"},
			PromotedAt:    promoted,
			ExpiresAt:     now.Add(24 * time.Hour),
		}
		if err := history.AddSynthesizedWinner(record, now); err != nil {
			t.Fatalf("add winner %d: %v", i, err)
		}
	}

	otherScope := scope
	otherScope.ClientScope.ID = "client-b"
	otherKey := synthesizedWinnerTestKey(otherScope)
	otherRecord := SynthesizedWinnerRecord{
		Compatibility: otherKey,
		Candidate:     synthesizedWinnerTestCandidate(t, otherScope, "1", now),
		EvidenceRefs:  []string{"be-b"},
		PromotedAt:    now,
		ExpiresAt:     now.Add(24 * time.Hour),
	}
	if err := history.AddSynthesizedWinner(otherRecord, now); err != nil {
		t.Fatalf("add other winner: %v", err)
	}

	if got := history.QuarantineSynthesizedWinnersForScope(scope, "operator revert", now.Add(time.Hour)); got != 2 {
		t.Fatalf("quarantined = %d, want 2", got)
	}
	if got := history.CompatibleSynthesizedWinners(key, now.Add(2*time.Hour)); len(got) != 0 {
		t.Fatalf("reverted-scope winners remain reusable: %d", len(got))
	}
	if got := history.CompatibleSynthesizedWinners(otherKey, now.Add(2*time.Hour)); len(got) != 1 {
		t.Fatalf("other-scope winner wrongly quarantined: %d", len(got))
	}
	if got := history.QuarantineSynthesizedWinnersForScope(scope, "operator revert", now.Add(3*time.Hour)); got != 0 {
		t.Fatalf("second quarantine must be a no-op, changed %d", got)
	}
	// Reverted records stay as audit entries.
	if len(history.SynthesizedWinners) != 3 {
		t.Fatalf("audit records = %d, want 3", len(history.SynthesizedWinners))
	}
}
