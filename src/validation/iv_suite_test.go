package validation

import (
	"strings"
	"testing"
)

func TestIV18RegistryRequirementsUniqueAndBlocking(t *testing.T) {
	requirements := IV18Requirements()
	if len(requirements) != 22 {
		t.Fatalf("registered %d requirements, want 22 (MON-1..MON-12 + FT-MON-A..J)", len(requirements))
	}
	seen := map[string]bool{}
	for _, r := range requirements {
		if !strings.HasPrefix(r.ID, "IV-18-") {
			t.Fatalf("requirement %q outside IV-18 suite", r.ID)
		}
		if seen[r.ID] {
			t.Fatalf("duplicate requirement %q", r.ID)
		}
		seen[r.ID] = true
		if !r.Blocking {
			t.Fatalf("requirement %q must be blocking (P0-NORMATIVE)", r.ID)
		}
		if r.Source == "" || r.Stage != iv18Stage || (r.Suite != iv18MONSuite && r.Suite != iv18FTSuite) {
			t.Fatalf("requirement %q incomplete: %+v", r.ID, r)
		}
	}
	for _, id := range []string{"IV-18-MON-01", "IV-18-MON-12", "IV-18-FT-MON-A", "IV-18-FT-MON-J"} {
		if !seen[id] {
			t.Fatalf("expected requirement %q missing", id)
		}
	}
}

func TestIV18RunSuiteIsFailClosed(t *testing.T) {
	result := RunIV18Suite()
	if result.SuiteID != IV18SuiteID || result.Registered != 22 {
		t.Fatalf("suite identity: %+v", result)
	}
	// Every registered requirement now has executed coverage (E3/E4 closed
	// the gaps), but the verdict must remain BLOCKED while the legacy
	// Watchdog mutating path is reachable (MON_PRODUCTION_READY impossible).
	if result.Verdict != Blocked {
		t.Fatalf("suite verdict = %v, want BLOCKED while legacy mutating path reachable", result.Verdict)
	}
	if len(result.MissingCoverage) != 0 {
		t.Fatalf("all requirements must have coverage after E3/E4, missing: %v", result.MissingCoverage)
	}
	if result.Covered != result.Registered {
		t.Fatalf("covered %d != registered %d", result.Covered, result.Registered)
	}
	if result.ProductionReady {
		t.Fatalf("production readiness must be false while applyBatchResults is reachable")
	}
	if len(result.LegacyMutatingHits) == 0 {
		t.Fatalf("expected legacy mutating hits in result: %+v", result)
	}
}

func TestIV18RegistryIntegrity(t *testing.T) {
	registry := IV18Registry()
	if !registry.Valid() {
		t.Fatalf("IV-18 registry invalid: %+v", registry)
	}
	if registry.Hash() == "" || registry.CanonicalBytes() == nil {
		t.Fatal("IV-18 registry hash/canonical bytes unavailable")
	}
}
