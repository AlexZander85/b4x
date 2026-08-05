package validation

import (
	"sort"
	"strings"
	"testing"
)

// FB-33 (b4x-yzt): the generated Canonical Exact Source-Stage Registry must
// be deterministic, internally consistent, and match its declared total.
// These tests run against the generated Go registry only (no YAML access),
// so `go test` inside CI fails closed on any registry-integrity regression.

func TestSourceStageCriteriaTotalMatchesDeclared(t *testing.T) {
	got := CriteriaTotal()
	if got != SourceStageDeclaredTotal {
		t.Fatalf("CriteriaTotal()=%d, declared_total=%d (FB-33: totals computed, never hard-coded)", got, SourceStageDeclaredTotal)
	}
	if got <= 0 {
		t.Fatalf("registry empty: CriteriaTotal()=%d", got)
	}
}

func TestSourceStageRegistryValid(t *testing.T) {
	errs := ValidateSourceStageRegistry()
	if len(errs) != 0 {
		t.Fatalf("registry integrity violations: %d\n%s", len(errs), strings.Join(errs, "\n"))
	}
	if !SourceStageRegistryValid() {
		t.Fatal("SourceStageRegistryValid()=false while ValidateSourceStageRegistry() returned no errors")
	}
}

func TestSourceStageRequirementLookup(t *testing.T) {
	// Every requirement in the registry must be resolvable by ID, and the
	// lookup must agree with the source document coverage.
	first := sourceStageRequirements[0]
	r, ok := SourceStageRequirementByID(first.RequirementID)
	if !ok || r.RequirementID != first.RequirementID {
		t.Fatalf("lookup failed for first requirement %q", first.RequirementID)
	}
	if _, ok := SourceStageRequirementByID("DOES-NOT-EXIST-REQ"); ok {
		t.Fatal("lookup of unknown requirement must fail")
	}
	// Total IDs across documents must equal the registry size (no
	// requirement silently dropped or duplicated across documents).
	total := 0
	for _, ids := range SourceStageCoverageByDocument() {
		total += len(ids)
	}
	if total != CriteriaTotal() {
		t.Fatalf("document coverage sum=%d != criteria_total=%d", total, CriteriaTotal())
	}
}

func TestSourceStageTotalsByCategorySum(t *testing.T) {
	totals := SourceStageTotalsByCategory()
	sum := 0
	for _, n := range totals {
		sum += n
	}
	if sum != CriteriaTotal() {
		t.Fatalf("category totals sum=%d != criteria_total=%d", sum, CriteriaTotal())
	}
	for _, c := range SourceStageCategories() {
		if _, ok := totals[c]; !ok {
			t.Fatalf("category %q missing from totals", c)
		}
	}
	if !sort.StringsAreSorted(SourceStageCategories()) {
		t.Fatal("SourceStageCategories() must be sorted (deterministic output)")
	}
}

func TestSourceStageDocumentHashesResolve(t *testing.T) {
	hashes := FB18BDocumentHashes()
	if len(hashes) == 0 {
		t.Fatal("FB18BDocumentHashes() empty")
	}
	// FB-18B must be able to resolve both crosswalk documents from the
	// registry (FB-33 criterion: FB-18 uses the registry, not manual numbers).
	for _, name := range []string{"B4_FORK_ARCHITECTURE_v2.4.md", "B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md"} {
		h, ok := SourceStageDocumentHash(name)
		if !ok {
			t.Fatalf("FB-18B document %q missing from source-stage registry", name)
		}
		if len(h) != 64 {
			t.Fatalf("FB-18B document %q has non-SHA256 hash %q", name, h)
		}
		if hashes[name] != h {
			t.Fatalf("FB18BDocumentHashes()[%q]=%q != registry hash %q", name, hashes[name], h)
		}
	}
}

func TestSourceStageRegistryDuplicatesAbsent(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range sourceStageRequirements {
		if seen[r.RequirementID] {
			t.Fatalf("duplicate requirement_id %q in generated registry", r.RequirementID)
		}
		seen[r.RequirementID] = true
	}
}
