package validation

import "testing"

func TestRegistryCanonicalHashAndOrphans(t *testing.T) {
	r := Registry{Version: 1, AddendumHash: "h", Requirements: []Requirement{{ID: "IV-1", Stage: "IV-1"}}, Coverage: []Coverage{{RequirementID: "IV-1", TestID: "registry"}}}
	if r.Hash() != r.Hash() {
		t.Fatal("hash unstable")
	}
	if got := r.Orphans(map[string]bool{"IV-1": true}); len(got) != 0 {
		t.Fatal(got)
	}
}
