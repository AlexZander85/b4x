package validation

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNoFlagDayMigrationMatrixValid checks the structural invariants of the
// ARCH §145 migration matrix (FB-35): unique IDs, meaningful status, at least
// one runnable evidence test per subject, and — for cutover-complete subjects
// — the mandatory reverse- and forward-reachability probes that make the
// status falsifiable.
func TestNoFlagDayMigrationMatrixValid(t *testing.T) {
	matrix := MigrationMatrix()
	if len(matrix) == 0 {
		t.Fatal("migration matrix is empty")
	}
	validStatuses := map[MigrationStatus]bool{}
	for _, s := range MigrationStatuses() {
		validStatuses[s] = true
	}
	seen := map[string]bool{}
	for _, subj := range matrix {
		if subj.ID == "" || subj.Title == "" {
			t.Fatalf("subject missing ID or title: %+v", subj)
		}
		if seen[subj.ID] {
			t.Fatalf("duplicate subject ID %q", subj.ID)
		}
		seen[subj.ID] = true
		if !validStatuses[subj.Status] {
			t.Fatalf("subject %q has unknown status %q", subj.ID, subj.Status)
		}
		if len(subj.Evidence) == 0 {
			t.Fatalf("subject %q has no evidence", subj.ID)
		}
		if subj.Status == MigrationCutoverComplete {
			if subj.LegacyMutatingSymbol == "" {
				t.Fatalf("cutover subject %q must declare the removed legacy mutating symbol", subj.ID)
			}
			if len(subj.NewPathSymbols) == 0 {
				t.Fatalf("cutover subject %q must declare at least one new production path symbol", subj.ID)
			}
		}
	}
}

// TestNoFlagDayMatrixEvidenceExists proves the matrix is executable: every
// referenced evidence test must exist in the actual source tree (AST scan via
// testFuncIndex), so a PASS here cannot survive a deleted or renamed test.
func TestNoFlagDayMatrixEvidenceExists(t *testing.T) {
	index, err := testFuncIndex()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range MigrationMatrix() {
		for _, ev := range m.Evidence {
			if !index[ev] {
				t.Fatalf("matrix subject %q references missing evidence test %q", m.ID, ev)
			}
		}
	}
}

// TestNoFlagDayCutoverReverseReachabilityClean proves the cutover-complete
// subjects: the legacy mutating symbol must be unreachable from the real
// production tree (reverse reachability clean), and every declared new path
// symbol must actually exist in production (forward reachability). This is
// the executable form of the L8/§145 cutover condition: legacy unsafe
// direct-apply paths are disabled before production-ready.
func TestNoFlagDayCutoverReverseReachabilityClean(t *testing.T) {
	for _, m := range MigrationMatrix() {
		if m.Status != MigrationCutoverComplete {
			continue
		}
		res := ReverseReachabilityFor("", m.LegacyMutatingSymbol)
		if !res.ProductionReady {
			t.Fatalf("subject %q: legacy mutating symbol %q still reachable in production: %+v",
				m.ID, m.LegacyMutatingSymbol, res.Hits)
		}
		if len(res.Hits) != 0 {
			t.Fatalf("subject %q: expected zero production call sites of %q, got %+v",
				m.ID, m.LegacyMutatingSymbol, res.Hits)
		}
		for _, sym := range m.NewPathSymbols {
			if !productionCallExists(sym) {
				t.Fatalf("subject %q: new production path symbol %q not reachable", m.ID, sym)
			}
		}
	}
}

// TestNoFlagDaySeededLegacyReactivationDetected proves the matrix scan is not
// trivially permissive: re-introducing a legacy-shaped mutating caller into a
// temporary production tree is detected per subject, so a resurrected legacy
// path can never claim the cutover phase (seeded reactivation is caught by
// the same reverse-reachability mechanism that backs MON_PRODUCTION_READY).
func TestNoFlagDaySeededLegacyReactivationDetected(t *testing.T) {
	for _, m := range MigrationMatrix() {
		if m.Status != MigrationCutoverComplete {
			continue
		}
		dir := t.TempDir()
		fixture := "package seeded\n\nfunc legacy() {\n\t_ = " + m.LegacyMutatingSymbol + "(nil, nil, nil, nil)\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "seeded.go"), []byte(fixture), 0o644); err != nil {
			t.Fatal(err)
		}
		res := ReverseReachabilityFor(dir, m.LegacyMutatingSymbol)
		if res.ProductionReady {
			t.Fatalf("subject %q: seeded reactivation of %q must NOT be production ready: %+v",
				m.ID, m.LegacyMutatingSymbol, res)
		}
		if len(res.Hits) != 1 {
			t.Fatalf("subject %q: expected exactly one seeded hit of %q, got %+v",
				m.ID, m.LegacyMutatingSymbol, res.Hits)
		}
	}
}
