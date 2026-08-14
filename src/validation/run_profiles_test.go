package validation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileNamesCoverContract(t *testing.T) {
	want := []string{
		ProfileDetectorQuick, ProfileDetectorDeep, ProfileGuidedSearchAB,
		ProfileTelegramBridgeAndroid, ProfileWARPCausalTrace, ProfileWARPNestedNonRU,
		ProfileFullB4X,
	}
	have := map[string]bool{}
	for _, n := range ProfileNames() {
		have[n] = true
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("missing contract profile %s", n)
		}
	}
}

func TestResolveCapabilityAlias(t *testing.T) {
	id, ok := ResolveCapabilityAlias("detector-v2")
	if !ok || id != "abd" {
		t.Fatalf("detector-v2 -> %q %v", id, ok)
	}
	id, ok = ResolveCapabilityAlias("telegram-transparent-bridge")
	if !ok || id != "tgb" {
		t.Fatalf("tgb alias -> %q %v", id, ok)
	}
	if _, ok := ResolveCapabilityAlias("not-a-capability"); ok {
		t.Fatal("unknown alias resolved")
	}
}

func TestExecuteProfileUnknown(t *testing.T) {
	if _, err := ExecuteProfile("no-such-profile", RunOptions{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteProfileDoesNotFalsePassWithoutFieldEvidence(t *testing.T) {
	for _, name := range []string{ProfileDetectorQuick, ProfileTelegramBridgeAndroid, ProfileFullB4X} {
		run, err := ExecuteProfile(name, RunOptions{RunID: "t-" + name})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if run.Verdict() == Pass {
			t.Fatalf("%s: missing field evidence must not PASS (got %s, results=%+v)", name, run.Verdict(), run.Results)
		}
		if DetectFalsePass(StageResult{Stage: "x", Verdict: Pass, Requirements: run.Results[0].Requirements}) {
			// empty tests/artifacts still a false pass — Aggregate must reject it
		}
		hostOK := false
		fieldBlocked := false
		for _, r := range run.Results {
			if r.Stage == "host-registry" && r.Verdict == Pass {
				hostOK = true
			}
			if len(r.Stage) > 6 && r.Stage[len(r.Stage)-6:] == "-field" && r.Verdict == Blocked {
				fieldBlocked = true
			}
		}
		if !hostOK {
			t.Fatalf("%s: host-registry should PASS on generated registries: %+v", name, run.Results)
		}
		if !fieldBlocked {
			t.Fatalf("%s: expected a BLOCKED field stage", name)
		}
	}
}

func TestExecuteProfileFullB4XFollowsCapabilityOrder(t *testing.T) {
	run, err := ExecuteProfile(ProfileFullB4X, RunOptions{RunID: "t-full"})
	if err != nil {
		t.Fatal(err)
	}
	order := FullRunOrder
	seen := 0
	for _, r := range run.Results {
		if len(r.Stage) > 5 && r.Stage[len(r.Stage)-5:] == "-host" {
			id := r.Stage[:len(r.Stage)-5]
			if seen >= len(order) || order[seen] != id {
				t.Fatalf("host stage order broke at %d: got %s want %s", seen, id, order[seen])
			}
			seen++
		}
	}
	if seen != len(order) {
		t.Fatalf("scheduled %d host stages, want %d", seen, len(order))
	}
	if run.CleanupComplete {
		t.Fatal("full-b4x without cleanup ledger must not claim cleanup complete")
	}
	if run.Verdict() != Blocked {
		t.Fatalf("full-b4x without field evidence: %s", run.Verdict())
	}
}

func TestExecuteProfileHonorsFieldEvidenceFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "abd.json"), []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	run, err := ExecuteProfile(ProfileDetectorQuick, RunOptions{RunID: "t-ev", EvidenceDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range run.Results {
		if r.Stage == "abd-field" {
			found = true
			if r.Verdict != Pass {
				t.Fatalf("abd-field with evidence: %s (%v)", r.Verdict, r.Limitations)
			}
		}
	}
	if !found {
		t.Fatal("missing abd-field stage")
	}
}

func TestRunHostPreflight(t *testing.T) {
	p := RunHostPreflight()
	if !p.Ready() {
		t.Fatalf("host preflight not ready: %+v", p)
	}
}

func TestWARPCausalDoesNotRequireNested(t *testing.T) {
	run, err := ExecuteProfile(ProfileWARPCausalTrace, RunOptions{RunID: "t-warp"})
	if err != nil {
		t.Fatal(err)
	}
	if run.WARP.Camouflage != NotApplicable || run.WARP.NonRU != NotApplicable {
		t.Fatalf("base causal profile must not mix nested/non-RU: %+v", run.WARP)
	}
	if run.WARP.Causal == Pass || run.WARP.Base == Pass {
		t.Fatal("WARP causal/base must not PASS without field evidence")
	}
}

// TestFindValidationDirPrebuiltBinaryFallback simulates a prebuilt binary
// whose embedded build-time path does not exist: packageDir() must fall back
// to locating src/validation under the working directory.
func TestFindValidationDirPrebuiltBinaryFallback(t *testing.T) {
	tmp := t.TempDir()
	pkg := filepath.Join(tmp, "src", "validation")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "hard_gates_registry.gen.go"), []byte("package validation\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(tmp)
	dir, ok := findValidationDir()
	if !ok {
		t.Fatal("findValidationDir: not found from repo-root layout cwd")
	}
	if dir != pkg {
		t.Fatalf("findValidationDir = %q, want %q", dir, pkg)
	}
	// Bare validation/ under cwd also resolves.
	sub := filepath.Join(tmp, "validation")
	if err := os.Rename(pkg, sub); err != nil {
		t.Fatal(err)
	}
	dir, ok = findValidationDir()
	if !ok || dir != sub {
		t.Fatalf("findValidationDir (bare) = %q, %v; want %q", dir, ok, sub)
	}
}
