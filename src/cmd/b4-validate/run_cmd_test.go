package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/validation"
)

func TestPreflight(t *testing.T) {
	code, out := runCLI(t, "preflight")
	if code != 0 {
		t.Fatalf("preflight exit=%d out=%s", code, out)
	}
	if !strings.Contains(out, "ready=true") {
		t.Fatalf("preflight: %s", out)
	}
}

func TestRunUnknownProfile(t *testing.T) {
	code, _ := runCLI(t, "run", "--profile", "nope")
	if code != 2 {
		t.Fatalf("exit=%d want 2", code)
	}
}

func TestRunDetectorQuickIsBlockedWithoutEvidence(t *testing.T) {
	code, out := runCLI(t, "run", "--profile", "detector-quick")
	if code != 1 {
		t.Fatalf("exit=%d want 1 (blocked), out=%s", code, out)
	}
	if !strings.Contains(out, "verdict=BLOCKED_TARGET_VALIDATION") && !strings.Contains(out, "abd-field") {
		t.Fatalf("expected blocked field stage:\n%s", out)
	}
	if !strings.Contains(out, "host-registry") {
		t.Fatalf("missing host-registry:\n%s", out)
	}
}

func TestRunJSONFullB4X(t *testing.T) {
	code, out := runCLI(t, "run", "--profile", "full-b4x", "--json")
	if code != 1 {
		t.Fatalf("exit=%d want 1, out=%s", code, out)
	}
	var run validation.FullRun
	if err := json.Unmarshal([]byte(out), &run); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if run.Profile != validation.ProfileFullB4X || run.CleanupComplete {
		t.Fatalf("unexpected run: %+v", run)
	}
	if run.Verdict() == validation.Pass {
		t.Fatal("full-b4x must not PASS without field evidence")
	}
}

func TestExplainIssue277(t *testing.T) {
	code, out := runCLI(t, "explain", "--verdict", "ISSUE_277_RESOLVED")
	if code != 0 {
		t.Fatalf("exit=%d out=%s", code, out)
	}
	if !strings.Contains(out, "cannot be inferred from a larger timeout") {
		t.Fatalf("missing claim policy:\n%s", out)
	}
	if !strings.Contains(out, "BLOCKED_MISSING_ARTIFACT") {
		t.Fatalf("explain must not claim PASS:\n%s", out)
	}
}

func TestListCapabilityDetectorV2(t *testing.T) {
	code, out := runCLI(t, "list", "--capability", "detector-v2")
	if code != 0 {
		t.Fatalf("exit=%d out=%s", code, out)
	}
	if !strings.Contains(out, "capability: abd") {
		t.Fatalf("expected abd:\n%s", out)
	}
}
