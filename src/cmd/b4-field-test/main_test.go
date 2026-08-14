package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String() + errb.String()
}

func TestUsage(t *testing.T) {
	code, _ := runCLI(t)
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
}

func TestPreflightJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("B4_RESULTS_DIR", dir)
	t.Setenv("B4_BASE_URL", "")
	code, out := runCLI(t, "preflight", "--json")
	if code != 1 {
		t.Fatalf("preflight without router should be blocked, exit=%d out=%s", code, out)
	}
	if !strings.Contains(out, `"ready"`) {
		t.Fatalf("expected JSON: %s", out)
	}
}

func TestRunQuickBlocked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("B4_RESULTS_DIR", dir)
	t.Setenv("B4_BASE_URL", "")
	t.Setenv("ADB_SERIAL", "")
	code, out := runCLI(t, "run", "--profile", "quick", "--json")
	if code != 1 {
		t.Fatalf("exit=%d out=%s", code, out)
	}
	if !strings.Contains(out, "BLOCKED") {
		t.Fatalf("expected blocked verdict: %s", out)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*-summary.json"))
	if len(matches) != 1 {
		t.Fatalf("expected summary artifact, got %v", matches)
	}
}

func TestCompareValidateCanaryFailClosed(t *testing.T) {
	code, out := runCLI(t, "compare", "a", "b")
	if code != 1 || !strings.Contains(out, "verdict=") {
		t.Fatalf("compare: %d %s", code, out)
	}
	code, out = runCLI(t, "validate", "cand-a", "--runs", "5")
	if code != 1 {
		t.Fatalf("validate: %d %s", code, out)
	}
	code, out = runCLI(t, "canary", "cand-a")
	if code != 1 {
		t.Fatalf("canary: %d %s", code, out)
	}
}

func TestExportMissing(t *testing.T) {
	t.Setenv("B4_RESULTS_DIR", t.TempDir())
	code, _ := runCLI(t, "export", "no-such-run")
	if code != 1 {
		t.Fatalf("export missing: %d", code)
	}
}

func TestExportFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("B4_RESULTS_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "RUN1-summary.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "export", "RUN1")
	if code != 0 || !strings.Contains(out, "RUN1-summary.json") {
		t.Fatalf("export: %d %s", code, out)
	}
}
