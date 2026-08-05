package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/validation"
)

// runCLI invokes run() with captured output and returns exit code + output.
func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String() + errb.String()
}

func TestList(t *testing.T) {
	code, out := runCLI(t, "list")
	if code != 0 {
		t.Fatalf("list exit=%d out=%s", code, out)
	}
	if !strings.Contains(out, "registered=285") {
		t.Errorf("list: expected registered=285, got:\n%s", out)
	}
	if !strings.Contains(out, "warp_secret_leak_total") {
		t.Errorf("list: expected warp_secret_leak_total row:\n%s", out)
	}
	for _, fam := range []string{"warp", "spf", "mon", "abd"} {
		if !strings.Contains(out, fam) {
			t.Errorf("list: missing family %s in summary:\n%s", fam, out)
		}
	}
}

func TestListJSON(t *testing.T) {
	code, out := runCLI(t, "list", "--json")
	if code != 0 {
		t.Fatalf("list --json exit=%d out=%s", code, out)
	}
	var gates []struct {
		GateID string `json:"GateID"`
	}
	if err := json.Unmarshal([]byte(out), &gates); err != nil {
		t.Fatalf("list --json is not valid JSON: %v\n%s", err, out)
	}
	if len(gates) != 285 {
		t.Errorf("list --json: expected 285 gates, got %d", len(gates))
	}
}

func TestPlanFull(t *testing.T) {
	code, out := runCLI(t, "plan", "full")
	if code != 0 {
		t.Fatalf("plan full exit=%d out=%s", code, out)
	}
	if !strings.Contains(out, "applicable=") {
		t.Errorf("plan full: missing applicable= summary:\n%s", out)
	}
	// The release profile applies exactly the registry-verified set (239)
	// as proven producers; the plan must carry producer/consumer refs.
	if !strings.Contains(out, "verified=") {
		t.Errorf("plan full: missing verified= summary:\n%s", out)
	}
}

func TestPlanFullJSON(t *testing.T) {
	code, out := runCLI(t, "plan", "full", "--json")
	if code != 0 {
		t.Fatalf("plan full --json exit=%d out=%s", code, out)
	}
	var plan []struct {
		GateID string `json:"gate_id"`
	}
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatalf("plan full --json invalid: %v", err)
	}
	if len(plan) == 0 {
		t.Error("plan full --json: empty plan")
	}
}

func TestPlanRequiresFull(t *testing.T) {
	code, out := runCLI(t, "plan")
	if code != 2 {
		t.Fatalf("plan (no subcommand) exit=%d want 2, out=%s", code, out)
	}
}

func TestRequirement(t *testing.T) {
	code, out := runCLI(t, "requirement", "warp_secret_leak_total")
	if code != 0 {
		t.Fatalf("requirement exit=%d out=%s", code, out)
	}
	for _, want := range []string{"gate_id:", "family:", "kind:", "status:"} {
		if !strings.Contains(out, want) {
			t.Errorf("requirement: missing %q:\n%s", want, out)
		}
	}
}

func TestRequirementUnknown(t *testing.T) {
	code, out := runCLI(t, "requirement", "no_such_gate_anywhere")
	if code != 2 {
		t.Fatalf("requirement unknown exit=%d want 2, out=%s", code, out)
	}
	if !strings.Contains(out, "not found") {
		t.Errorf("requirement unknown: expected not-found message:\n%s", out)
	}
}

func TestFullMissingCountersFailClosed(t *testing.T) {
	// Without observed counters the CLI is fail-closed: applicable gates
	// without producer evidence must block (criterion 5 — no PASS without
	// evidence). This is the honest state until subsystem producers are
	// verified in production code (FB-02/FB-07/FB-27/FB-28).
	code, out := runCLI(t, "full", "--profile", "release")
	if code != 1 {
		t.Fatalf("full (no counters) exit=%d want 1 (fail-closed), out=%s", code, out)
	}
	if !strings.Contains(out, "verdict=BLOCKED") {
		t.Errorf("full (no counters): expected BLOCKED:\n%s", out)
	}
}

// zeroTolCounters returns a JSON map with a zero for every applicable gate
// that requires a produced counter (zero-tolerance and threshold gates;
// telemetry and readiness inputs are informational and never block).
// This is the honest "all producers observed, no violations" fixture.
func zeroTolCounters(t *testing.T) string {
	t.Helper()
	payload := map[string]uint64{}
	for _, g := range validation.AllHardGates() {
		if g.Kind == "telemetry_counter" || g.Kind == "current_generation_readiness_input" {
			continue
		}
		payload[g.GateID] = 0
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestFullPassWithObservedZeroCounters(t *testing.T) {
	dir := t.TempDir()
	counters := filepath.Join(dir, "counters.json")
	if err := os.WriteFile(counters, []byte(zeroTolCounters(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "full", "--profile", "release", "--counters-file", counters)
	if code != 0 {
		t.Fatalf("full (zero counters) exit=%d want 0, out=%s", code, out)
	}
	if !strings.Contains(out, "verdict=PASS") {
		t.Errorf("full (zero counters): expected PASS:\n%s", out)
	}
}

func TestFullFailsOnViolation(t *testing.T) {
	dir := t.TempDir()
	counters := filepath.Join(dir, "counters.json")
	payload := map[string]uint64{}
	for _, g := range validation.AllHardGates() {
		if g.Kind == "telemetry_counter" || g.Kind == "current_generation_readiness_input" {
			continue
		}
		payload[g.GateID] = 0
	}
	payload["warp_secret_leak_total"] = 1
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(counters, data, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "full", "--profile", "release", "--counters-file", counters)
	if code != 1 {
		t.Fatalf("full (violation) exit=%d want 1, out=%s", code, out)
	}
	if !strings.Contains(out, "verdict=FAIL") {
		t.Errorf("full (violation): expected FAIL:\n%s", out)
	}
	if !strings.Contains(out, "warp_secret_leak_total") {
		t.Errorf("full (violation): expected violated gate in output:\n%s", out)
	}
}

func TestFullWindowBaseline(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "current.json")
	base := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(cur, []byte(zeroTolCounters(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte(zeroTolCounters(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "full", "--profile", "release", "--counters-file", cur, "--baseline-file", base)
	if code != 0 {
		t.Fatalf("full (delta 0) exit=%d want 0, out=%s", code, out)
	}
	if !strings.Contains(out, "window_baseline=true") {
		t.Errorf("full (delta 0): expected window_baseline=true:\n%s", out)
	}
}

func TestFullRequiresReleaseProfile(t *testing.T) {
	code, out := runCLI(t, "full", "--profile", "beta")
	if code != 2 {
		t.Fatalf("full (bad profile) exit=%d want 2, out=%s", code, out)
	}
}

func TestMeta(t *testing.T) {
	code, out := runCLI(t, "meta")
	if code != 0 {
		t.Fatalf("meta exit=%d out=%s", code, out)
	}
	for _, want := range []string{"registry_complete=true", "api_parity=true", "ready=true"} {
		if !strings.Contains(out, want) {
			t.Errorf("meta: missing %q:\n%s", want, out)
		}
	}
}

func TestMetaJSON(t *testing.T) {
	code, out := runCLI(t, "meta", "--json")
	if code != 0 {
		t.Fatalf("meta --json exit=%d out=%s", code, out)
	}
	var res struct {
		RegistryComplete bool `json:"RegistryComplete"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("meta --json invalid: %v", err)
	}
	if !res.RegistryComplete {
		t.Error("meta --json: RegistryComplete=false")
	}
}

func TestMatrix(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "FB03_GATE_PRODUCER_CONSUMER_MATRIX.json")
	code, out := runCLI(t, "matrix", "--out", outPath)
	if code != 0 {
		t.Fatalf("matrix exit=%d out=%s", code, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("matrix: %v", err)
	}
	var doc struct {
		Total    int `json:"total"`
		Verified int `json:"verified"`
		Missing  int `json:"missing"`
		Gates    []struct {
			GateID string `json:"gate_id"`
		} `json:"gates"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("matrix JSON invalid: %v", err)
	}
	if doc.Total != 285 || len(doc.Gates) != 285 {
		t.Errorf("matrix: total=%d gates=%d, want 285/285", doc.Total, len(doc.Gates))
	}
	if doc.Verified+doc.Missing != doc.Total {
		t.Errorf("matrix: verified+missing=%d != total=%d", doc.Verified+doc.Missing, doc.Total)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, out := runCLI(t, "frobnicate")
	if code != 2 {
		t.Fatalf("unknown command exit=%d want 2, out=%s", code, out)
	}
	if !strings.Contains(out, "unknown command") {
		t.Errorf("unknown command: missing error message:\n%s", out)
	}
}

func TestHelp(t *testing.T) {
	code, out := runCLI(t, "--help")
	if code != 0 {
		t.Fatalf("--help exit=%d out=%s", code, out)
	}
	for _, want := range []string{"list", "plan", "full", "requirement", "meta", "matrix"} {
		if !strings.Contains(out, want) {
			t.Errorf("--help: missing %q", want)
		}
	}
}
