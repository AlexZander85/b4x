package validation

import (
	"strings"
	"testing"
)

func TestArtifactValidRejectsMissingDigest(t *testing.T) {
	a := Artifact{Name: "hard_gates.yaml", SHA256: "short", Kind: "evidence", Size: 1, Redacted: true}
	if ArtifactValid(a) {
		t.Fatal("artifact with invalid digest must not be valid")
	}
}

func TestArtifactValidAcceptsCompleteEvidence(t *testing.T) {
	a := Artifact{Name: "hard_gates.yaml", SHA256: strings.Repeat("ab", 32), Kind: "evidence", Size: 1, Redacted: true}
	if !ArtifactValid(a) {
		t.Fatal("complete evidence artifact must be valid")
	}
}

func TestMetaResultReadyRequiresAllFlagsAndArtifacts(t *testing.T) {
	m := MetaResult{RegistryComplete: true, APIParity: true, VerdictMutationDetected: true, EvidenceIntegrity: true, Reproducible: true, InfrastructureSafe: true, FalseNegativeDetected: true}
	if m.Ready() {
		t.Fatal("Ready must be false without artifacts")
	}
	m.Artifacts = []Artifact{{Name: "x.yaml", SHA256: strings.Repeat("ab", 32), Kind: "evidence", Size: 1, Redacted: true}}
	if !m.Ready() {
		t.Fatal("Ready must be true with all flags and valid artifacts")
	}
	m.VerdictMutationDetected = false
	if m.Ready() {
		t.Fatal("Ready must be false when a flag is false")
	}
}

func TestRunMetaSuiteDetectsMutationAndViolation(t *testing.T) {
	artifacts := []Artifact{
		{Name: "specs/registries/hard_gates.yaml", SHA256: strings.Repeat("ab", 32), Kind: "evidence", Size: 1, Redacted: true},
		{Name: "src/validation/hard_gates_registry.gen.go", SHA256: strings.Repeat("cd", 32), Kind: "evidence", Size: 1, Redacted: true},
	}
	m := RunMetaSuite(artifacts)
	if !m.RegistryComplete {
		t.Error("RegistryComplete must pass on the canonical generated registry")
	}
	if !m.APIParity {
		t.Error("APIParity must pass (canonical names resolve to themselves, aliases == 17)")
	}
	if !m.VerdictMutationDetected {
		t.Error("forced-zero counter without producer must yield BLOCKED, not PASS")
	}
	if !m.Reproducible {
		t.Errorf("Reproducible must hold (285 gates / 265 applicable), got %d/%d", HardGateCount(), len(ApplicableHardGates()))
	}
	if !m.InfrastructureSafe {
		t.Error("evaluator must not mutate counters")
	}
	if !m.FalseNegativeDetected {
		t.Error("violation fixture must yield FAIL, never PASS")
	}
	if !m.EvidenceIntegrity {
		t.Error("valid artifacts must pass EvidenceIntegrity")
	}
	if !m.Ready() {
		t.Error("full meta-suite with valid artifacts must be Ready")
	}
}

func TestRunMetaSuiteFailsWithoutEvidence(t *testing.T) {
	m := RunMetaSuite(nil)
	if m.EvidenceIntegrity {
		t.Error("missing evidence must not pass integrity")
	}
	if m.Ready() {
		t.Error("Ready must be false without evidence artifacts")
	}
}

func TestRegistryCompleteDetectsDuplicates(t *testing.T) {
	// registryComplete is computed from the generated registry; guard the
	// canonical registry itself against duplicate GateIDs.
	seen := map[string]bool{}
	for _, g := range hardGates {
		if seen[g.GateID] {
			t.Fatalf("duplicate GateID %q in generated registry", g.GateID)
		}
		seen[g.GateID] = true
	}
}
