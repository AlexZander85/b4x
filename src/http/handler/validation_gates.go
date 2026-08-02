package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/validation"
)

const validationGatesAPIPath = "/api/v2/validation/gates"
const validationIV18APIPath = "/api/v2/validation/iv"

// gateSnapshot carries the live hard-gate evaluation (FB-03) for the
// validation API/CLI surface. Meta contains the meta-suite result; evidence
// artifacts are hashed from the working tree when available (registry YAML
// and generated Go reference), otherwise EvidenceIntegrity is false.
type gateSnapshot struct {
	Scope      validation.ReleaseScope        `json:"scope"`
	Evaluation validation.GateEvaluation      `json:"evaluation"`
	Readiness  validation.ReadinessEvaluation `json:"readiness"`
	Window     validation.WindowInfo          `json:"window"`
	Meta       validation.MetaResult          `json:"meta"`
	CheckedAt  time.Time                      `json:"checked_at"`
}

// RegisterValidationAPI wires the canonical hard-gate evaluation and the
// meta-suite into the HTTP API (FB-03 §4: validation API/CLI consumer).
func (api *API) RegisterValidationAPI() {
	api.mux.HandleFunc(validationGatesAPIPath, api.handleValidationGates)
	api.mux.HandleFunc(validationIV18APIPath, api.handleValidationIV18)
}

// iv18Snapshot carries the FB-28 IV-18 conformance suite result (registry +
// executed coverage) for the validation API surface. It is read-only: the
// suite is executed on request from the canonical requirements.
type iv18Snapshot struct {
	APIVersion  string               `json:"api_version"`
	Suite       string               `json:"suite"`
	Requirements []validation.Requirement `json:"requirements,omitempty"`
	Coverage    []validation.Coverage    `json:"coverage,omitempty"`
	Result      validation.IV18Result    `json:"result"`
	CheckedAt   time.Time               `json:"checked_at"`
}

func (api *API) handleValidationIV18(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	result := validation.RunIV18Suite()
	sendResponse(w, iv18Snapshot{
		APIVersion:   config.ClassifierAPIV23,
		Suite:        validation.IV18SuiteID,
		Requirements: validation.IV18Requirements(),
		Coverage:     validation.IV18Coverage(),
		Result:       result,
		CheckedAt:    time.Now().UTC(),
	})
}

// currentGenerationID returns the generation of the active TestSession/
// ValidationRun when runtime control is initialized, so the validation API
// evaluates the same window as canary/PromotePending (FB-03 phase E2).
func (api *API) currentGenerationID() string {
	manager := api.getRuntimeControlManager()
	if manager == nil {
		return ""
	}
	status := manager.Status()
	if status.Active != nil {
		return status.Active.ID
	}
	if status.Pending != nil {
		return status.Pending.Generation.ID
	}
	return ""
}

func (api *API) handleValidationGates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg := api.getCfg()
	scope := hardGateScope(cfg)
	eval := evaluateProductionGates(cfg, api.currentGenerationID())
	readiness := validation.EvaluateReadiness(eval.ReadinessInputs, productionOwnerStates())
	meta := validation.RunMetaSuite(evidenceArtifacts())
	sendResponse(w, gateSnapshot{
		Scope:      scope,
		Evaluation: eval,
		Readiness:  readiness,
		Window:     validation.ProductionWindowInfo(),
		Meta:       meta,
		CheckedAt:  time.Now().UTC(),
	})
}

// evidenceArtifacts hashes the canonical registry sources from the working
// tree. On target devices without the repository the artifacts are absent and
// EvidenceIntegrity stays false (missing evidence is never PASS).
func evidenceArtifacts() []validation.Artifact {
	var out []validation.Artifact
	for _, path := range []string{
		"specs/registries/hard_gates.yaml",
		"src/validation/hard_gates_registry.gen.go",
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(b)
		out = append(out, validation.Artifact{
			Name:     path,
			SHA256:   hex.EncodeToString(sum[:]),
			Kind:     "evidence",
			Size:     int64(len(b)),
			Redacted: true,
		})
	}
	return out
}
