package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"time"

	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/validation"
)

const validationGatesAPIPath = "/api/v2/validation/gates"

// gateSnapshot carries the live hard-gate evaluation (FB-03) for the
// validation API/CLI surface. Meta contains the meta-suite result; evidence
// artifacts are hashed from the working tree when available (registry YAML
// and generated Go reference), otherwise EvidenceIntegrity is false.
type gateSnapshot struct {
	Scope      validation.ReleaseScope   `json:"scope"`
	Evaluation validation.GateEvaluation `json:"evaluation"`
	Meta       validation.MetaResult     `json:"meta"`
	CheckedAt  time.Time                 `json:"checked_at"`
}

// RegisterValidationAPI wires the canonical hard-gate evaluation and the
// meta-suite into the HTTP API (FB-03 §4: validation API/CLI consumer).
func (api *API) RegisterValidationAPI() {
	api.mux.HandleFunc(validationGatesAPIPath, api.handleValidationGates)
}

func (api *API) handleValidationGates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg := api.getCfg()
	scope := hardGateScope(cfg)
	snap := observability.Default().Metrics.Snapshot(time.Now().UTC())
	counters := make(map[string]uint64, len(snap.Counters))
	produced := make(map[string]bool, len(snap.Counters))
	for _, s := range snap.Counters {
		counters[s.Name] += s.Value
		produced[s.Name] = true
	}
	eval := validation.EvaluateHardGates(scope, nil, "", validation.GenerationSet{}, counters, produced)
	meta := validation.RunMetaSuite(evidenceArtifacts())
	sendResponse(w, gateSnapshot{Scope: scope, Evaluation: eval, Meta: meta, CheckedAt: snap.GeneratedAt})
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
