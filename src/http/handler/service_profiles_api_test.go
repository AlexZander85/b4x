package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/serviceprofile"
)

// spTestProjection is the §28A.5 capability projection a running daemon
// supplies to the runtime status surface during the endpoint tests.
func spTestProjection() serviceprofile.WARPProjection {
	return serviceprofile.WARPProjection{
		Provider:                    "builtin",
		BundledEngineAvailable:      true,
		EnrollmentSupported:         true,
		BaseTransportCapable:        true,
		CausalTraceReady:            true,
		PathProofSupported:          true,
		ForwardedBindingCorrelation: true,
		TargetCanarySupported:       true,
		RuntimeState:                "ready",
		SafetyHash:                  "hash-test",
	}
}

// newSPAPIHandler starts a live service-profile runtime, binds it through the
// production handler setter (the same call main.go makes) and registers only
// the service-profile endpoints so tests are isolated from the rest of the
// API surface.
func newSPAPIHandler(t *testing.T) (*API, *http.ServeMux) {
	t.Helper()
	rt := serviceprofile.NewRuntime(serviceprofile.DefaultConfig())
	rt.Start()
	t.Cleanup(func() {
		rt.Stop()
		SetServiceProfileRuntime(nil)
	})
	SetServiceProfileRuntime(rt)
	rt.SetProjection(spTestProjection())

	mux := http.NewServeMux()
	api := &API{mux: mux}
	api.RegisterServiceProfileAPI()
	return api, mux
}

func spHTTPRecommendation(id, hypothesis string) serviceprofile.TransportRecommendation {
	r := serviceprofile.TransportRecommendation{
		RecommendationID:     id,
		ServiceProfileID:     "svc-a",
		ComponentID:          "web",
		ClientScopeHash:      "client-a",
		SetID:                "set-1",
		BlockingProfileID:    "profile-1",
		NetworkContextID:     "wan-a",
		EvidenceRefs:         []string{"ev-1", "ev-2"},
		TransportKind:        "cloudflare-warp-masque",
		TransportMode:        "base",
		FailurePolicyPreview: "fail-open",
		ConfigGen:            7,
		SessionGen:           7,
		RouteGen:             7,
	}
	if hypothesis == "" {
		r.BlockingHypothesisID = "path_local_syn_filter_probable"
	} else {
		r.BlockingHypothesisID = hypothesis
	}
	return r
}

// TestServiceProfileStatusServesWARPRecommendationYAML is the E2E smoke for
// the §28A.5 status projection: a live runtime with a capability projection
// must serve the canonical nine-field warp_recommendation YAML and an empty
// (redacted) recommendation inventory.
func TestServiceProfileStatusServesWARPRecommendationYAML(t *testing.T) {
	_, mux := newSPAPIHandler(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, warpRecommendationAPIPath+"/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp warpRecommendationStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.RuntimeReady {
		t.Fatal("runtime_ready must be true")
	}
	if !resp.Projection.Valid() {
		t.Fatalf("projection must be valid, got %+v", resp.Projection)
	}
	for _, want := range []string{
		"warp_recommendation:",
		"transport_kind: cloudflare-warp-masque",
		"bundled_engine_available: true",
		"enrollment_supported: true",
		"base_transport_capable: true",
		"causal_trace_ready: true",
		"path_proof_supported: true",
		"forwarded_binding_correlation: true",
		"target_canary_supported: true",
		"current_runtime_state: ready",
	} {
		if !strings.Contains(resp.WarpRecommendationYAML, want) {
			t.Fatalf("yaml missing %q:\n%s", want, resp.WarpRecommendationYAML)
		}
	}
	if resp.GeneratedAt.IsZero() {
		t.Fatal("generated_at must be set")
	}
	if len(resp.Recommendations) != 0 {
		t.Fatalf("fresh runtime must have empty inventory, got %d", len(resp.Recommendations))
	}
}

// TestServiceProfileStatusWithoutRuntime is the fail-closed counterpart: the
// projection endpoints must not serve fabricated data when the runtime is
// not running.
func TestServiceProfileStatusWithoutRuntime(t *testing.T) {
	SetServiceProfileRuntime(nil)
	t.Cleanup(func() { SetServiceProfileRuntime(nil) })

	mux := http.NewServeMux()
	api := &API{mux: mux}
	api.RegisterServiceProfileAPI()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, warpRecommendationAPIPath+"/status", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 without runtime", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, warpRecommendationAPIPath+"/status", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}

// TestServiceProfileLifecycleEndToEnd drives the full production cycle over
// HTTP: compile -> begin-test -> validate -> apply, using the same production
// roots the daemon loop dispatches to, and proves the redacted snapshot is
// served at each step (§28A.6 bounded transaction).
func TestServiceProfileLifecycleEndToEnd(t *testing.T) {
	_, mux := newSPAPIHandler(t)

	var compiled serviceprofile.TransportRecommendation
	spPostJSON(t, mux, warpRecommendationAPIPath+"/compile", warpCompileRequest{
		Recommendation:    spHTTPRecommendation("rec-e2e", ""),
		IPPathEvidence:    true,
		OriginAlive:       true,
		ControlsHealthy:   true,
		ConsumerService:   "svc-a",
		EvidenceAuthority: "authoritative-abd",
	}, http.StatusCreated, &compiled)
	if compiled.State != serviceprofile.RecommendationEligibleToTest {
		t.Fatalf("compiled state = %s, want eligible-to-test", compiled.State)
	}

	spPostJSON(t, mux, warpRecommendationAPIPath+"/begin-test",
		warpBeginTestRequest{Recommendation: compiled}, http.StatusCreated, nil)
	resp := spGetStatus(t, mux)
	if len(resp.Recommendations) != 1 {
		t.Fatalf("inventory = %d, want 1", len(resp.Recommendations))
	}
	if !resp.Recommendations[0].TestTokenActive {
		t.Fatal("begin-test must mint an active test token (reported, not leaked)")
	}

	spPostJSON(t, mux, warpRecommendationAPIPath+"/validate", warpValidateRequest{
		RecommendationID: "rec-e2e",
		Validation: serviceprofile.RecommendationValidation{
			DirectFailed:          true,
			WARPReached:           true,
			ControlsHealthy:       true,
			PathProofCurrent:      true,
			ForwardedCanaryPassed: true,
			LeaksAbsent:           true,
			CleanedUp:             true,
		},
	}, http.StatusOK, nil)

	var applied serviceprofile.RecommendationSnapshot
	spPostJSON(t, mux, warpRecommendationAPIPath+"/apply", warpApplyRequest{
		RecommendationID:      "rec-e2e",
		ForwardedCanaryPassed: true,
	}, http.StatusOK, &applied)
	if !applied.ProductionAuthorized {
		t.Fatal("apply must authorize production for the validated recommendation")
	}
	if applied.TestTokenActive {
		t.Fatal("test token must be revoked after finish")
	}
}

// TestServiceProfileApplyBeforeValidationIsDenied proves production
// enablement requires a current scoped validation (SP-31: no apply without
// validated).
func TestServiceProfileApplyBeforeValidationIsDenied(t *testing.T) {
	_, mux := newSPAPIHandler(t)

	var compiled serviceprofile.TransportRecommendation
	spPostJSON(t, mux, warpRecommendationAPIPath+"/compile", warpCompileRequest{
		Recommendation:    spHTTPRecommendation("rec-apply-early", ""),
		IPPathEvidence:    true,
		OriginAlive:       true,
		ControlsHealthy:   true,
		ConsumerService:   "svc-a",
		EvidenceAuthority: "authoritative-abd",
	}, http.StatusCreated, &compiled)
	spPostJSON(t, mux, warpRecommendationAPIPath+"/begin-test",
		warpBeginTestRequest{Recommendation: compiled}, http.StatusCreated, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, spJSONRequest(http.MethodPost, warpRecommendationAPIPath+"/apply",
		warpApplyRequest{RecommendationID: "rec-apply-early", ForwardedCanaryPassed: true}))
	if rec.Code == http.StatusOK {
		t.Fatalf("apply before validation must not succeed, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestServiceProfileCompileRejectsOutsideCausalEligibility proves the
// endpoint runs the §28A.11 causal-eligibility guard: a hypothesis the
// FB-31 matrix does not map to scoped transport is rejected even with
// authoritative evidence (fail closed on unknown hypotheses).
func TestServiceProfileCompileRejectsOutsideCausalEligibility(t *testing.T) {
	_, mux := newSPAPIHandler(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, spJSONRequest(http.MethodPost, warpRecommendationAPIPath+"/compile", warpCompileRequest{
		Recommendation:    spHTTPRecommendation("rec-foreign", "no_such_hypothesis"),
		IPPathEvidence:    true,
		OriginAlive:       true,
		ControlsHealthy:   true,
		ConsumerService:   "svc-a",
		EvidenceAuthority: "authoritative-abd",
	}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("outside-causal compile must be 422, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---- helpers -----------------------------------------------------------------

func spGetStatus(t *testing.T, mux *http.ServeMux) warpRecommendationStatusResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, warpRecommendationAPIPath+"/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp warpRecommendationStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp
}

func spJSONRequest(method, path string, body any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(method, path, bytes.NewReader(b))
}

func spPostJSON(t *testing.T, mux *http.ServeMux, path string, body any, want int, dst any) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, spJSONRequest(http.MethodPost, path, body))
	if rec.Code != want {
		t.Fatalf("POST %s = %d, want %d; body = %s", path, rec.Code, want, rec.Body.String())
	}
	if dst != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
	}
}
