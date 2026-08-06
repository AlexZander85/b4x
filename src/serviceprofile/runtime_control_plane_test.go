package serviceprofile

import (
	"strings"
	"testing"
	"time"
)

// TestRuntimeSnapshotRedacted verifies the control-plane projection never
// leaks the test token (SP-31 §28A.8 redaction): the API may learn that a
// token is active, never its value.
func TestRuntimeSnapshotRedacted(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	rt.Start()
	t.Cleanup(rt.Stop)

	r := spRecommendation()
	tx, err := rt.BeginTest(time.Now(), r)
	if err != nil {
		t.Fatalf("begin-test: %v", err)
	}
	if tx.TestToken == "" {
		t.Fatal("test token must be minted by begin-test")
	}
	snap, ok := rt.Snapshot(r.RecommendationID)
	if !ok {
		t.Fatal("snapshot must exist after begin-test")
	}
	if !snap.TestTokenActive {
		t.Fatal("snapshot must report an active test token")
	}
	if strings.Contains(snap.FailurePolicyPreview+snap.TransportKind+snap.RecommendationID, tx.TestToken) {
		t.Fatal("test token leaked into snapshot")
	}
	if snap.State != RecommendationTesting {
		t.Fatalf("state = %s, want testing", snap.State)
	}
	if snap.ProductionAuthorized {
		t.Fatal("begin-test must not authorize production")
	}
}

// TestRuntimeValidateTransactionCommitsVerdict drives the full §28A.6 bounded
// transaction through the production roots: compile -> begin-test ->
// validate (validated) -> enable, and proves ValidateTransaction is the
// missing link that commits the verdict into the transaction so that
// EnableAfterValidation can succeed afterwards.
func TestRuntimeValidateTransactionCommitsVerdict(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	rt.Start()
	t.Cleanup(rt.Stop)

	compiled, err := rt.Compile(time.Now(), spRecommendation(), spCompileCtx())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := rt.BeginTest(time.Now(), compiled); err != nil {
		t.Fatalf("begin-test: %v", err)
	}
	v := RecommendationValidation{
		RecommendationID:      compiled.RecommendationID,
		DirectFailed:          true,
		WARPReached:           true,
		ControlsHealthy:       true,
		PathProofCurrent:      true,
		ForwardedCanaryPassed: true,
		LeaksAbsent:           true,
		CleanedUp:             true,
	}
	state, err := rt.ValidateTransaction(compiled.RecommendationID, v, false)
	if err != nil {
		t.Fatalf("validate transaction: %v", err)
	}
	if state != RecommendationValidated {
		t.Fatalf("state = %s, want validated", state)
	}
	snap, _ := rt.Snapshot(compiled.RecommendationID)
	if snap.State != RecommendationValidated {
		t.Fatalf("snapshot state = %s, want validated", snap.State)
	}
	if err := rt.Enable(compiled.RecommendationID, spWARPProjection(), true); err != nil {
		t.Fatalf("enable after validated transaction must pass: %v", err)
	}
	snap, _ = rt.Snapshot(compiled.RecommendationID)
	if !snap.ProductionAuthorized {
		t.Fatal("enable must authorize production in the snapshot")
	}
	if snap.TestTokenActive {
		t.Fatal("finish must revoke the test token")
	}
}

// TestRuntimeValidateTransactionRejectedLeavesBlocked drives the honest
// failure path: a rejected validation (WARP did not reach the milestone)
// closes the transaction without authorizing production.
func TestRuntimeValidateTransactionRejectedLeavesBlocked(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	rt.Start()
	t.Cleanup(rt.Stop)

	compiled, err := rt.Compile(time.Now(), spRecommendation(), spCompileCtx())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := rt.BeginTest(time.Now(), compiled); err != nil {
		t.Fatalf("begin-test: %v", err)
	}
	v := RecommendationValidation{
		RecommendationID: compiled.RecommendationID,
		DirectFailed:     true,
		WARPReached:      false, // WARP did not reach the target milestone
		CleanedUp:        true,
	}
	state, err := rt.ValidateTransaction(compiled.RecommendationID, v, false)
	if err != nil {
		t.Fatalf("validate transaction: %v", err)
	}
	if state != RecommendationRejected {
		t.Fatalf("state = %s, want rejected", state)
	}
	if err := rt.Enable(compiled.RecommendationID, spWARPProjection(), true); err == nil {
		t.Fatal("enable after rejected validation must fail")
	}
}

// TestRuntimeValidateTransactionRequiresOpenTransaction proves the endpoint
// cannot validate a recommendation that never entered the bounded test
// transaction.
func TestRuntimeValidateTransactionRequiresOpenTransaction(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	rt.Start()
	t.Cleanup(rt.Stop)

	if _, err := rt.ValidateTransaction("unknown", RecommendationValidation{}, false); err == nil {
		t.Fatal("validate of unknown recommendation must fail")
	}
}

// TestRuntimeProjectionRoundTrip verifies the §28A.5 capability projection
// survives SetProjection/Projection and the status endpoint can render the
// canonical warp_recommendation YAML from it.
func TestRuntimeProjectionRoundTrip(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	rt.Start()
	t.Cleanup(rt.Stop)

	if p := rt.Projection(); p.RuntimeState != "" {
		t.Fatalf("fresh runtime must have no projection, got %+v", p)
	}
	rt.SetProjection(spWARPProjection())
	p := rt.Projection()
	if !p.Valid() {
		t.Fatal("projection must be valid after SetProjection")
	}
	yaml, err := p.MarshalWARPRecommendation()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(yaml)
	for _, key := range []string{
		"warp_recommendation:", "transport_kind:", "bundled_engine_available:",
		"enrollment_supported:", "base_transport_capable:", "causal_trace_ready:",
		"path_proof_supported:", "forwarded_binding_correlation:", "target_canary_supported:",
		"current_runtime_state: ready",
	} {
		if !strings.Contains(text, key) {
			t.Fatalf("yaml missing %q:\n%s", key, text)
		}
	}
}
