package serviceprofile

// Tests for the §28A.5 WARP readiness gates: the warp_recommendation
// projection must expose path_proof_supported (SP-30 DoD; FB-32 phase A) and
// the YAML serialization must emit the nine §28A.5 fields in snake_case.

import (
	"strings"
	"testing"
)

func validProjection() WARPProjection {
	return WARPProjection{
		Provider:                    "builtin",
		BundledEngineAvailable:      true,
		EnrollmentSupported:         true,
		BaseTransportCapable:        true,
		CausalTraceReady:            true,
		PathProofSupported:          true,
		ForwardedBindingCorrelation: true,
		TargetCanarySupported:       true,
		RuntimeState:                "ready",
		SafetyHash:                  "hash-1",
	}
}

// TestWARPProjectionValidRequiresPathProof: §28A.5 — causal trace and path
// proof must both be ready before an actionable test button; without
// path_proof_supported the projection is not valid for production
// recommendation even when the other capability booleans are true.
func TestWARPProjectionValidRequiresPathProof(t *testing.T) {
	p := validProjection()
	if !p.Valid() {
		t.Fatal("full projection must be valid")
	}
	p.PathProofSupported = false
	if p.Valid() {
		t.Fatal("projection without path proof must not be valid")
	}
	p = validProjection()
	p.CausalTraceReady = false
	if p.Valid() {
		t.Fatal("projection without causal trace must not be valid")
	}
}

// TestValidateWARPPolicyAllowsFullProjection: the policy validator must
// accept the §28A.5-ready projection (SP-30 DoD base capability).
func TestValidateWARPPolicyAllowsFullProjection(t *testing.T) {
	if err := ValidateWARPPolicy(validProjection(), CamouflagePolicy{}, NonRUPolicy{}); err != nil {
		t.Fatalf("full projection must validate: %v", err)
	}
}

// TestMarshalWARPRecommendationNineFields: YAML output must contain exactly
// the nine §28A.5 fields (snake_case), including path_proof_supported.
func TestMarshalWARPRecommendationNineFields(t *testing.T) {
	out, err := validProjection().MarshalWARPRecommendation()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(out)
	for _, key := range []string{
		"warp_recommendation:",
		"  transport_kind: cloudflare-warp-masque",
		"  bundled_engine_available: true",
		"  enrollment_supported: true",
		"  base_transport_capable: true",
		"  causal_trace_ready: true",
		"  path_proof_supported: true",
		"  forwarded_binding_correlation: true",
		"  target_canary_supported: true",
		"  current_runtime_state: ready",
	} {
		if !strings.Contains(s, key) {
			t.Fatalf("YAML missing %q:\n%s", key, s)
		}
	}
	if strings.Contains(s, "SafetyHash") || strings.Contains(s, "safety_hash") {
		t.Fatalf("safety hash must not leak into projection YAML:\n%s", s)
	}
}

// TestMarshalWARPRecommendationFailsClosedOnUnknownState: unknown
// current_runtime_state must produce an error, not an ambiguous projection.
func TestMarshalWARPRecommendationFailsClosedOnUnknownState(t *testing.T) {
	p := validProjection()
	p.RuntimeState = "bogus"
	if _, err := p.MarshalWARPRecommendation(); err == nil {
		t.Fatal("unknown runtime state must fail closed")
	}
}

// TestMarshalWARPRecommendationAllRuntimeStates: all five §28.5 enumerants
// serialize without error.
func TestMarshalWARPRecommendationAllRuntimeStates(t *testing.T) {
	for _, st := range []string{"unconfigured", "ready", "active", "degraded", "unavailable"} {
		p := validProjection()
		p.RuntimeState = st
		if _, err := p.MarshalWARPRecommendation(); err != nil {
			t.Fatalf("state %s must marshal: %v", st, err)
		}
	}
}
