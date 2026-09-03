package serviceprofile

import (
	"testing"

	"github.com/daniellavrushin/b4/serviceprofile/schema"
)

// TestCompileSafetyHashCanonicalIgnoresFieldOrder pins the canonical-sorting
// hash invariant: the same profile in different field orders yields the same
// safety hash, and executable-only fields (none exist in schema) cannot
// change authoring semantics. This backs SP-12 "preview compile" /
// deterministic compilation (DoD 4).
func TestCompileSafetyHashCanonicalIgnoresFieldOrder(t *testing.T) {
	m1 := schema.Manifest{SchemaVersion: 1, ID: "svc", Name: "Service", Classification: "custom", Components: []schema.Component{
		{ID: "web", Delivery: schema.DirectStrategy, Execution: schema.ExecutionObserve, Targets: []schema.Target{{Name: "a", Role: "primary", Domains: []string{"b.example", "a.example"}}}},
		{ID: "api", Delivery: schema.DirectStrategy, Execution: schema.ExecutionObserve, Targets: []schema.Target{{Name: "b", Role: "primary", Domains: []string{"api.example"}}}},
	}}
	m2 := schema.Manifest{SchemaVersion: 1, ID: "svc", Name: "Service", Classification: "custom", Components: []schema.Component{
		{ID: "api", Delivery: schema.DirectStrategy, Execution: schema.ExecutionObserve, Targets: []schema.Target{{Name: "b", Role: "primary", Domains: []string{"api.example"}}}},
		{ID: "web", Delivery: schema.DirectStrategy, Execution: schema.ExecutionObserve, Targets: []schema.Target{{Name: "a", Role: "primary", Domains: []string{"a.example", "b.example"}}}},
	}}
	if m1.SafetyHash() != m2.SafetyHash() {
		t.Fatalf("canonical hash must be order-independent: %s != %s", m1.SafetyHash(), m2.SafetyHash())
	}
	// Distinct manifest must differ.
	m3 := m1
	m3.Name = "Other"
	if m1.SafetyHash() == m3.SafetyHash() {
		t.Fatal("distinct manifests must differ")
	}
}

// TestWizardViewHealthClaimsPinCanClaimHealthy covers the beginner-UI claim:
// Healthy must not be claimable under legacy/degraded/unvalidated isolation
// (DoD 37) — the mapping is exposed through WizardView.CanClaimHealthy.
func TestWizardViewHealthClaims(t *testing.T) {
	healthy := WizardView{Health: HealthHealthy, EffectivePolicy: "observe", LastNegativeControl: "none"}
	if !healthy.CanClaimHealthy() {
		t.Fatal("healthy view must claim healthy")
	}
	for _, h := range []HealthState{HealthDegraded, HealthUnvalidated, HealthLegacy} {
		v := healthy
		v.Health = h
		if v.CanClaimHealthy() {
			t.Fatalf("view with %s must not claim healthy (DoD 37)", h)
		}
	}
	noPolicy := healthy
	noPolicy.EffectivePolicy = ""
	if noPolicy.CanClaimHealthy() {
		t.Fatal("view without effective policy must not claim healthy")
	}
}

// TestCustomTemplatesComposeWithObjectives ensures user-authored custom packs
// compile cleanly through the same objectives path as starter packs.
func TestCustomTemplatesComposeObjectives(t *testing.T) {
	for _, pack := range []StarterPack{
		CustomDomainGroupPack("dg", "d.example"),
		CustomStreamingServicePack("ss", "s.example"),
		CustomAPIPlusMediaPack("am", "a.example", "m.example"),
		CustomTransportRequiredServicePack("tr", "t.example"),
	} {
		compiled, err := Compile(pack.Manifest, CompileOptions{})
		if err != nil {
			t.Fatalf("%s: %v", pack.Manifest.ID, err)
		}
		if len(compiled.Sets) == 0 {
			t.Fatalf("%s: no compiled sets", pack.Manifest.ID)
		}
		for _, s := range compiled.Sets {
			if s.ID == "" || s.Domain == "" {
				t.Fatalf("%s: broken set %+v", pack.Manifest.ID, s)
			}
		}
	}
}
