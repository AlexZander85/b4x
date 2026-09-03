package validate

import (
	"github.com/daniellavrushin/b4/serviceprofile/schema"
	"testing"
)

func TestManifestRejectsAggressiveRSTAndAcceptsCanonical(t *testing.T) {
	m := schema.Manifest{SchemaVersion: 1, ID: "youtube", Name: "YouTube", Components: []schema.Component{{ID: "video", Delivery: schema.DirectStrategy, Execution: schema.ExecutionObserve, PassiveRST: "observe-max", Targets: []schema.Target{{Name: "youtubei.googleapis.com", Role: "primary", Domains: []string{"youtubei.googleapis.com"}}}}}}
	if err := Manifest(m); err != nil {
		t.Fatal(err)
	}
	if m.SafetyHash() != m.SafetyHash() {
		t.Fatal("non deterministic")
	}
	m.Components[0].PassiveRST = "aggressive"
	if err := Manifest(m); err == nil {
		t.Fatal("accepted aggressive rst")
	}
}
