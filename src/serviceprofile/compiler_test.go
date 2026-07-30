package serviceprofile

import (
	"github.com/daniellavrushin/b4/serviceprofile/schema"
	"testing"
)

func TestCompileDeterministic(t *testing.T) {
	m := schema.Manifest{SchemaVersion: 1, ID: "x", Name: "x", Components: []schema.Component{{ID: "c", Delivery: schema.DirectStrategy, Execution: schema.ExecutionObserve, Targets: []schema.Target{{Name: "a", Role: "primary", Domains: []string{"a.example"}}}}}}
	a, e := Compile(m, CompileOptions{})
	if e != nil {
		t.Fatal(e)
	}
	b, _ := Compile(m, CompileOptions{})
	if a.SafetyHash != b.SafetyHash || a.Sets[0].ID != b.Sets[0].ID {
		t.Fatal("not deterministic")
	}
}
