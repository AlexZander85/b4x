package discovery

import (
	"errors"
	"testing"

	"github.com/daniellavrushin/b4/capture/ppe"
)

func TestAutomaticDiscoveryRequiresCompleteVisibility(t *testing.T) {
	gate := ppe.DefaultVisibilityGate()
	gate.DisableRequirement("test reset")
	defer gate.DisableRequirement("test cleanup")
	gate.EnsureRequired("gen-1", "proof required")
	_, err := NewRuntime().StartSuite(nil, nil, StartSuiteOptions{Automatic: true})
	if !errors.Is(err, ErrAutomaticDiscoveryVisibility) {
		t.Fatalf("err=%v", err)
	}
}
