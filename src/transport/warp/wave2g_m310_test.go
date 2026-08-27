package transportwarp

import (
	"errors"
	"testing"
)

// M3-10: the "inner control must not egress direct-WAN" rule is enforced on
// the ACTUAL inner dial policy, and the declarative BaseInterface/InnerFwMark
// fields are wired into it so they constrain the socket (session.go:204).

func TestNestedValidateWiresDeclarativeConstraint(t *testing.T) {
	c := validNestedConfig() // BaseInterface: "warp-base", no user Policy
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config must pass: %v", err)
	}
	if c.InnerTemplate.Policy.BindDevice != "warp-base" {
		t.Fatalf("BaseInterface not injected into inner policy: BindDevice=%q", c.InnerTemplate.Policy.BindDevice)
	}
	if !c.InnerTemplate.Policy.Constrained() {
		t.Fatal("injected inner policy must be constrained")
	}
}

func TestNestedValidateInjectsInnerFwMark(t *testing.T) {
	c := validNestedConfig()
	c.BaseInterface = ""
	c.InnerFwMark = 42
	if err := c.Validate(); err != nil {
		t.Fatalf("FwMark-declared config must pass: %v", err)
	}
	if c.InnerTemplate.Policy.FwMark != 42 {
		t.Fatalf("InnerFwMark not injected: FwMark=%d", c.InnerTemplate.Policy.FwMark)
	}
	if !c.InnerTemplate.Policy.RequireMark {
		t.Fatal("FwMark-only constraint must set RequireMark (fail-closed)")
	}
	if !c.InnerTemplate.Policy.Constrained() {
		t.Fatal("injected FwMark policy must be constrained")
	}
}

func TestNestedValidateRejectsDeclarativePlusPolicy(t *testing.T) {
	c := validNestedConfig() // BaseInterface referenced inside
	var explicit DialPolicy
	c.InnerTemplate.Policy = explicit
	c.InnerTemplate.Policy.FwMark = 7
	if err := c.Validate(); !errors.Is(err, ErrUnconstrainedInner) {
		t.Fatalf("declarative + user Policy must conflict, got %v", err)
	}
}

func TestNestedValidateEnforcesEmptyConstraint(t *testing.T) {
	c := validNestedConfig()
	c.BaseInterface = ""
	c.InnerFwMark = 0
	c.InnerTemplate.Policy = DialPolicy{}
	if err := c.Validate(); !errors.Is(err, ErrUnconstrainedInner) {
		t.Fatalf("empty constraint + !AllowUnconstrainedInner must reject, got %v", err)
	}
	// Escape hatch stays usable for tests only.
	c.AllowUnconstrainedInner = true
	if err := c.Validate(); err != nil {
		t.Fatalf("AllowUnconstrainedInner escape hatch must pass: %v", err)
	}
}
