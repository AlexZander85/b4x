package config

import (
	"errors"
	"testing"
)

func TestEffectiveDomainPolicyResolution(t *testing.T) {
	set := &SetConfig{Targets: TargetsConfig{DomainOnly: true}}
	cases := []struct {
		name   string
		global string
		policy DomainPolicy
		want   DomainPolicy
	}{
		{"absent inherits legacy", DomainLegacy, "", DomainPolicyLegacy},
		{"inherit scoped", DomainScopedHints, DomainPolicyInherit, DomainPolicyScopedHints},
		{"explicit strict", DomainLegacy, DomainPolicyStrict, DomainPolicyStrict},
		{"explicit scoped", DomainLegacy, DomainPolicyScopedHints, DomainPolicyScopedHints},
		{"explicit legacy", DomainStrict, DomainPolicyLegacy, DomainPolicyLegacy},
		{"explicit disabled", DomainStrict, DomainPolicyDisabled, DomainPolicyDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set.Targets.DomainPolicy = tc.policy
			if got := EffectiveDomainPolicy(tc.global, set); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
	set.Targets.DomainOnly = false
	if got := EffectiveDomainPolicy(DomainStrict, set); got != DomainPolicyDisabled {
		t.Fatalf("DomainOnly=false got %q", got)
	}
}

func TestUnsafeLegacyDomainScopeGuard(t *testing.T) {
	cfg := DefaultConfig
	cfg.System.Geo.GeoSitePath = ""
	cfg.System.Geo.GeoIpPath = ""
	set := NewSetConfig()
	set.Id = "legacy"
	set.Name = "legacy"
	set.Targets.DomainOnly = true
	set.Targets.DomainPolicy = DomainPolicyLegacy
	set.Targets.IPs = []string{"203.0.113.0/24"}
	set.Routing.Enabled = true
	set.Routing.Mode = RoutingModeInterface
	cfg.Sets = []*SetConfig{&set}
	err := cfg.Validate()
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
	found := false
	for _, field := range validation.Fields {
		found = found || field.Code == UnsafeLegacyDomainScopeReason
	}
	if !found {
		t.Fatalf("missing %s: %+v", UnsafeLegacyDomainScopeReason, validation.Fields)
	}

	cfg.System.Classifier.UnsafeLegacyDomainScopeOverride = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit unsafe override rejected: %v", err)
	}
}

func TestObserveOnlyLegacyAcceptedAndPreviewed(t *testing.T) {
	cfg := DefaultConfig
	set := SetConfig{Id: "observe", Name: "observe", Enabled: true, Targets: TargetsConfig{DomainOnly: true, DomainPolicy: DomainPolicyLegacy, IPs: []string{"203.0.113.1"}}}
	cfg.Sets = []*SetConfig{&set}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("observe-only legacy rejected: %v", err)
	}
	preview := cfg.PreviewDomainPolicyMigration()
	if len(preview) != 1 || preview[0].To != DomainPolicyScopedHints || preview[0].Required {
		t.Fatalf("unexpected preview: %+v", preview)
	}
}

func TestGeneratedProfileNeverUsesLegacy(t *testing.T) {
	set := SetConfig{Targets: TargetsConfig{DomainOnly: true}}
	if err := PrepareGeneratedSetDomainPolicy(&set); err != nil || set.Targets.DomainPolicy != DomainPolicyScopedHints {
		t.Fatalf("managed default not scoped-hints: policy=%q err=%v", set.Targets.DomainPolicy, err)
	}
	set.Targets.DomainPolicy = DomainPolicyLegacy
	if err := PrepareGeneratedSetDomainPolicy(&set); err == nil {
		t.Fatal("legacy generated policy accepted")
	}
}
