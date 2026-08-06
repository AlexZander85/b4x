package serviceprofile

import (
	"errors"
	"fmt"
	"strings"
)

const BuiltinWARPKind = "cloudflare-warp-masque"

// WARPProjection is the §28A.5 runtime capability projection. Valid() models
// the production recommendation gate: bundled builtin engine + base transport
// + causal trace + path proof must all be ready before an actionable test
// button may be shown; anything less is diagnostic/manual-only.
type WARPProjection struct {
	Provider                                                                                                                                                    string
	BundledEngineAvailable, EnrollmentSupported, BaseTransportCapable, CausalTraceReady, PathProofSupported, ForwardedBindingCorrelation, TargetCanarySupported bool
	RuntimeState                                                                                                                                                string
	SafetyHash                                                                                                                                                  string
}

func (p WARPProjection) Valid() bool {
	return p.Provider == "builtin" && p.BundledEngineAvailable && p.BaseTransportCapable && p.CausalTraceReady && p.PathProofSupported
}

// ValidRuntimeStates are the §28A.5 current_runtime_state values shown in
// the warp_recommendation projection.
var ValidRuntimeStates = map[string]bool{
	"unconfigured": true,
	"ready":        true,
	"active":       true,
	"degraded":     true,
	"unavailable":  true,
}

// MarshalWARPRecommendation serializes the §28A.5 warp_recommendation YAML
// projection (9 fields, snake_case keys). The projection is the exact YAML
// block the UI consumes before showing an actionable test button; it fails
// closed on an unknown current_runtime_state.
func (p WARPProjection) MarshalWARPRecommendation() ([]byte, error) {
	if !ValidRuntimeStates[p.RuntimeState] {
		return nil, fmt.Errorf("invalid current_runtime_state %q", p.RuntimeState)
	}
	var b strings.Builder
	b.WriteString("warp_recommendation:\n")
	fmt.Fprintf(&b, "  transport_kind: %s\n", BuiltinWARPKind)
	fmt.Fprintf(&b, "  bundled_engine_available: %t\n", p.BundledEngineAvailable)
	fmt.Fprintf(&b, "  enrollment_supported: %t\n", p.EnrollmentSupported)
	fmt.Fprintf(&b, "  base_transport_capable: %t\n", p.BaseTransportCapable)
	fmt.Fprintf(&b, "  causal_trace_ready: %t\n", p.CausalTraceReady)
	fmt.Fprintf(&b, "  path_proof_supported: %t\n", p.PathProofSupported)
	fmt.Fprintf(&b, "  forwarded_binding_correlation: %t\n", p.ForwardedBindingCorrelation)
	fmt.Fprintf(&b, "  target_canary_supported: %t\n", p.TargetCanarySupported)
	fmt.Fprintf(&b, "  current_runtime_state: %s\n", p.RuntimeState)
	return []byte(b.String()), nil
}

type CamouflagePolicy struct {
	Enabled           bool
	MaxCandidates     int
	EstablishedBypass bool
	EndpointPin       string
	Experimental      bool
}
type NonRUPolicy struct {
	Enabled, Strict     bool
	RequireIPv6DNSProof bool
	GeoRequirement      string
}

func ValidateWARPPolicy(p WARPProjection, c CamouflagePolicy, n NonRUPolicy) error {
	if p.Provider != "builtin" || !p.BundledEngineAvailable {
		return errors.New("warp must use bundled builtin engine")
	}
	if c.MaxCandidates < 0 {
		return errors.New("negative camouflage bound")
	}
	if c.Enabled && c.EndpointPin == "" {
		return errors.New("endpoint pin required")
	}
	if n.Strict && n.GeoRequirement == "" {
		return errors.New("strict non-ru requires geo requirement")
	}
	if n.Strict && !n.Enabled {
		return errors.New("strict non-ru disabled")
	}
	return nil
}

func CompileStrictNonRU(p NonRUPolicy, capability WARPProjection) (NonRUPolicy, error) {
	if !p.Enabled {
		return p, nil
	}
	if p.Strict && (!capability.Valid() || !capability.ForwardedBindingCorrelation) {
		return NonRUPolicy{}, errors.New("strict non-ru capability unavailable")
	}
	return p, nil
}

type WARPHealth struct {
	Base, Camouflage, NonRU         string
	ObservedCountry, AttestationAge string
	DegradedReason                  string
}
type PromotionState string

const (
	PromotionPending      PromotionState = "pending"
	PromotionReady        PromotionState = "ready"
	PromotionExperimental PromotionState = "experimental"
	PromotionBlocked      PromotionState = "blocked"
)

func PromoteWARP(p WARPProjection, health WARPHealth, targetCanary, controls bool) PromotionState {
	if !p.Valid() || !targetCanary || !controls {
		return PromotionBlocked
	}
	if health.NonRU == "experimental" {
		return PromotionExperimental
	}
	if health.Base == "healthy" {
		return PromotionReady
	}
	return PromotionPending
}

type WARPWizardState struct {
	BaseEnabled       bool
	CamouflageChoice  string
	ExperimentalNonRU bool
	Health            WARPHealth
	TraceVisible      bool
	SecretsRedacted   bool
}

func (w WARPWizardState) Honest() bool {
	return w.SecretsRedacted && (w.Health.Base != "healthy" || w.Health.ObservedCountry != "")
}
