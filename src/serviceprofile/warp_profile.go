package serviceprofile

import "errors"

const BuiltinWARPKind = "cloudflare-warp-masque"

type WARPProjection struct {
	Provider                                                                                                                                string
	BundledEngineAvailable, EnrollmentSupported, BaseTransportCapable, CausalTraceReady, ForwardedBindingCorrelation, TargetCanarySupported bool
	RuntimeState                                                                                                                            string
	SafetyHash                                                                                                                              string
}

func (p WARPProjection) Valid() bool {
	return p.Provider == "builtin" && p.BundledEngineAvailable && p.BaseTransportCapable && p.CausalTraceReady
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
