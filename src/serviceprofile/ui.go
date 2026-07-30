package serviceprofile

type InstallMode string

const (
	InstallPreview InstallMode = "preview"
	InstallApply   InstallMode = "apply"
)

type HealthState string

const (
	HealthHealthy     HealthState = "healthy"
	HealthDegraded    HealthState = "degraded"
	HealthUnvalidated HealthState = "unvalidated"
	HealthLegacy      HealthState = "legacy"
)

type WizardView struct {
	Catalog             []string
	SelectedService     string
	SelectedDevice      string
	Mode                InstallMode
	Preview             Preview
	Health              HealthState
	EffectivePolicy     string
	AuthorizationTrace  []string
	LastNegativeControl string
	AdvancedLink        string
}

func (w WizardView) CanClaimHealthy() bool {
	return w.Health == HealthHealthy && w.EffectivePolicy != "" && w.LastNegativeControl != ""
}
