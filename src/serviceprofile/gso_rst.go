package serviceprofile

type GSOProjection struct {
	Policy                        string
	CertifiedTechnique            string
	PassiveRSTMaximum             string
	EffectiveMode, DegradedReason string
	ValidationRequired            bool
}

func (g GSOProjection) Valid() bool { return g.Policy != "" && g.PassiveRSTMaximum != "aggressive" }
func (g GSOProjection) Effective() string {
	if g.DegradedReason != "" {
		return "degraded"
	}
	return g.EffectiveMode
}
