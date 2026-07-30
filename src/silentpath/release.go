package silentpath

type ReleaseVerdict string

const (
	ObserveReady       ReleaseVerdict = "silent-observe-ready"
	RecommendReady     ReleaseVerdict = "silent-recommend-ready"
	AutoCanaryReady    ReleaseVerdict = "silent-auto-canary-ready"
	NotTargetValidated ReleaseVerdict = "implemented-not-target-validated"
)

func Verdict(unitPass, targetValidated bool) ReleaseVerdict {
	if !unitPass || !targetValidated {
		return NotTargetValidated
	}
	return AutoCanaryReady
}
