package validation

var FullRunOrder = []string{"static/provenance", "unit/property/fuzz", "synthetic-network", "clean-router-baseline", "warp-trace-order", "warp-path-forwarded", "warp-nested-geo-dns-ipv6-cleanup", "abd-target-evidence-profile", "ddi-revalidation", "guided-full-ab", "service-control-android", "tgb-synthetic-stress", "tgb-keenetic-android", "rollback-cleanup", "validation-of-validation", "independent-aggregation"}

type WARPVerdicts struct{ Base, Camouflage, NonRU, Causal Verdict }
type FullRun struct {
	Results           []StageResult
	WARP              WARPVerdicts
	DeclaredWARPScope bool
	CleanupComplete   bool
	BundleArtifacts   []Artifact
}

func (r FullRun) Verdict() Verdict {
	if r.DeclaredWARPScope && (r.WARP.Base != Pass || r.WARP.Camouflage == Blocked || r.WARP.NonRU == Blocked || r.WARP.Causal != Pass) {
		return Blocked
	}
	if !r.CleanupComplete {
		return Blocked
	}
	for _, a := range r.BundleArtifacts {
		if !ArtifactValid(a) {
			return Blocked
		}
	}
	return Aggregate(r.Results)
}
