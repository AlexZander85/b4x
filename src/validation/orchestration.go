package validation

// FullRunOrder is the normative capability execution schedule for a full run
// (FB-36, b4x-0yf). It is no longer a hand-maintained literal: it is derived
// from the canonical Capability Dependency Graph (specs/registries/
// capability_dependencies.yaml via capability_deps.gen.go), so missing
// upstream dependencies (MON/ABD/DDI) can never be scheduled after WARP, and
// the scheduler cannot silently drop MON (the abandoned stage list below kept
// WARP before ABD and had no MON step at all):
//
//	Legacy literal (replaced): static/provenance, unit/property/fuzz,
//	synthetic-network, clean-router-baseline, warp-trace-order,
//	warp-path-forwarded, warp-nested-geo-dns-ipv6-cleanup,
//	abd-target-evidence-profile, ddi-revalidation, guided-full-ab,
//	service-control-android, tgb-synthetic-stress, tgb-keenetic-android,
//	rollback-cleanup, validation-of-validation, independent-aggregation
var FullRunOrder = CapabilityExecutionOrder()

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
