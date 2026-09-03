package validation

var ABDRequirements = []string{"ABD-1", "ABD-2", "ABD-3", "ABD-4", "ABD-5", "ABD-6", "ABD-7", "ABD-8", "ABD-9", "ABD-10", "ABD-11", "ABD-12"}

type ABDConformance struct {
	Requirements, TestIDs, Artifacts                                                                                             []string
	TargetPlan, CleanBaseline, MultiProtocol, DynamicControls, EvidenceGraph, BlockingProfile, RouterValidated, AndroidValidated bool
	HardGateViolations                                                                                                           []string
}

func (a ABDConformance) Ready() bool {
	return len(a.Requirements) == 12 && len(a.TestIDs) > 0 && len(a.Artifacts) > 0 && a.TargetPlan && a.CleanBaseline && a.MultiProtocol && a.DynamicControls && a.EvidenceGraph && a.BlockingProfile && a.RouterValidated && a.AndroidValidated && len(a.HardGateViolations) == 0
}

var DDIRequirements = []string{"DDI-1", "DDI-2", "DDI-3", "DDI-4", "DDI-5", "DDI-6", "DDI-7", "DDI-8", "DDI-9", "DDI-10"}

type DDIConformance struct {
	Requirements, TestIDs, Artifacts                                                                                  []string
	Envelope, Freshness, Revalidation, Priors, Baselines, FullFallback, GuidedAB, TargetControls, ActionAuthorization bool
	QualityDelta, Tolerance                                                                                           float64
	HardGateViolations                                                                                                []string
}

func (d DDIConformance) Ready() bool {
	return len(d.Requirements) == 10 && len(d.TestIDs) > 0 && len(d.Artifacts) > 0 && d.Envelope && d.Freshness && d.Revalidation && d.Priors && d.Baselines && d.FullFallback && d.GuidedAB && d.TargetControls && d.ActionAuthorization && d.QualityDelta >= -d.Tolerance && len(d.HardGateViolations) == 0
}

var TGBRequirements = []string{"TGB-1", "TGB-2", "TGB-3", "TGB-4", "TGB-5", "TGB-6", "TGB-7", "TGB-8", "TGB-9", "TGB-10"}

type TGBConformance struct {
	Requirements, TestIDs, Artifacts                                                                                                                 []string
	StructuredOutcome, DelayedFirstData, PendingBudget, PrefixExact, NonRecursiveFallback, AndroidValidated, ExplicitControlSeparated, CleanupClosed bool
	DestructiveZeroByteDrops                                                                                                                         int
	HardGateViolations                                                                                                                               []string
}

func (t TGBConformance) Ready() bool {
	return len(t.Requirements) == 10 && len(t.TestIDs) > 0 && len(t.Artifacts) > 0 && t.StructuredOutcome && t.DelayedFirstData && t.PendingBudget && t.PrefixExact && t.NonRecursiveFallback && t.AndroidValidated && t.ExplicitControlSeparated && t.CleanupClosed && t.DestructiveZeroByteDrops == 0 && len(t.HardGateViolations) == 0
}
