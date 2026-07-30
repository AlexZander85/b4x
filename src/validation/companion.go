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
