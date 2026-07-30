package validation

type PPEResult struct {
	CapabilityDetected, RuleScopeBound, BidirectionalVisible, SelfTestPassed, LifecycleClean bool
	QueueOwner, Generation                                                                   string
	ResourceCPU, ResourceMemoryMiB                                                           float64
}

func (r PPEResult) Ready() bool {
	return r.CapabilityDetected && r.RuleScopeBound && r.BidirectionalVisible && r.SelfTestPassed && r.LifecycleClean && r.QueueOwner != "" && r.Generation != ""
}
