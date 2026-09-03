package validation

type TransportFixture struct {
	Kind, Scope                                                                                         string
	RouteLeak, RecursiveRoute, NATLeak, SOCKSHealthy, TUNHealthy, WARPReady, AtomicApply, RollbackClean bool
	ConfigGen, RouteGen, SessionGen                                                                     uint64
}

func (f TransportFixture) Ready() bool {
	return f.Kind != "" && f.Scope != "" && !f.RouteLeak && !f.RecursiveRoute && !f.NATLeak && f.SOCKSHealthy && f.TUNHealthy && f.WARPReady && f.AtomicApply && f.RollbackClean && f.ConfigGen > 0 && f.RouteGen > 0 && f.SessionGen > 0
}

type LifecycleResult struct{ Applied, ActiveFlowsPreserved, LastGood, CanaryRollback, RestartRecovered, CleanupClosed bool }

func (r LifecycleResult) Ready() bool {
	return r.Applied && r.ActiveFlowsPreserved && r.LastGood && r.CanaryRollback && r.RestartRecovered && r.CleanupClosed
}
