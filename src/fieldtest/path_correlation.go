package fieldtest

type AndroidBindingCorrelation struct {
	TestSessionID, ClientKey, ProfileID, ComponentID, BindingID, RouteTokenID string
	ConfigGen, RouteGen, SessionGen                                           uint64
	Milestone                                                                 string
	Forwarded                                                                 bool
	DirectFallback, ControlInheritedTarget                                    bool
}

func (c AndroidBindingCorrelation) Valid() bool {
	return c.TestSessionID != "" && c.ClientKey != "" && c.ProfileID != "" && c.ComponentID != "" && c.BindingID != "" && c.RouteTokenID != "" && c.ConfigGen > 0 && c.RouteGen > 0 && c.SessionGen > 0 && c.Milestone != "" && c.Forwarded && !c.DirectFallback && !c.ControlInheritedTarget
}

type RoutePathReport struct {
	Proofs                                               []TransportPathProof
	Correlations                                         []AndroidBindingCorrelation
	StaleProofs, RecursiveRoutes, WrongInterfaceCounters int
}

func (r RoutePathReport) Ready() bool {
	if len(r.Proofs) == 0 || len(r.Correlations) == 0 || r.StaleProofs > 0 || r.RecursiveRoutes > 0 || r.WrongInterfaceCounters > 0 {
		return false
	}
	for _, p := range r.Proofs {
		if !p.Valid() {
			return false
		}
	}
	for _, c := range r.Correlations {
		if !c.Valid() {
			return false
		}
	}
	return true
}
