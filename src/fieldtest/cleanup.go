package fieldtest

type OwnedResource struct {
	ID, Kind, Generation, Owner string
	Terminal                    bool
	Foreign                     bool
}
type CleanupReport struct {
	Resources                                                                       []OwnedResource
	ParentLinkCurrent, GeoQuorumIndependent, DNSInnerProof, IPv6Proof, NoDirectLeak bool
	ParentReconnectInvalidated                                                      bool
}

func (r CleanupReport) Ready() bool {
	if !r.ParentLinkCurrent || !r.GeoQuorumIndependent || !r.DNSInnerProof || !r.IPv6Proof || !r.NoDirectLeak || !r.ParentReconnectInvalidated {
		return false
	}
	for _, x := range r.Resources {
		if x.Foreign || !x.Terminal || x.ID == "" || x.Generation == "" || x.Owner == "" {
			return false
		}
	}
	return len(r.Resources) > 0
}

type CausalTraceRelease struct {
	AC                TraceCausalReport
	AD                RoutePathReport
	AE                CleanupReport
	WARPHardGatesZero bool
	KeeneticCounters  bool
	AndroidForwarded  bool
	SafetyHash        string
}

const WARPTraceReady = "WARP_CAUSAL_TRACE_READY"

func (r CausalTraceRelease) Verdict() string {
	if r.AC.Ready() && r.AD.Ready() && r.AE.Ready() && r.WARPHardGatesZero && r.KeeneticCounters && r.AndroidForwarded && r.SafetyHash != "" {
		return WARPTraceReady
	}
	return string(PromotionBlocked)
}
