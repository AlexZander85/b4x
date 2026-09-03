package fieldtest

type PathCounters struct{ PacketsBefore, PacketsAfter, BytesBefore, BytesAfter uint64 }

func (c PathCounters) Positive() bool {
	return c.PacketsAfter > c.PacketsBefore && c.BytesAfter > c.BytesBefore
}

type TransportPathProof struct {
	ProofID, SessionID, BindingID, RouteTokenID string
	ClientID, ComponentID, Interface, Namespace string
	ConfigGen, RouteGen, SessionGen             uint64
	Counters                                    PathCounters
	Forwarded, RouterOrigin, DNS, UDP, TCP      bool
	Current                                     bool
}

func (p TransportPathProof) Valid() bool {
	return p.ProofID != "" && p.SessionID != "" && p.BindingID != "" && p.RouteTokenID != "" && p.ConfigGen > 0 && p.RouteGen > 0 && p.SessionGen > 0 && p.Counters.Positive() && p.Current && (p.Forwarded || p.RouterOrigin)
}

type WARPBaseResult struct {
	EngineHash, SessionID string
	MTU                   int
	W0, W1, W2, W3, W4    bool
	Proofs                []TransportPathProof
	CleanupClosed         bool
}

func (r WARPBaseResult) Ready() bool {
	if r.EngineHash == "" || r.SessionID == "" || r.MTU != 1280 || !r.W0 || !r.W1 || !r.W2 || !r.W3 || !r.W4 || !r.CleanupClosed {
		return false
	}
	for _, p := range r.Proofs {
		if !p.Valid() {
			return false
		}
	}
	return len(r.Proofs) > 0
}
