package fieldtest

type WARPGate struct {
	Base                                        WARPBaseResult
	Camouflage                                  []CamouflageResult
	Nested                                      NonRUSuite
	Faults                                      []FaultResult
	TraceReady, RouteProofReady, ForwardedReady bool
	HardGateViolations                          []string
}

func (g WARPGate) Verdict() PromotionVerdict {
	if !g.Base.Ready() || !g.TraceReady || !g.RouteProofReady || !g.ForwardedReady || !FaultMatrixPass(g.Faults) || len(g.HardGateViolations) > 0 {
		return PromotionBlocked
	}
	return PromotionPass
}
func (g WARPGate) SeparateVerdicts() (PromotionVerdict, PromotionVerdict) {
	base := g.Verdict()
	nested := PromotionBlocked
	if g.Nested.Ready() {
		nested = PromotionPass
	}
	return base, nested
}
