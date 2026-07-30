package fieldtest

import "sort"

type CandidateMetrics struct {
	CandidateID, ComponentID                                                                               string
	ColdStartMS, FirstByteMS, FirstFrameMS, GoodputBPS, StallCount, Retries, PacketAmplification, CPU, RAM float64
	ControlsClean                                                                                          bool
	EvidenceReady                                                                                          bool
}
type CandidateGate struct {
	MinGoodput, MaxColdStart, MaxFirstFrame, MaxStalls, MaxRetries, MaxCPU, MaxRAM float64
	RequireControls, RequireEvidence                                               bool
}

func Eligible(m CandidateMetrics, g CandidateGate) bool {
	return m.GoodputBPS >= g.MinGoodput && m.ColdStartMS <= g.MaxColdStart && m.FirstFrameMS <= g.MaxFirstFrame && m.StallCount <= g.MaxStalls && m.Retries <= g.MaxRetries && m.CPU <= g.MaxCPU && m.RAM <= g.MaxRAM && (!g.RequireControls || m.ControlsClean) && (!g.RequireEvidence || m.EvidenceReady)
}
func Rank(xs []CandidateMetrics) []CandidateMetrics {
	out := append([]CandidateMetrics(nil), xs...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ComponentID != out[j].ComponentID {
			return out[i].ComponentID < out[j].ComponentID
		}
		if out[i].FirstFrameMS != out[j].FirstFrameMS {
			return out[i].FirstFrameMS < out[j].FirstFrameMS
		}
		return out[i].GoodputBPS > out[j].GoodputBPS
	})
	return out
}
