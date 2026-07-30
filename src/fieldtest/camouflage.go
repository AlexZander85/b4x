package fieldtest

type CamouflageCandidate string

const (
	C0 CamouflageCandidate = "C0"
	C1 CamouflageCandidate = "C1"
	C2 CamouflageCandidate = "C2"
	C3 CamouflageCandidate = "C3"
	C4 CamouflageCandidate = "C4"
	C5 CamouflageCandidate = "C5"
	C6 CamouflageCandidate = "C6"
)

type CamouflageResult struct {
	Candidate                                                             CamouflageCandidate
	Complexity                                                            int
	Stable, PinValid, CutoffVerified, PostCutoffMutationsZero, Authorized bool
	ConfigGen, RouteGen, SessionGen                                       uint64
}

func (r CamouflageResult) Valid() bool {
	return r.Stable && r.PinValid && r.CutoffVerified && r.PostCutoffMutationsZero && r.Authorized && r.ConfigGen > 0 && r.RouteGen > 0 && r.SessionGen > 0
}
func SelectCamouflage(xs []CamouflageResult) (CamouflageResult, bool) {
	var best CamouflageResult
	ok := false
	for _, x := range xs {
		if !x.Valid() {
			continue
		}
		if !ok || x.Complexity < best.Complexity {
			best = x
			ok = true
		}
	}
	return best, ok
}
