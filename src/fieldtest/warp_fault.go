package fieldtest

type FaultKind string

const (
	FaultEngine    FaultKind = "engine"
	FaultPin       FaultKind = "pin"
	FaultTUN       FaultKind = "tun"
	FaultRoute     FaultKind = "route"
	FaultFirewall  FaultKind = "firewall"
	FaultCrash     FaultKind = "crash"
	FaultTraceDrop FaultKind = "trace-drop"
	FaultOrphan    FaultKind = "orphan"
)

type FaultResult struct {
	Kind                                   FaultKind
	Recovered, FailOpen, Cleaned, LeakFree bool
	CPU, MemoryMiB, LatencyMS              float64
	Reason                                 string
}

func (r FaultResult) Safe() bool { return r.Recovered && r.Cleaned && r.LeakFree }
func FaultMatrixPass(xs []FaultResult) bool {
	if len(xs) == 0 {
		return false
	}
	for _, x := range xs {
		if !x.Safe() {
			return false
		}
	}
	return true
}
