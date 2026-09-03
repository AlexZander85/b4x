package validation

type DNSFixture struct {
	Query, Answer, Resolver                string
	Consensus, SpoofDetected, CacheCorrect bool
}
type QUICFixture struct {
	Initial, Retry, VersionNegotiation, Handshake, HTTP3, TCPComparison bool
	SingleTargetGlobalVerdict                                           bool
}
type IPFamilyResult struct {
	IPv4, IPv6, DNSForward, DoH bool
	Parity                      bool
	Leak                        bool
}

func DNSReady(xs []DNSFixture) bool {
	if len(xs) == 0 {
		return false
	}
	for _, x := range xs {
		if !x.Consensus || !x.CacheCorrect || x.SpoofDetected {
			return false
		}
	}
	return true
}
func QUICReady(q QUICFixture) bool {
	return q.Initial && q.Retry && q.VersionNegotiation && q.Handshake && q.HTTP3 && q.TCPComparison && !q.SingleTargetGlobalVerdict
}
func IPFamilyReady(r IPFamilyResult) bool {
	return r.IPv4 && r.IPv6 && r.DNSForward && r.DoH && r.Parity && !r.Leak
}
