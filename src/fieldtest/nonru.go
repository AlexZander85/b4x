package fieldtest

type NonRUVerdict string

const (
	NonRUVerified     NonRUVerdict = "NONRU_VERIFIED"
	NonRUUnavailable  NonRUVerdict = "NONRU_UNAVAILABLE"
	NonRURUObserved   NonRUVerdict = "NONRU_RU_OBSERVED"
	NonRUConflict     NonRUVerdict = "NONRU_CONFLICTING_ATTESTATION"
	NonRUStale        NonRUVerdict = "NONRU_STALE"
	NonRUPathUnproven NonRUVerdict = "NONRU_PATH_UNPROVEN"
	NonRUBlocked      NonRUVerdict = "NONRU_BLOCKED_CAPABILITY"
)

type GeoProviderEvent struct {
	Provider, Country, AttestationID string
	Current                          bool
	RouteProof                       TransportPathProof
}
type NonRUSuite struct {
	ParentSessionID, ParentSessionGen, InnerSessionID           string
	Providers                                                   []GeoProviderEvent
	DNSInnerPath, IPv6Validated, DirectWANAbsent, CleanupClosed bool
	Strict                                                      bool
	Verdict                                                     NonRUVerdict
}

func (s NonRUSuite) Quorum() (string, bool) {
	counts := map[string]int{}
	for _, p := range s.Providers {
		if p.Current && p.RouteProof.Valid() {
			counts[p.Country]++
		}
	}
	for c, n := range counts {
		if n >= 2 {
			return c, true
		}
	}
	return "", false
}
func (s NonRUSuite) Ready() bool {
	country, ok := s.Quorum()
	return s.ParentSessionID != "" && s.ParentSessionGen != "" && s.InnerSessionID != "" && ok && country != "RU" && s.DNSInnerPath && s.IPv6Validated && s.DirectWANAbsent && s.CleanupClosed && s.Verdict == NonRUVerified
}
