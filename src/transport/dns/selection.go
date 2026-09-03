package dnspath

import (
	"sort"
	"time"
)

// CandidateEvidence aggregates everything selection may use for one path.
// Correctness gates are evaluated before scoring; a candidate that failed
// correctness is never scored (addendum §65).
type CandidateEvidence struct {
	Path            DNSPathID
	CorrectnessPass bool
	ControlsPass    bool
	Stability       float64 // 0..1 from repeated attempts
	Latency         time.Duration
	TimeoutRate     float64 // 0..1
	ResourceCost    float64 // 0..1 normalized CPU/RAM cost
	DNSSEC          bool
	NoLogClaim      bool
	NoFilterClaim   bool
	Anonymized      bool
	// CorrelatedGroup marks operator/provider/route dependency; candidates
	// sharing a group reduce each other's diversity contribution (§68).
	CorrelatedGroup string
	CatalogTrusted  bool
}

// Eligible reports whether the candidate passes the correctness gates.
func (c CandidateEvidence) Eligible(policy AdaptivePolicy) bool {
	if !c.CorrectnessPass || !c.ControlsPass {
		return false
	}
	if !policy.AllowsFamily(c.Path.Family) {
		return false
	}
	if policy.ManuallyExcluded(c.Path.Hash()) {
		return false
	}
	if policy.RequireDNSSECCapable && !c.DNSSEC {
		return false
	}
	if policy.RequireNoLogClaim && !c.NoLogClaim {
		return false
	}
	if policy.RequireNoFilterClaim && !c.NoFilterClaim {
		return false
	}
	return true
}

// Score computes the correctness-first candidate score (addendum §65).
// Correctness is a gate, not a summand; the score only ranks eligible
// candidates.
func Score(c CandidateEvidence, policy AdaptivePolicy) float64 {
	var s float64
	s += 40 * c.Stability
	s -= 20 * c.TimeoutRate
	s -= 10 * c.ResourceCost
	if !c.CatalogTrusted {
		s -= 15
	}
	switch policy.Preference {
	case PreferenceLowestLatency:
		s -= latencyPenalty(c.Latency, 30)
	case PreferenceBalanced:
		s -= latencyPenalty(c.Latency, 15)
		if c.DNSSEC {
			s += 3
		}
	case PreferencePrivacy:
		s -= latencyPenalty(c.Latency, 5)
		if c.NoLogClaim {
			s += 8
		}
		if c.NoFilterClaim {
			s += 4
		}
		if c.Anonymized {
			s += 10
		}
	case PreferenceMinimumDependency:
		s -= latencyPenalty(c.Latency, 10)
		// Minimum-complexity native path beats managed/anonymized at equal
		// correctness/stability (ADR-ADNS-014).
		s -= float64(c.Path.Family.Complexity()) * 4
	}
	return s
}

func latencyPenalty(d time.Duration, weight float64) float64 {
	ms := float64(d.Milliseconds())
	if ms < 0 {
		ms = 0
	}
	if ms > 2000 {
		ms = 2000
	}
	return weight * ms / 2000
}

// diversityBonus rewards fallbacks that do not share the primary's failure
// domain (addendum §68).
func diversityBonus(candidate, primary CandidateEvidence, weight float64) float64 {
	if candidate.CorrelatedGroup == "" || candidate.CorrelatedGroup != primary.CorrelatedGroup {
		return weight
	}
	if candidate.Path.Family != primary.Path.Family {
		return weight / 2
	}
	return 0
}

// RankedCandidate is the deterministic ordering output.
type RankedCandidate struct {
	Candidate CandidateEvidence
	Score     float64
}

// RankCandidates deterministically orders eligible candidates (addendum §66).
// Equal scores break ties by canonical DNSPathID ordering; no random shuffle.
func RankCandidates(candidates []CandidateEvidence, policy AdaptivePolicy) []RankedCandidate {
	ranked := make([]RankedCandidate, 0, len(candidates))
	for _, c := range candidates {
		if !c.Eligible(policy) {
			continue
		}
		ranked = append(ranked, RankedCandidate{Candidate: c, Score: Score(c, policy)})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].Score != ranked[j].Score {
			return ranked[i].Score > ranked[j].Score
		}
		return ranked[i].Candidate.Path.Canonical() < ranked[j].Candidate.Path.Canonical()
	})
	return ranked
}

// CompileProfileSelection picks a primary and diverse fallbacks from ranked
// candidates (addendum §68). Fallbacks avoid the primary's correlated failure
// group when possible.
func CompileProfileSelection(ranked []RankedCandidate, maxFallbacks int, diversityWeight float64) (primary *RankedCandidate, fallbacks []RankedCandidate) {
	if len(ranked) == 0 {
		return nil, nil
	}
	primary = &ranked[0]
	rest := ranked[1:]
	// Score fallback diversity and re-sort deterministically.
	type fb struct {
		RankedCandidate
		eff float64
	}
	scored := make([]fb, 0, len(rest))
	for _, r := range rest {
		if r.Candidate.Path.SamePathAlias(primary.Candidate.Path) {
			continue
		}
		scored = append(scored, fb{r, r.Score + diversityBonus(r.Candidate, primary.Candidate, diversityWeight)})
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].eff != scored[j].eff {
			return scored[i].eff > scored[j].eff
		}
		return scored[i].Candidate.Path.Canonical() < scored[j].Candidate.Path.Canonical()
	})
	for i := 0; i < len(scored) && len(fallbacks) < maxFallbacks; i++ {
		alias := false
		for _, chosen := range fallbacks {
			if scored[i].Candidate.Path.SamePathAlias(chosen.Candidate.Path) {
				alias = true
				break
			}
		}
		if !alias {
			fallbacks = append(fallbacks, scored[i].RankedCandidate)
		}
	}
	return primary, fallbacks
}

// FailurePrior is the failure-to-family prior (addendum §67). It boosts and
// penalizes families based on authoritative detector evidence; it never
// authorizes promotion by itself.
type FailurePrior struct {
	Boost    map[DNSPathFamily]float64
	Penalize map[DNSPathFamily]float64
	Exclude  map[DNSPathFamily]bool
}

func newFailurePrior() *FailurePrior {
	return &FailurePrior{
		Boost:    map[DNSPathFamily]float64{},
		Penalize: map[DNSPathFamily]float64{},
		Exclude:  map[DNSPathFamily]bool{},
	}
}

func (p *FailurePrior) boost(f DNSPathFamily, w float64)    { p.Boost[f] += w }
func (p *FailurePrior) penalize(f DNSPathFamily, w float64) { p.Penalize[f] += w }

// PriorFromEvidence maps detector evidence flags to family priors
// (addendum §67 table).
func PriorFromEvidence(poisoning, udpDrop, port53Blocked, dohTLSBlocked, udp443Blocked, resolverSpecific, ipv6Failure, allDNSCorrect bool) *FailurePrior {
	p := newFailurePrior()
	switch {
	case poisoning:
		// early UDP injection
		for _, f := range []DNSPathFamily{DNSPathTCP, DNSPathDoT, DNSPathDoH, DNSPathDNSCrypt} {
			p.boost(f, 10)
		}
		p.penalize(DNSPathSystemForward, 20)
		p.penalize(DNSPathUDP, 20)
	case udpDrop:
		// UDP timeout, TCP works
		for _, f := range []DNSPathFamily{DNSPathTCP, DNSPathDoT, DNSPathDoH} {
			p.boost(f, 10)
		}
		p.penalize(DNSPathUDP, 20)
		p.penalize(DNSPathSystemForward, 10)
	}
	if port53Blocked {
		// UDP+TCP port 53 fail, DoH works
		for _, f := range []DNSPathFamily{DNSPathDoH, DNSPathDNSCrypt, DNSPathODoH} {
			p.boost(f, 12)
		}
		p.penalize(DNSPathUDP, 25)
		p.penalize(DNSPathTCP, 25)
		p.penalize(DNSPathSystemForward, 25)
	}
	if dohTLSBlocked {
		// DoH TLS/SNI blocked, DNSCrypt works
		p.boost(DNSPathDNSCrypt, 12)
		p.boost(DNSPathAnonymizedDNSCrypt, 8)
		p.penalize(DNSPathDoH, 20)
	}
	if udp443Blocked {
		p.boost(DNSPathDoH, 8)
		p.boost(DNSPathTCP, 6)
		p.Exclude[DNSPathDoH3] = true
		p.Exclude[DNSPathDoQ] = true
	}
	if resolverSpecific {
		// handled per-resolver by the caller (exclude affected resolver across
		// transports until revalidated); family-level prior stays neutral.
	}
	if ipv6Failure {
		// family-level exclusion of IPv6 candidates is applied by the caller
		// via IPFamily filtering.
	}
	if allDNSCorrect {
		// DNS is fine: avoid resolver churn; non-DNS discovery families take
		// over. No boosts.
	}
	return p
}

// ApplyTo adjusts ranked scores by the prior. Excluded families are dropped.
func (p *FailurePrior) ApplyTo(ranked []RankedCandidate) []RankedCandidate {
	out := make([]RankedCandidate, 0, len(ranked))
	for _, r := range ranked {
		f := r.Candidate.Path.Family
		if p.Exclude[f] {
			continue
		}
		r.Score += p.Boost[f]
		r.Score -= p.Penalize[f]
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Candidate.Path.Canonical() < out[j].Candidate.Path.Canonical()
	})
	return out
}
