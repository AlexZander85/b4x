package detector

import (
	"sort"

	"github.com/daniellavrushin/b4/monitor"
)

// DifferentialKind identifies bounded active comparisons that explain why a
// target failed before discovery escalates to a more aggressive strategy.
type DifferentialKind string

const (
	DifferentialPathPair    DifferentialKind = "path-pair"
	DifferentialDNSControl  DifferentialKind = "dns-control"
	DifferentialAltEndpoint DifferentialKind = "alternative-endpoint"
)

type DifferentialVerdict string

const (
	DifferentialNoOpinion              DifferentialVerdict = "NO_OPINION"
	DifferentialDPIInterference        DifferentialVerdict = "DPI_INTERFERENCE"
	DifferentialOriginOrNetwork        DifferentialVerdict = "ORIGIN_OR_NETWORK_FAILURE"
	DifferentialProcessedRegression    DifferentialVerdict = "PROCESSED_PATH_REGRESSION"
	DifferentialNoDifference           DifferentialVerdict = "NO_DIFFERENTIAL"
	DifferentialDNSHijackSuspected     DifferentialVerdict = "DNS_HIJACK_SUSPECTED"
	DifferentialDNSClassicInterference DifferentialVerdict = "DNS_CLASSIC_PATH_INTERFERENCE"
	DifferentialDNSConsistent          DifferentialVerdict = "DNS_CONSISTENT"
	DifferentialDNSDivergence          DifferentialVerdict = "DNS_DIVERGENCE_NEEDS_CORROBORATION"
	DifferentialAlternativeAvailable   DifferentialVerdict = "ALTERNATIVE_ENDPOINT_AVAILABLE"
)

// DifferentialSignal is classifier evidence, not an action. In particular,
// DeferAggressiveEscalation asks discovery to try a cheaper explanation/path
// first; it never promotes or changes a strategy by itself.
type DifferentialSignal struct {
	Kind                      DifferentialKind
	Verdict                   DifferentialVerdict
	SupportsDPI               bool
	Confidence                float64
	DeferAggressiveEscalation bool
	Reason                    string
	EvidenceRefs              []string
}

type PathProbeOutcome struct {
	Scope        monitor.MonitorScopeKey
	Mode         ProbePathMode
	Observation  VantageObservation
	EvidenceRefs []string
}

// CompareDirectAndProcessed implements the b4 direct-vs-anti-DPI control.
// Both observations must belong to the exact same monitor scope/generation,
// target, endpoint mode and protocol stage; any mismatch fails closed to
// NO_OPINION so a stale async result cannot become current DPI evidence.
func CompareDirectAndProcessed(direct, processed PathProbeOutcome) DifferentialSignal {
	s := DifferentialSignal{Kind: DifferentialPathPair, Verdict: DifferentialNoOpinion}
	if !direct.Scope.Valid() || direct.Scope != processed.Scope {
		s.Reason = "path observations are not bound to the same valid monitor scope"
		return s
	}
	if direct.Mode != PathNativeDirect || processed.Mode == PathNativeDirect || processed.Mode == "" {
		s.Reason = "path roles are not direct-vs-processed"
		return s
	}
	d, p := direct.Observation, processed.Observation
	if !d.Available || !p.Available || d.TargetID == "" || d.TargetID != p.TargetID || d.Stage == "" || d.Stage != p.Stage || d.ExactEndpoint != p.ExactEndpoint {
		s.Reason = "path observations are unavailable or not stage/target aligned"
		return s
	}
	s.EvidenceRefs = mergeRefs(direct.EvidenceRefs, processed.EvidenceRefs)
	switch {
	case !d.Success && p.Success:
		s.Verdict = DifferentialDPIInterference
		s.SupportsDPI = true
		s.Confidence = 0.95
		s.Reason = "same endpoint/stage fails natively but succeeds on processed path"
	case !d.Success && !p.Success:
		s.Verdict = DifferentialOriginOrNetwork
		s.Confidence = 0.75
		s.DeferAggressiveEscalation = true
		s.Reason = "both native and processed paths fail; outage/origin/path failure remains plausible"
	case d.Success && !p.Success:
		s.Verdict = DifferentialProcessedRegression
		s.Confidence = 0.90
		s.DeferAggressiveEscalation = true
		s.Reason = "native path succeeds while processed path fails"
	default:
		s.Verdict = DifferentialNoDifference
		s.Confidence = 0.80
		s.Reason = "both paths succeed at the same stage"
	}
	return s
}

type DNSControlTransport string

const (
	DNSControlClassic DNSControlTransport = "classic"
	DNSControlDoH     DNSControlTransport = "doh"
	DNSControlDoT     DNSControlTransport = "dot"
)

// DNSControlObservation stores endpoint hashes only. Bogus is set by an
// existing DNS classifier when the answer is a known stub/fake response.
type DNSControlObservation struct {
	Scope        monitor.MonitorScopeKey
	QNameHash    string
	Transport    DNSControlTransport
	Answers      []string
	Success      bool
	Negative     bool
	Bogus        bool
	EvidenceRefs []string
}

// CompareClassicDNSWithEncrypted treats encrypted DNS as a control detector,
// not as a replacement resolver. A mere CDN answer-set difference is kept as
// low-confidence divergence and cannot support a DPI claim without another
// signal. Cross-generation comparisons fail closed.
func CompareClassicDNSWithEncrypted(classic, encrypted DNSControlObservation) DifferentialSignal {
	s := DifferentialSignal{Kind: DifferentialDNSControl, Verdict: DifferentialNoOpinion}
	if !classic.Scope.Valid() || classic.Scope != encrypted.Scope {
		s.Reason = "DNS controls are not bound to the same valid monitor scope"
		return s
	}
	if classic.Transport != DNSControlClassic || (encrypted.Transport != DNSControlDoH && encrypted.Transport != DNSControlDoT) || classic.QNameHash == "" || classic.QNameHash != encrypted.QNameHash {
		s.Reason = "DNS observations are not classic-vs-encrypted controls for the same qname"
		return s
	}
	s.EvidenceRefs = mergeRefs(classic.EvidenceRefs, encrypted.EvidenceRefs)
	if !encrypted.Success {
		s.Reason = "encrypted DNS control unavailable"
		return s
	}
	if (classic.Bogus || classic.Negative) && !encrypted.Negative && len(encrypted.Answers) > 0 {
		s.Verdict = DifferentialDNSHijackSuspected
		s.SupportsDPI = true
		s.Confidence = 0.95
		s.Reason = "classic DNS produced bogus/negative result while encrypted control returned usable answers"
		return s
	}
	if !classic.Success {
		s.Verdict = DifferentialDNSClassicInterference
		s.SupportsDPI = true
		s.Confidence = 0.85
		s.Reason = "classic DNS path failed while encrypted control succeeded"
		return s
	}
	if classic.Negative == encrypted.Negative && sameStringSet(classic.Answers, encrypted.Answers) {
		s.Verdict = DifferentialDNSConsistent
		s.Confidence = 0.85
		s.Reason = "classic and encrypted DNS controls agree"
		return s
	}
	if classic.Success {
		s.Verdict = DifferentialDNSDivergence
		s.Confidence = 0.40
		s.DeferAggressiveEscalation = true
		s.Reason = "DNS answer sets diverge; CDN variance must be excluded before a hijack claim"
		return s
	}
	s.Reason = "insufficient DNS control evidence"
	return s
}

type AlternativeEndpointDecision struct {
	Signal          DifferentialSignal
	PrimaryHash     string
	AlternativeHash string
	Family          string
}

// RecommendAlternativeEndpoint implements the b4 alternative-IP/CDN guard.
// It only recommends a sibling from the same address family and the same
// resolution snapshot/experiment after the primary has terminal failure.
// Selection is deterministic: lowest measured latency, then address index.
func RecommendAlternativeEndpoint(primaryHash string, outcomes []DNSAddressOutcome) AlternativeEndpointDecision {
	decision := AlternativeEndpointDecision{PrimaryHash: primaryHash}
	decision.Signal = DifferentialSignal{Kind: DifferentialAltEndpoint, Verdict: DifferentialNoOpinion}
	if primaryHash == "" {
		decision.Signal.Reason = "primary endpoint is required"
		return decision
	}
	var primary *DNSAddressOutcome
	for i := range outcomes {
		if outcomes[i].IPHash == primaryHash {
			primary = &outcomes[i]
			break
		}
	}
	if primary == nil || primary.Success {
		decision.Signal.Reason = "primary endpoint is missing or did not fail"
		return decision
	}
	candidates := make([]DNSAddressOutcome, 0)
	for _, o := range outcomes {
		if !o.Success || o.IPHash == "" || o.IPHash == primary.IPHash || o.IPFamily != primary.IPFamily {
			continue
		}
		if primary.SnapshotID != "" && o.SnapshotID != primary.SnapshotID {
			continue
		}
		if primary.Experiment != "" && o.Experiment != primary.Experiment {
			continue
		}
		candidates = append(candidates, o)
	}
	if len(candidates) == 0 {
		decision.Signal.Reason = "no successful sibling endpoint in the same resolution experiment"
		return decision
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		li, lj := candidates[i].LatencyMS, candidates[j].LatencyMS
		if li == 0 && lj != 0 {
			return false
		}
		if lj == 0 && li != 0 {
			return true
		}
		if li != lj {
			return li < lj
		}
		return candidates[i].AddressIndex < candidates[j].AddressIndex
	})
	alt := candidates[0]
	decision.AlternativeHash = alt.IPHash
	decision.Family = alt.IPFamily
	decision.Signal.Verdict = DifferentialAlternativeAvailable
	decision.Signal.Confidence = 0.90
	decision.Signal.DeferAggressiveEscalation = true
	decision.Signal.Reason = "primary failed while a sibling endpoint in the same resolution experiment succeeded"
	decision.Signal.EvidenceRefs = mergeRefs(primary.EvidenceRefs, alt.EvidenceRefs)
	return decision
}

// AddDPISupportToGraph adds only positive DPI differential evidence. The
// caller supplies the authority; this function never upgrades provisional or
// passive evidence to authoritative ABD evidence.
func AddDPISupportToGraph(g *EvidenceGraph, scope monitor.MonitorScopeKey, nodeID, hypothesisID string, authority monitor.EvidenceAuthority, signal DifferentialSignal) bool {
	if g == nil || !scope.Valid() || nodeID == "" || hypothesisID == "" || !signal.SupportsDPI || signal.Confidence <= 0 {
		return false
	}
	g.AddNode(EvidenceNode{
		ID:             nodeID,
		Kind:           NodeObservation,
		Authority:      authority,
		Attribution:    monitor.AttributionTransport,
		Scope:          scope,
		Active:         true,
		IndependentKey: string(signal.Kind) + ":" + nodeID,
		Supports:       true,
	})
	g.AddEdge(EvidenceEdge{From: nodeID, To: hypothesisID, Relation: "supports", Weight: signal.Confidence, Provenance: string(signal.Kind)})
	return true
}

func sameStringSet(a, b []string) bool {
	aa, bb := normalizedSet(a), normalizedSet(b)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func normalizedSet(in []string) []string {
	m := map[string]struct{}{}
	for _, s := range in {
		if s != "" {
			m[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func mergeRefs(groups ...[]string) []string {
	m := map[string]struct{}{}
	for _, g := range groups {
		for _, ref := range g {
			if ref != "" {
				m[ref] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(m))
	for ref := range m {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}
