package detector

import dnspath "github.com/daniellavrushin/b4/transport/dns"

// applyTransportDifferentialEvidence refines transport-level attribution after
// semantic quorum. A UDP timeout/conflict is not called interception merely
// because UDP failed: TCP to the same apparent resolver must itself have
// passed the full correctness+control suite. This is the decisive controlled
// variable in the transparent UDP/53 interception scenario.
func applyTransportDifferentialEvidence(outcomes []dnspath.DNSPathProbeOutcome, paths map[string]dnspath.DNSPathID, stats map[string]verifiedPathStats, attempts int) (annotated []dnspath.DNSPathProbeOutcome, udpInterference, sameResolverConflict bool) {
	if attempts < 1 {
		attempts = 1
	}
	annotated = append([]dnspath.DNSPathProbeOutcome(nil), outcomes...)

	tcpGoodByResolver := map[string]bool{}
	for hash, st := range stats {
		id := paths[hash]
		if id.ResolverID == "" {
			continue
		}
		if id.Family != dnspath.DNSPathTCP && id.Family != dnspath.DNSPathTCPSegmented {
			continue
		}
		if st.CorrectnessPass && st.ControlsPass && st.Pass > 0 && st.Conflicts == 0 && !st.Injection {
			tcpGoodByResolver[id.ResolverID] = true
		}
	}

	for hash, st := range stats {
		id := paths[hash]
		if id.ResolverID == "" || (id.Family != dnspath.DNSPathUDP && id.Family != dnspath.DNSPathSystemForward) {
			continue
		}
		if !tcpGoodByResolver[id.ResolverID] {
			continue
		}
		if st.Timeouts >= attempts && st.Pass == 0 {
			udpInterference = true
		}
		if st.Conflicts >= attempts && st.Pass == 0 {
			sameResolverConflict = true
		}
	}

	if !sameResolverConflict {
		return annotated, udpInterference, false
	}
	for i := range annotated {
		o := &annotated[i]
		if o.PathID.ResolverID == "" || (o.PathID.Family != dnspath.DNSPathUDP && o.PathID.Family != dnspath.DNSPathSystemForward) {
			continue
		}
		if !tcpGoodByResolver[o.PathID.ResolverID] {
			continue
		}
		if o.Class != dnspath.OutcomeAnswerConflict && o.Class != dnspath.OutcomeRCodeMismatch && o.Class != dnspath.OutcomeEarlyInjectionSuspected {
			continue
		}
		o.EvidenceRefs = appendEvidenceRef(o.EvidenceRefs, "same-resolver-tcp-contradiction")
		if o.FailureCode == "" || o.FailureCode == "expected_noerror_rcode" || o.FailureCode == "expected_positive_rcode" {
			o.FailureCode = "udp_tcp_same_resolver_conflict"
		}
	}
	return annotated, udpInterference, true
}

func appendEvidenceRef(refs []string, ref string) []string {
	for _, existing := range refs {
		if existing == ref {
			return refs
		}
	}
	return append(refs, ref)
}

// corroboratedPort53Block requires both UDP and TCP failure for at least one
// resolver identity and no validated classic path, while an encrypted path is
// independently validated. This avoids labelling a single broken endpoint as
// a network-wide port-53 block.
func corroboratedPort53Block(paths map[string]dnspath.DNSPathID, stats map[string]verifiedPathStats, attempts int) bool {
	if attempts < 1 {
		attempts = 1
	}
	type pair struct {
		udpSeen, tcpSeen       bool
		udpBlocked, tcpBlocked bool
	}
	byResolver := map[string]pair{}
	encryptedGood := false
	classicGood := false
	for hash, st := range stats {
		id := paths[hash]
		if id.Family.Encrypted() && st.CorrectnessPass && st.ControlsPass {
			encryptedGood = true
		}
		if id.Family == dnspath.DNSPathUDP || id.Family == dnspath.DNSPathTCP || id.Family == dnspath.DNSPathTCPSegmented || id.Family == dnspath.DNSPathSystemForward {
			if st.CorrectnessPass && st.ControlsPass {
				classicGood = true
			}
		}
		if id.ResolverID == "" {
			continue
		}
		p := byResolver[id.ResolverID]
		switch id.Family {
		case dnspath.DNSPathUDP, dnspath.DNSPathSystemForward:
			p.udpSeen = true
			p.udpBlocked = st.TransportFailures >= attempts && st.Pass == 0 && st.Conflicts == 0 && !st.Injection
		case dnspath.DNSPathTCP, dnspath.DNSPathTCPSegmented:
			p.tcpSeen = true
			p.tcpBlocked = st.TransportFailures >= attempts && st.Pass == 0 && st.Conflicts == 0 && !st.Injection
		}
		byResolver[id.ResolverID] = p
	}
	if !encryptedGood || classicGood {
		return false
	}
	paired := 0
	for _, p := range byResolver {
		if !p.udpSeen || !p.tcpSeen {
			continue
		}
		paired++
		if !p.udpBlocked || !p.tcpBlocked {
			return false
		}
	}
	return paired > 0
}
