package dnspath

// cloneDNSPathProfile returns a deep copy suitable for crossing the Manager
// ownership boundary. Profiles are evidence receipts; callers must never be
// able to mutate an adopted profile through a retained pointer.
func cloneDNSPathProfile(in *DNSPathProfile) *DNSPathProfile {
	if in == nil {
		return nil
	}
	out := *in
	out.Fallbacks = append([]DNSPathID(nil), in.Fallbacks...)
	out.Excluded = make([]DNSPathExclusion, len(in.Excluded))
	for i := range in.Excluded {
		out.Excluded[i] = in.Excluded[i]
		out.Excluded[i].EvidenceRefs = append([]string(nil), in.Excluded[i].EvidenceRefs...)
	}
	out.CandidateOutcomes = make([]DNSPathProbeOutcome, len(in.CandidateOutcomes))
	for i := range in.CandidateOutcomes {
		out.CandidateOutcomes[i] = in.CandidateOutcomes[i]
		out.CandidateOutcomes[i].EvidenceRefs = append([]string(nil), in.CandidateOutcomes[i].EvidenceRefs...)
	}
	return &out
}

func cloneDNSPathBinding(in *DNSPathBinding) *DNSPathBinding {
	if in == nil {
		return nil
	}
	out := *in
	out.Fallbacks = append([]DNSPathID(nil), in.Fallbacks...)
	return &out
}
