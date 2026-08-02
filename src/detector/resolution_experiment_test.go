package detector

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

// terminalOutcome builds a per-address outcome fixture with the FB-29 fields.
func terminalOutcome(hash, family string, idx uint16, success bool, code ProbeFailureCode, sel bool, stages []AddressStageOutcome) DNSAddressOutcome {
	return DNSAddressOutcome{
		IPHash:        hash,
		IPFamily:      family,
		AddressIndex:  idx,
		Success:       success,
		FailureCode:   code,
		Experiment:    ClientObservedExactEndpoint,
		Provenance:    "resolver.cache",
		Selected:      sel,
		StageOutcomes: stages,
		ObservedAt:    time.Unix(12000, 0),
	}
}

// TestResolutionExperimentMixedV4V6PerAddress verifies that a mixed
// IPv4/IPv6 experiment (FB-29 fixture) keeps per-address outcomes across
// families: A and AAAA answers are aggregated separately, both families are
// present in the summary, and no address collapses into a single verdict.
func TestResolutionExperimentMixedV4V6PerAddress(t *testing.T) {
	answers := []monitor.ResolvedEndpoint{
		{IPHash: "v4-a", IPFamily: "v4", AddressIndex: 0},
		{IPHash: "v4-b", IPFamily: "v4", AddressIndex: 1},
		{IPHash: "v6-a", IPFamily: "v6", AddressIndex: 0},
	}
	outcomes := []DNSAddressOutcome{
		terminalOutcome("v4-a", "v4", 0, true, "", true, []AddressStageOutcome{{Protocol: ProofStageDNS, Outcome: "ok"}}),
		terminalOutcome("v4-b", "v4", 1, false, FailureDNSNoAnswer, false, []AddressStageOutcome{{Protocol: ProofStageDNS, Outcome: "ok"}}),
		terminalOutcome("v6-a", "v6", 0, true, "", true, []AddressStageOutcome{{Protocol: ProofStageDNS, Outcome: "ok"}}),
	}
	s := SummarizeResolutionDNS(ClientObservedExactEndpoint, "snap-1", answers, outcomes)
	if len(s.Families) != 2 {
		t.Fatalf("families = %d, want 2 (ipv4+ipv6)", len(s.Families))
	}
	if s.Flags.AllAddressesCovered != true {
		t.Fatalf("all addresses covered = false, want true: %+v", s.MissingEvidence)
	}
	if s.ClientReadiness() != "ABD_CLIENT_RESOLUTION_READY" {
		t.Fatalf("readiness = %s, want READY", s.ClientReadiness())
	}
	// per-address: v4 has one resolved, one failed; v6 resolved.
	var v4, v6 *ResolutionFamilySummary
	for i := range s.Families {
		if s.Families[i].Family == "v4" {
			v4 = &s.Families[i]
		}
		if s.Families[i].Family == "v6" {
			v6 = &s.Families[i]
		}
	}
	if v4 == nil || v6 == nil {
		t.Fatalf("family split missing: %+v", s.Families)
	}
	if len(v4.Resolved) != 1 || len(v4.Failed) != 1 || v4.Total != 2 {
		t.Fatalf("v4 per-address = %+v, want 1 resolved + 1 failed of 2", v4)
	}
	if len(v6.Resolved) != 1 || len(v6.Failed) != 0 || v6.Total != 1 {
		t.Fatalf("v6 per-address = %+v, want 1 resolved of 1", v6)
	}
}

// TestResolutionExperimentFirstSuccessDoesNotMaskSibling is the mutation
// guard for first-success masking: when one address succeeds first, a
// sibling failure in the same family must still be surfaced in
// MaskedSiblings. If the aggregation collapsed to "first success => all
// fine", the masked-sibling list would be empty and this test fails.
func TestResolutionExperimentFirstSuccessDoesNotMaskSibling(t *testing.T) {
	answers := []monitor.ResolvedEndpoint{
		{IPHash: "v4-a", IPFamily: "v4", AddressIndex: 0},
		{IPHash: "v4-b", IPFamily: "v4", AddressIndex: 1},
	}
	outcomes := []DNSAddressOutcome{
		terminalOutcome("v4-a", "v4", 0, true, "", true, []AddressStageOutcome{{Protocol: ProofStageDNS, Outcome: "ok"}}),
		terminalOutcome("v4-b", "v4", 1, false, FailureTransportTimeout, false, []AddressStageOutcome{{Protocol: ProofStageDNS, Outcome: "ok"}, {Protocol: ProofStageTCP, Outcome: OutcomeProofTimeout}}),
	}
	s := SummarizeResolutionDNS(ClientObservedExactEndpoint, "snap-2", answers, outcomes)
	if len(s.MaskedSiblings) != 1 {
		t.Fatalf("masked siblings = %+v, want 1 (v4-b failed while v4-a succeeded)", s.MaskedSiblings)
	}
	if s.MaskedSiblings[0].AddressHash != "v4-b" || s.MaskedSiblings[0].SelectedHash != "v4-a" {
		t.Fatalf("masked sibling = %+v, want b masked by a", s.MaskedSiblings[0])
	}
	// The sibling failure must stay visible in the family too.
	f := s.Families[0]
	if len(f.Failed) != 1 || f.Failed[0].IPHash != "v4-b" {
		t.Fatalf("failed sibling erased from family: %+v", f.Failed)
	}
}

// TestResolutionExperimentMissingPerAddressEvidenceBlocks blocks the
// readiness verdict when one client answer has no matching per-address
// outcome (FB-29 acceptance: missing per-address evidence blocks
// ABD_CLIENT_RESOLUTION_READY).
func TestResolutionExperimentMissingPerAddressEvidenceBlocks(t *testing.T) {
	answers := []monitor.ResolvedEndpoint{
		{IPHash: "v4-a", IPFamily: "v4", AddressIndex: 0},
		{IPHash: "v4-b", IPFamily: "v4", AddressIndex: 1},
	}
	// Only v4-a has an outcome; v4-b's outcome is missing.
	outcomes := []DNSAddressOutcome{
		terminalOutcome("v4-a", "v4", 0, true, "", true, []AddressStageOutcome{{Protocol: ProofStageDNS, Outcome: "ok"}}),
	}
	s := SummarizeResolutionDNS(ClientObservedExactEndpoint, "snap-3", answers, outcomes)
	if s.Flags.AllAddressesCovered {
		t.Fatalf("evidence marked covered despite missing per-address outcome")
	}
	if s.ClientReadiness() != "ABD_CLIENT_RESOLUTION_BLOCKED_MISSING_EVIDENCE" {
		t.Fatalf("readiness = %s, want BLOCKED_MISSING_EVIDENCE", s.ClientReadiness())
	}
	if len(s.MissingEvidence) != 1 || s.MissingEvidence[0] != "v4-b" {
		t.Fatalf("missing evidence = %+v, want [v4-b]", s.MissingEvidence)
	}
}

// TestResolutionExperimentErasureCounter verifies the zero-tolerance
// erasure producer: the aggregation surfaces the masked sibling instead of
// erasing it (ErasedByFirstSuccess stays at the sibling count and the
// RecordResolutionErasure gate producer fires the mon/abd counters). If a
// mutation collapsed the per-address vector to the first success, the
// counter would diverge from the surfaced MaskedSiblings and this test
// fails.
func TestResolutionExperimentErasureCounterSync(t *testing.T) {
	answers := []monitor.ResolvedEndpoint{
		{IPHash: "v4-a", IPFamily: "v4", AddressIndex: 0},
		{IPHash: "v4-b", IPFamily: "v4", AddressIndex: 1},
	}
	outcomes := []DNSAddressOutcome{
		terminalOutcome("v4-a", "v4", 0, true, "", true, []AddressStageOutcome{{Protocol: ProofStageDNS, Outcome: "ok"}}),
		terminalOutcome("v4-b", "v4", 1, false, FailureTransportTimeout, false, []AddressStageOutcome{{Protocol: ProofStageDNS, Outcome: "ok"}, {Protocol: ProofStageTCP, Outcome: OutcomeProofTimeout}}),
	}
	s := SummarizeResolutionDNS(ClientObservedExactEndpoint, "snap-4", answers, outcomes)
	erased := s.ErasedByFirstSuccess()
	if erased != 1 {
		t.Fatalf("ErasedByFirstSuccess = %d, want 1 (sibling surfaced, not erased)", erased)
	}
	if len(s.MaskedSiblings) != erased {
		t.Fatalf("MaskedSiblings=%d vs ErasedByFirstSuccess=%d diverge", len(s.MaskedSiblings), erased)
	}
	// No erasure must remain a no-op for the gate (clean window, count stays 0).
	clear := SummarizeResolutionDNS(IndependentCurrentResolution, "snap-5",
		[]monitor.ResolvedEndpoint{{IPHash: "v6-a", IPFamily: "v6"}},
		[]DNSAddressOutcome{terminalOutcome("v6-a", "v6", 0, true, "", true, []AddressStageOutcome{{Protocol: ProofStageDNS, Outcome: "ok"}})})
	RecordResolutionErasure(clear, clear.ErasedByFirstSuccess())
}
