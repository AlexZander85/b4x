package detector

import (
	"sort"

	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/observability"
)

// ResolutionFamilySummary aggregates the terminal per-address outcomes of one
// A (ipv4) or AAAA (ipv6) family for a resolution experiment (FB-29). The
// resolved/failed split is always per-address: selecting one working address
// never erases a sibling failure from the report.
type ResolutionFamilySummary struct {
	Family          string   // "ipv4" | "ipv6"
	Resolved        []string // hashes of successfully reached addresses
	Failed          []AddressStageFailure
	SelectedAddress string // hash of the address the experiment last selected
	Total           int
}

// AddressStageFailure keeps the identity and per-protocol trail of one failed
// address so an earlier success elsewhere cannot mask it.
type AddressStageFailure struct {
	IPHash       string
	AddressIndex uint16
	FailureCode  ProbeFailureCode
	Attribution  monitor.FailureAttribution
	Stages       []AddressStageOutcome
}

// MaskedSiblingFailure is a sibling address that failed while an earlier
// address in the same family succeeded. FB-29 requires these to be surfaced,
// never erased, by the aggregation.
type MaskedSiblingFailure struct {
	Family       string
	SelectedHash string
	AddressHash  string
	AddressIndex uint16
	FailureCode  ProbeFailureCode
}

// EvidenceCompleteness carries the readiness flags consumed by the
// ABD_CLIENT_RESOLUTION_READY verdict.
type EvidenceCompleteness struct {
	AllAddressesCovered bool
}

// ResolutionExperimentSummary is the machine-readable aggregation of one
// resolution experiment: per-family outcomes, first-success masking
// detection and per-address evidence completeness.
type ResolutionExperimentSummary struct {
	Experiment       ResolutionExperimentMode
	ClientSnapshotID string
	Families         []ResolutionFamilySummary
	MaskedSiblings   []MaskedSiblingFailure
	MissingEvidence  []string // client answers with no matching per-address outcome
	TotalAnswers     int
	Flags            EvidenceCompleteness
}

// SummarizeResolutionDNS aggregates terminal A/AAAA per-address outcomes for
// one experiment. Every client answer must have a matching per-address
// outcome; a missing outcome makes the evidence incomplete (which blocks
// ABD_CLIENT_RESOLUTION_READY). Sibling failures, including failures masked
// by an earlier success, are always surfaced in MaskedSiblings.
func SummarizeResolutionDNS(exp ResolutionExperimentMode, snapshotID string, clientAnswers []monitor.ResolvedEndpoint, outcomes []DNSAddressOutcome) ResolutionExperimentSummary {
	summary := ResolutionExperimentSummary{Experiment: exp, ClientSnapshotID: snapshotID, TotalAnswers: len(clientAnswers)}
	if len(clientAnswers) == 0 || len(outcomes) == 0 {
		summary.MissingEvidence = addressHashes(clientAnswers)
		return summary
	}
	byHash := map[string]DNSAddressOutcome{}
	for _, o := range outcomes {
		if o.IPHash != "" {
			byHash[o.IPHash] = o
		}
	}
	family := map[string]*ResolutionFamilySummary{}
	firstSuccess := map[string]string{} // family -> first successful address hash
	for _, a := range clientAnswers {
		o, ok := byHash[a.IPHash]
		if !ok {
			summary.MissingEvidence = append(summary.MissingEvidence, a.IPHash)
			continue
		}
		fs := familyGet(family, o.IPFamily)
		fs.Total++
		if o.Success {
			fs.Resolved = append(fs.Resolved, o.IPHash)
			if _, seen := firstSuccess[o.IPFamily]; !seen {
				firstSuccess[o.IPFamily] = o.IPHash
			}
			fs.SelectedAddress = o.IPHash
		} else {
			fs.Failed = append(fs.Failed, AddressStageFailure{
				IPHash:       o.IPHash,
				AddressIndex: o.AddressIndex,
				FailureCode:  o.FailureCode,
				Attribution:  o.Attribution,
				Stages:       append([]AddressStageOutcome(nil), o.StageOutcomes...),
			})
			// A sibling failed while the first address of this family
			// already succeeded: surface it explicitly (first-success
			// masking must never erase it).
			if selected := firstSuccess[o.IPFamily]; selected != "" {
				summary.MaskedSiblings = append(summary.MaskedSiblings, MaskedSiblingFailure{
					Family:       o.IPFamily,
					SelectedHash: selected,
					AddressHash:  o.IPHash,
					AddressIndex: o.AddressIndex,
					FailureCode:  o.FailureCode,
				})
			}
		}
	}
	for _, fs := range family {
		summary.Families = append(summary.Families, *fs)
	}
	sort.Slice(summary.Families, func(i, j int) bool { return summary.Families[i].Family < summary.Families[j].Family })
	sort.Slice(summary.MaskedSiblings, func(i, j int) bool { return summary.MaskedSiblings[i].Family < summary.MaskedSiblings[j].Family })
	summary.MissingEvidence = sortUnique(summary.MissingEvidence)
	summary.Flags.AllAddressesCovered = len(summary.MissingEvidence) == 0
	return summary
}

func familyGet(m map[string]*ResolutionFamilySummary, family string) *ResolutionFamilySummary {
	fs, ok := m[family]
	if !ok {
		fs = &ResolutionFamilySummary{Family: family}
		m[family] = fs
	}
	return fs
}

func sortUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:1]
	for i := 1; i < len(in); i++ {
		if in[i] != in[i-1] {
			out = append(out, in[i])
		}
	}
	return out
}

func addressHashes(answers []monitor.ResolvedEndpoint) []string {
	if len(answers) == 0 {
		return nil
	}
	out := make([]string, 0, len(answers))
	for _, a := range answers {
		out = append(out, a.IPHash)
	}
	return out
}

// ClientReadiness returns the ABD client-resolution readiness verdict for
// this experiment summary: READY only when every client answer has terminal
// per-address evidence. Sibling failures never block readiness by
// themselves — they are actionable evidence and remain visible in
// MaskedSiblings — but missing per-address evidence blocks the verdict
// (FB-29 acceptance).
func (s ResolutionExperimentSummary) ClientReadiness() string {
	if !s.Flags.AllAddressesCovered {
		return "ABD_CLIENT_RESOLUTION_BLOCKED_MISSING_EVIDENCE"
	}
	return "ABD_CLIENT_RESOLUTION_READY"
}

// ErasedByFirstSuccess reports how many sibling failures would have been
// erased if only the first successful address of each family were used for
// the verdict. The aggregation never erases them — it surfaces them in
// MaskedSiblings — but the count is the producer input for the
// monitor_/detector_first_success_erased_address_failures_total
// zero-tolerance counters: a regression that collapses the per-address
// vector to the first success would flip this from 0 to >0 and block
// promotion.
func (s ResolutionExperimentSummary) ErasedByFirstSuccess() int {
	return len(s.MaskedSiblings)
}

// RecordResolutionErasure is the hard-gate producer call site for the
// FB-29 address-erasure counters (owner families mon/abd, zero tolerance).
// It must be invoked whenever a first-success selection is found alongside
// a sibling failure; in the current aggregation this happens in the
// projection path and never erases the sibling — the count inside is what
// the gate watches.
func RecordResolutionErasure(summary ResolutionExperimentSummary, erased int) {
	if erased <= 0 || len(summary.MaskedSiblings) == 0 {
		return
	}
	count := uint64(erased)
	if count > uint64(len(summary.MaskedSiblings)) {
		count = uint64(len(summary.MaskedSiblings))
	}
	observability.Default().Metrics.Inc(observability.MetricMonitorFirstSuccessErasedAddressFailures, map[string]string{"experiment": string(summary.Experiment), "snapshot": summary.ClientSnapshotID}, count)
	observability.Default().Metrics.Inc(observability.MetricDetectorFirstSuccessErasedAddressFailures, map[string]string{"experiment": string(summary.Experiment), "snapshot": summary.ClientSnapshotID}, count)
}
