package detector

import (
	"fmt"
	"sort"
	"strings"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

type verifiedPathStats struct {
	Pass            int
	Fail            int
	Latency         time.Duration
	LatencyN        int
	Timeouts        int
	Conflicts       int
	Injection       bool
	MidHandshake    bool
	CorrectnessPass bool
	ControlsPass    bool
}

// verifyADNSOutcomes upgrades only independently corroborated, repeatable
// observations to PASS_CORRECT. Providers are intentionally not allowed to
// make this decision by themselves.
func verifyADNSOutcomes(outcomes []dnspath.DNSPathProbeOutcome, suite []ADNSSuiteCase, attempts int) ([]dnspath.DNSPathProbeOutcome, map[string]verifiedPathStats) {
	if attempts < 1 {
		attempts = 1
	}
	verified := append([]dnspath.DNSPathProbeOutcome(nil), outcomes...)

	type pathCase struct {
		path string
		caseID string
	}
	indices := map[pathCase][]int{}
	for i := range verified {
		key := pathCase{path: verified[i].PathID.Hash(), caseID: verified[i].QuerySuiteID}
		indices[key] = append(indices[key], i)
	}

	// First require repeatability inside each path/case. A path that returns
	// different answers across its own attempts cannot become reference truth.
	stableSig := map[pathCase]string{}
	for key, idxs := range indices {
		var sig string
		valid := 0
		stable := true
		for _, idx := range idxs {
			o := verified[idx]
			if o.Class != dnspath.OutcomeInconclusive {
				continue
			}
			s := outcomeSignature(o, isControlCase(key.caseID))
			if sig == "" {
				sig = s
			} else if sig != s {
				stable = false
			}
			valid++
		}
		if valid >= attempts && stable && sig != "" {
			stableSig[key] = sig
			continue
		}
		if valid > 0 && !stable {
			for _, idx := range idxs {
				if verified[idx].Class == dnspath.OutcomeInconclusive {
					verified[idx].Class = dnspath.OutcomeAnswerConflict
					verified[idx].FailureCode = "unstable_repeated_answer"
				}
			}
		}
	}

	// For each suite case, choose a unique signature supported by at least two
	// independent resolver identities. Same resolver over UDP/TCP is useful
	// differential evidence, but it is not two independent truth sources.
	caseIDs := make([]string, 0, len(suite))
	seenCase := map[string]bool{}
	for _, sc := range suite {
		if !seenCase[sc.ID] {
			seenCase[sc.ID] = true
			caseIDs = append(caseIDs, sc.ID)
		}
	}
	for _, caseID := range caseIDs {
		groupsBySig := map[string]map[string]bool{}
		for key, sig := range stableSig {
			if key.caseID != caseID {
				continue
			}
			var resolver string
			for _, idx := range indices[key] {
				resolver = verified[idx].PathID.ResolverID
				if resolver != "" {
					break
				}
			}
			if resolver == "" {
				continue
			}
			if groupsBySig[sig] == nil {
				groupsBySig[sig] = map[string]bool{}
			}
			groupsBySig[sig][resolver] = true
		}
		winner, winnerCount, tied := "", 0, false
		for sig, groups := range groupsBySig {
			count := len(groups)
			if count > winnerCount {
				winner, winnerCount, tied = sig, count, false
			} else if count == winnerCount && count > 0 {
				tied = true
			}
		}
		if winnerCount < 2 || tied {
			continue
		}
		for key, sig := range stableSig {
			if key.caseID != caseID {
				continue
			}
			for _, idx := range indices[key] {
				if verified[idx].Class != dnspath.OutcomeInconclusive {
					continue
				}
				if sig == winner {
					verified[idx].Class = dnspath.OutcomePassCorrect
					verified[idx].Stage = dnspath.StageControl
					verified[idx].EvidenceRefs = append(verified[idx].EvidenceRefs, "independent-quorum")
				} else {
					verified[idx].Class = dnspath.OutcomeAnswerConflict
					verified[idx].FailureCode = "independent_reference_conflict"
				}
			}
		}
	}

	stats := map[string]verifiedPathStats{}
	for _, o := range verified {
		h := o.PathID.Hash()
		st := stats[h]
		switch {
		case o.Class.Pass():
			st.Pass++
			st.Latency += o.Latency
			st.LatencyN++
		case o.Class == dnspath.OutcomeTimeout:
			st.Timeouts++
			st.Fail++
		case o.Class == dnspath.OutcomeAnswerConflict || o.Class == dnspath.OutcomeRCodeMismatch:
			st.Conflicts++
			st.Fail++
		case o.Class == dnspath.OutcomeEarlyInjectionSuspected:
			st.Injection = true
			st.Fail++
		case o.Class == dnspath.OutcomeTLSMidHandshakeReset:
			st.MidHandshake = true
			st.Fail++
		default:
			st.Fail++
		}
		stats[h] = st
	}

	for hash, st := range stats {
		pathOutcomes := make([]dnspath.DNSPathProbeOutcome, 0)
		for _, o := range verified {
			if o.PathID.Hash() == hash {
				pathOutcomes = append(pathOutcomes, o)
			}
		st.ControlsPass = suiteCasesPass(pathOutcomes, suite, attempts, true)
		st.CorrectnessPass = suiteCasesPass(pathOutcomes, suite, attempts, false)
		stats[hash] = st
	}
	return verified, stats
}

func suiteCasesPass(outcomes []dnspath.DNSPathProbeOutcome, suite []ADNSSuiteCase, attempts int, controls bool) bool {
	required := map[string]bool{}
	for _, sc := range suite {
		if isControlCase(sc.ID) == controls {
			required[sc.ID] = true
		}
	}
	if len(required) == 0 {
		return false
	}
	counts := map[string]int{}
	for _, o := range outcomes {
		if required[o.QuerySuiteID] && o.Class.Pass() {
			counts[o.QuerySuiteID]++
		}
	}
	for id := range required {
		if counts[id] < attempts {
			return false
		}
	}
	return true
}

func isControlCase(id string) bool {
	return id == "CONTROL_SAME" || id == "CONTROL_UNRELATED"
}

func outcomeSignature(o dnspath.DNSPathProbeOutcome, coarse bool) string {
	negativeProof := false
	for _, ref := range o.EvidenceRefs {
		if ref == "authority-soa" {
			negativeProof = true
			break
		}
	}
	if coarse {
		positiveEvidence := o.AnswerFingerprint != "" || o.CNAMEFingerprint != "" || o.HTTPSFingerprint != ""
		return fmt.Sprintf("r=%d|p=%t|neg=%t", o.RCode, positiveEvidence, negativeProof)
	}
	return fmt.Sprintf("r=%d|a=%s|c=%s|h=%s|neg=%t",
		o.RCode, o.AnswerFingerprint, o.CNAMEFingerprint, o.HTTPSFingerprint, negativeProof)
}

func classifyDiagnosisFlags(outcomes []dnspath.DNSPathProbeOutcome, paths map[string]dnspath.DNSPathID, stats map[string]verifiedPathStats, attempts int) (poisoning, injection, udpDrop, port53Blocked, encryptedBlocked bool, filtered []dnspath.DNSPathFamily) {
	if attempts < 1 {
		attempts = 1
	}
	classicFailures := 0
	classicPaths := 0
	encryptedPass := false
	classicPass := false
	filteredSet := map[dnspath.DNSPathFamily]bool{}

	for hash, st := range stats {
		id := paths[hash]
		if st.Injection {
			injection = true
		}
		if st.Conflicts >= attempts {
			poisoning = true
		}
		if id.Family == dnspath.DNSPathUDP || id.Family == dnspath.DNSPathSystemForward {
			if st.Timeouts >= attempts {
				udpDrop = true
			}
		}
		if id.Family == dnspath.DNSPathUDP || id.Family == dnspath.DNSPathTCP || id.Family == dnspath.DNSPathTCPSegmented || id.Family == dnspath.DNSPathSystemForward {
			classicPaths++
			if st.CorrectnessPass && st.ControlsPass {
				classicPass = true
			} else if st.Timeouts+st.Conflicts >= attempts || st.Fail >= attempts {
				classicFailures++
			}
		}
		if id.Family.Encrypted() && st.CorrectnessPass && st.ControlsPass {
			encryptedPass = true
		}
		if st.MidHandshake && id.Family.Encrypted() {
			filteredSet[id.Family] = true
		}
	}
	port53Blocked = classicPaths > 0 && classicFailures == classicPaths && encryptedPass
	for _, o := range outcomes {
		if !o.PathID.Family.Encrypted() {
			continue
		}
		switch o.Class {
		case dnspath.OutcomeTLSMidHandshakeReset, dnspath.OutcomeTLSAlert, dnspath.OutcomeTLSCertFailure, dnspath.OutcomeHTTPStatusFailure, dnspath.OutcomeQUICUnavailable:
			encryptedBlocked = encryptedBlocked || classicPass
		}
	}
	for family := range filteredSet {
		filtered = append(filtered, family)
	}
	sort.Slice(filtered, func(i, j int) bool { return strings.Compare(string(filtered[i]), string(filtered[j])) < 0 })
	return
}
