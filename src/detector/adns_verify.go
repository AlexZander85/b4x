package detector

import (
	"fmt"
	"sort"
	"strings"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

type verifiedPathStats struct {
	Pass              int
	Fail              int
	Latency           time.Duration
	LatencyN          int
	Timeouts          int
	TransportFailures int
	Conflicts         int
	Injection         bool
	MidHandshake      bool
	CorrectnessPass   bool
	ControlsPass      bool
}

type adnsPathCase struct {
	path   string
	caseID string
}

// verifyADNSOutcomes upgrades only independently corroborated, repeatable
// observations to PASS_CORRECT/PASS_DIFFERENT_BUT_VALID. Providers prove
// transport/message validity; correctness remains a differential decision.
//
// Exact answer equality is intentionally not required across independent
// resolvers: legitimate CDN/geographic rotation may return different address
// sets. We require the same semantic answer class from at least two resolver
// identities. Exact fingerprint agreement earns PASS_CORRECT; semantic
// agreement with a different fingerprint earns PASS_DIFFERENT_BUT_VALID.
func verifyADNSOutcomes(outcomes []dnspath.DNSPathProbeOutcome, suite []ADNSSuiteCase, attempts int) ([]dnspath.DNSPathProbeOutcome, map[string]verifiedPathStats) {
	if attempts < 1 {
		attempts = 1
	}
	verified := append([]dnspath.DNSPathProbeOutcome(nil), outcomes...)
	indices := map[adnsPathCase][]int{}
	for i := range verified {
		key := adnsPathCase{path: verified[i].PathID.Hash(), caseID: verified[i].QuerySuiteID}
		indices[key] = append(indices[key], i)
	}

	// First require repeatability of the semantic result inside one path/case.
	// Exact address changes across attempts are allowed for positive CDN answers
	// as long as the semantic result remains positive and structurally valid.
	stableSemantic := map[adnsPathCase]string{}
	stableExact := map[adnsPathCase]string{}
	for key, idxs := range indices {
		semantic := ""
		exact := ""
		valid := 0
		semanticStable := true
		exactStable := true
		for _, idx := range idxs {
			o := verified[idx]
			if o.Class != dnspath.OutcomeInconclusive {
				continue
			}
			s := semanticOutcomeSignature(o, key.caseID)
			e := exactOutcomeSignature(o)
			if semantic == "" {
				semantic = s
			} else if semantic != s {
				semanticStable = false
			}
			if exact == "" {
				exact = e
			} else if exact != e {
				exactStable = false
			}
			valid++
		}
		if valid >= attempts && semanticStable && semantic != "" {
			stableSemantic[key] = semantic
			if exactStable {
				stableExact[key] = exact
			}
			continue
		}
		if valid > 0 && !semanticStable {
			for _, idx := range idxs {
				if verified[idx].Class == dnspath.OutcomeInconclusive {
					verified[idx].Class = dnspath.OutcomeAnswerConflict
					verified[idx].FailureCode = "unstable_semantic_answer"
				}
			}
		}
	}

	caseIDs := make([]string, 0, len(suite))
	seenCase := map[string]bool{}
	for _, sc := range suite {
		if !seenCase[sc.ID] {
			seenCase[sc.ID] = true
			caseIDs = append(caseIDs, sc.ID)
		}
	}

	for _, caseID := range caseIDs {
		// Resolver identities, not transport paths, form the independent quorum.
		groupsBySemantic := map[string]map[string]bool{}
		exactGroups := map[string]map[string]bool{}
		for key, semantic := range stableSemantic {
			if key.caseID != caseID {
				continue
			}
			resolver := resolverForPathCase(verified, indices[key])
			if resolver == "" {
				continue
			}
			if groupsBySemantic[semantic] == nil {
				groupsBySemantic[semantic] = map[string]bool{}
			}
			groupsBySemantic[semantic][resolver] = true
			if exact, ok := stableExact[key]; ok {
				if exactGroups[exact] == nil {
					exactGroups[exact] = map[string]bool{}
				}
				exactGroups[exact][resolver] = true
			}
		}

		winner, winnerCount, tied := "", 0, false
		for semantic, groups := range groupsBySemantic {
			count := len(groups)
			if count > winnerCount {
				winner, winnerCount, tied = semantic, count, false
			} else if count == winnerCount && count > 0 {
				tied = true
			}
		}
		if winnerCount < 2 || tied {
			continue
		}

		for key, semantic := range stableSemantic {
			if key.caseID != caseID {
				continue
			}
			for _, idx := range indices[key] {
				if verified[idx].Class != dnspath.OutcomeInconclusive {
					continue
				}
				if semantic != winner {
					verified[idx].Class = dnspath.OutcomeAnswerConflict
					verified[idx].FailureCode = "independent_reference_conflict"
					continue
				}
				verified[idx].Stage = dnspath.StageControl
				verified[idx].EvidenceRefs = append(verified[idx].EvidenceRefs, "independent-quorum")
				exact := exactOutcomeSignature(verified[idx])
				if len(exactGroups[exact]) >= 2 {
					verified[idx].Class = dnspath.OutcomePassCorrect
				} else {
					verified[idx].Class = dnspath.OutcomePassDifferentButValid
					verified[idx].EvidenceRefs = append(verified[idx].EvidenceRefs, "cdn-answer-diversity")
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
			st.TransportFailures++
			st.Fail++
		case o.Class == dnspath.OutcomeConnectionRefused:
			st.TransportFailures++
			st.Fail++
		case o.Class == dnspath.OutcomeAnswerConflict || o.Class == dnspath.OutcomeRCodeMismatch:
			st.Conflicts++
			st.Fail++
		case o.Class == dnspath.OutcomeEarlyInjectionSuspected:
			st.Injection = true
			st.Fail++
		case o.Class == dnspath.OutcomeTLSMidHandshakeReset:
			st.MidHandshake = true
			st.TransportFailures++
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
		}
		st.ControlsPass = suiteCasesPass(pathOutcomes, suite, attempts, true)
		st.CorrectnessPass = suiteCasesPass(pathOutcomes, suite, attempts, false)
		stats[hash] = st
	}
	return verified, stats
}

func resolverForPathCase(outcomes []dnspath.DNSPathProbeOutcome, idxs []int) string {
	for _, idx := range idxs {
		if idx >= 0 && idx < len(outcomes) && outcomes[idx].PathID.ResolverID != "" {
			return outcomes[idx].PathID.ResolverID
		}
	}
	return ""
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

func semanticOutcomeSignature(o dnspath.DNSPathProbeOutcome, caseID string) string {
	negativeProof := hasEvidenceRef(o, "authority-soa")
	switch strings.ToUpper(caseID) {
	case "NXDOMAIN":
		return fmt.Sprintf("nxdomain|r=%d|soa=%t", o.RCode, negativeProof)
	case "CNAME":
		return fmt.Sprintf("positive-cname|r=%d|present=%t", o.RCode, o.CNAMEFingerprint != "")
	case "HTTPS":
		return fmt.Sprintf("positive-https|r=%d|present=%t", o.RCode, o.HTTPSFingerprint != "")
	default:
		positive := o.AnswerFingerprint != "" || o.CNAMEFingerprint != "" || o.HTTPSFingerprint != ""
		return fmt.Sprintf("positive|r=%d|present=%t", o.RCode, positive)
	}
}

func exactOutcomeSignature(o dnspath.DNSPathProbeOutcome) string {
	return fmt.Sprintf("r=%d|a=%s|c=%s|h=%s|neg=%t",
		o.RCode, o.AnswerFingerprint, o.CNAMEFingerprint, o.HTTPSFingerprint, hasEvidenceRef(o, "authority-soa"))
}

func hasEvidenceRef(o dnspath.DNSPathProbeOutcome, want string) bool {
	for _, ref := range o.EvidenceRefs {
		if ref == want {
			return true
		}
	}
	return false
}

func classifyDiagnosisFlags(outcomes []dnspath.DNSPathProbeOutcome, paths map[string]dnspath.DNSPathID, stats map[string]verifiedPathStats, attempts int) (poisoning, injection, udpDrop, port53Blocked, encryptedBlocked bool, filtered []dnspath.DNSPathFamily) {
	if attempts < 1 {
		attempts = 1
	}
	classicBlocked := 0
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
			if st.Timeouts >= attempts && st.Pass == 0 {
				udpDrop = true
			}
		}
		if id.Family == dnspath.DNSPathUDP || id.Family == dnspath.DNSPathTCP || id.Family == dnspath.DNSPathTCPSegmented || id.Family == dnspath.DNSPathSystemForward {
			classicPaths++
			if st.CorrectnessPass && st.ControlsPass {
				classicPass = true
			}
			if st.TransportFailures >= attempts && st.Pass == 0 && st.Conflicts == 0 && !st.Injection {
				classicBlocked++
			}
		}
		if id.Family.Encrypted() && st.CorrectnessPass && st.ControlsPass {
			encryptedPass = true
		}
		if st.MidHandshake && id.Family.Encrypted() {
			filteredSet[id.Family] = true
		}
	}
	port53Blocked = classicPaths > 0 && classicBlocked == classicPaths && encryptedPass
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
