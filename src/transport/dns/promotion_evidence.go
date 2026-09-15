package dnspath

import "fmt"

var canonicalPromotionCases = []string{
	"A",
	"AAAA",
	"CNAME",
	"HTTPS",
	"NXDOMAIN",
	"CONTROL_SAME",
	"CONTROL_UNRELATED",
}

const minRepeatedPromotionAttempts = 2

// ValidatePromotionEvidence enforces the evidence half of the promotion
// contract independently of caller-populated PromotionGate booleans. Every
// selected path must have passing, contradiction-free evidence for every
// canonical suite case. A profile with a single successful query is not
// promotable even if it is otherwise well formed and correctly hashed.
//
// Detector-produced profiles carry non-zero Attempt numbers. For those
// profiles, at least two distinct successful attempts are required for every
// canonical case on every selected path. Attempt==0 is retained only for
// compatibility with internal legacy fixtures that predate attempt receipts;
// runtime detector output never uses that representation.
func ValidatePromotionEvidence(p *DNSPathProfile) error {
	if p == nil {
		return fmt.Errorf("profile required")
	}
	selected := make([]DNSPathID, 0, 1+len(p.Fallbacks))
	selected = append(selected, p.Primary)
	selected = append(selected, p.Fallbacks...)
	for _, path := range selected {
		if err := validatePathPromotionEvidence(p, path); err != nil {
			return err
		}
	}
	return nil
}

func validatePathPromotionEvidence(p *DNSPathProfile, path DNSPathID) error {
	passed := map[string]bool{}
	attempts := map[string]map[uint16]bool{}
	hasReceiptAttempts := false

	for _, out := range p.CandidateOutcomes {
		if out.PathID.Hash() != path.Hash() || !isCanonicalPromotionCase(out.QuerySuiteID) {
			continue
		}
		// Any contradictory/non-passing receipt for a canonical case blocks
		// promotion. We do not allow a later PASS to erase a failed attempt.
		if !out.Class.Pass() {
			return fmt.Errorf("path %s has non-passing %s evidence: %s", path.Family, out.QuerySuiteID, out.Class)
		}
		passed[out.QuerySuiteID] = true
		if out.Attempt != 0 {
			hasReceiptAttempts = true
			if attempts[out.QuerySuiteID] == nil {
				attempts[out.QuerySuiteID] = map[uint16]bool{}
			}
			attempts[out.QuerySuiteID][out.Attempt] = true
		}
	}

	for _, caseID := range canonicalPromotionCases {
		if !passed[caseID] {
			return fmt.Errorf("path %s missing passing %s evidence", path.Family, caseID)
		}
		if hasReceiptAttempts && len(attempts[caseID]) < minRepeatedPromotionAttempts {
			return fmt.Errorf("path %s has only %d distinct %s attempts; need at least %d", path.Family, len(attempts[caseID]), caseID, minRepeatedPromotionAttempts)
		}
	}
	return nil
}

func isCanonicalPromotionCase(caseID string) bool {
	for _, required := range canonicalPromotionCases {
		if caseID == required {
			return true
		}
	}
	return false
}
