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

// ValidatePromotionEvidence enforces the evidence half of the promotion
// contract independently of caller-populated PromotionGate booleans. Every
// selected path must have passing, contradiction-free evidence for every
// canonical suite case. A profile with a single successful query is not
// promotable even if it is otherwise well formed and correctly hashed.
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
	for _, out := range p.CandidateOutcomes {
		if out.PathID.Hash() != path.Hash() {
			continue
		}
		if !isCanonicalPromotionCase(out.QuerySuiteID) {
			continue
		}
		if !out.Class.Pass() {
			return fmt.Errorf("path %s has non-passing %s evidence: %s", path.Family, out.QuerySuiteID, out.Class)
		}
		passed[out.QuerySuiteID] = true
	}
	for _, caseID := range canonicalPromotionCases {
		if !passed[caseID] {
			return fmt.Errorf("path %s missing passing %s evidence", path.Family, caseID)
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
