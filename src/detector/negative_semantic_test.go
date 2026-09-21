package detector

import (
	"testing"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

func TestNegativeSemanticGroupsNXDOMAINAndNODATA(t *testing.T) {
	nx := dnspath.DNSPathProbeOutcome{RCode: 3, EvidenceRefs: []string{"authority-soa"}}
	nodata := dnspath.DNSPathProbeOutcome{RCode: 0, EvidenceRefs: []string{"authority-soa"}}
	if semanticOutcomeSignature(nx, "NXDOMAIN") != semanticOutcomeSignature(nodata, "NXDOMAIN") {
		t.Fatalf("proved NXDOMAIN and NODATA must share one semantic: %q vs %q",
			semanticOutcomeSignature(nx, "NXDOMAIN"), semanticOutcomeSignature(nodata, "NXDOMAIN"))
	}
	bare := dnspath.DNSPathProbeOutcome{RCode: 3}
	if semanticOutcomeSignature(bare, "NXDOMAIN") == semanticOutcomeSignature(nx, "NXDOMAIN") {
		t.Fatal("a bare negative without SOA proof must be distinguished from a proved one")
	}
}
