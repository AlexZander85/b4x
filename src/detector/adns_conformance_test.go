package detector

import "testing"

func TestCanonicalConformanceSuiteRequiresAllControlledFixtures(t *testing.T) {
	if _, err := CanonicalConformanceSuite("target.example", "same.example", "other.example", ADNSConformanceFixtures{}); err == nil {
		t.Fatal("missing controlled mutation fixtures must fail closed")
	}
}

func TestCanonicalConformanceSuiteIncludesSection54Cases(t *testing.T) {
	suite, err := CanonicalConformanceSuite("target.example", "same.example", "other.example", ADNSConformanceFixtures{
		SERVFAIL: "servfail.fixture",
		Truncation: "large.fixture",
		MultiAnswer: "multi.fixture",
		DNSSECValid: "valid-dnssec.fixture",
		DNSSECBogus: "bogus-dnssec.fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "HTTPS": true, "NXDOMAIN": true,
		"SERVFAIL": true, "TRUNCATION": true, "MULTI": true,
		"DNSSEC_VALID": true, "DNSSEC_BOGUS": true,
		"CONTROL_SAME": true, "CONTROL_UNRELATED": true,
	}
	for _, sc := range suite {
		delete(want, sc.ID)
	}
	if len(want) != 0 {
		t.Fatalf("full §54 conformance suite missing cases: %+v", want)
	}
}
