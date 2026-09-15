package detector

import (
	"fmt"
	"strings"
)

// ADNSConformanceFixtures are controlled names used only for lab/field
// conformance checks. Public resolver targets must not be guessed for
// SERVFAIL/truncation/DNSSEC mutation claims because those semantics require
// an authoritative fixture owned by the test environment.
type ADNSConformanceFixtures struct {
	SERVFAIL    string
	Truncation  string
	MultiAnswer string
	DNSSECValid string
	DNSSECBogus string
}

// CanonicalConformanceSuite returns the full §54 suite when the caller has
// supplied every controlled fixture. It intentionally fails rather than
// silently dropping mutation/error cases; production diagnosis may keep using
// CanonicalSuiteWithControls until such reviewed fixtures are provisioned.
func CanonicalConformanceSuite(target, sameServiceControl, unrelatedControl string, f ADNSConformanceFixtures) ([]ADNSSuiteCase, error) {
	missing := make([]string, 0)
	for name, value := range map[string]string{
		"SERVFAIL": f.SERVFAIL,
		"TRUNCATION": f.Truncation,
		"MULTI": f.MultiAnswer,
		"DNSSEC_VALID": f.DNSSECValid,
		"DNSSEC_BOGUS": f.DNSSECBogus,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		return nil, fmt.Errorf("ADNS conformance fixtures incomplete: %s", strings.Join(missing, ","))
	}
	base := CanonicalSuiteWithControls(target, sameServiceControl, unrelatedControl)
	base = append(base,
		ADNSSuiteCase{ID: "SERVFAIL", Name: f.SERVFAIL, QType: 1},
		ADNSSuiteCase{ID: "TRUNCATION", Name: f.Truncation, QType: 1},
		ADNSSuiteCase{ID: "MULTI", Name: f.MultiAnswer, QType: 1},
		ADNSSuiteCase{ID: "DNSSEC_VALID", Name: f.DNSSECValid, QType: 1},
		ADNSSuiteCase{ID: "DNSSEC_BOGUS", Name: f.DNSSECBogus, QType: 1},
	)
	return base, nil
}
