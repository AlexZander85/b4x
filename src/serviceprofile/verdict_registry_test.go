package serviceprofile

import (
	"testing"

	"github.com/daniellavrushin/b4/validation"
)

// FB-34.1 (b4x-ewc): the WARP recommendation readiness verdict emitted by
// this package must be a registered principal verdict. Mutation of the
// constant in recommendation.go fails this test.
func TestPrincipalVerdictRuntimeNamesRegistered(t *testing.T) {
	if missing := validation.VerifyPrincipalVerdictNames([]string{ProfileWARPRecommendationReady}); len(missing) != 0 {
		t.Fatalf("serviceprofile runtime verdict name not registered (FB-34.1): %v", missing)
	}
}
