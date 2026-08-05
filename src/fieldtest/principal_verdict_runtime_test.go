package fieldtest

import (
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/validation"
)

// FB-34.1 (b4x-ewc): every verdict name emitted by this package's runtime
// must be a registered principal verdict (canonical or alias). The names are
// referenced through package symbols, so a mutation of any verdict string
// constant or release-gate map key in the source fails this test — the
// runtime can never drift from the registry silently.
func TestPrincipalVerdictRuntimeNamesRegistered(t *testing.T) {
	var names []string

	// Detector field verdicts (detector_field.go).
	for _, v := range []DetectorFieldVerdict{
		ABDTargetPlanReady, ABDCleanBaselineReady, ABDDNSEvidenceReady,
		ABDTLSEvidenceReady, ABDQUICEvidenceReady, ABDL4Ready,
		ABDDynamicReady, ABDEvidenceGraphReady, ABDBlockingProfileReady,
	} {
		names = append(names, string(v))
	}

	// Promotion gate verdicts (promotion.go). PromotionBlocked is a registry
	// verdict name; PromotionPass/PromotionFail ("PASS"/"FAIL") are internal
	// result codes, not verdict names, and are never emitted as names.
	names = append(names, string(PromotionBlocked))

	// WARP causal trace release (cleanup.go).
	names = append(names, WARPTraceReady)

	// Detector release gate map keys (release_detector.go) — every key is
	// emitted regardless of gate state, so the empty gate still enumerates
	// the full key set.
	for k := range (DetectorReleaseGate{}).Verdicts() {
		names = append(names, k)
	}

	if missing := validation.VerifyPrincipalVerdictNames(names); len(missing) != 0 {
		t.Fatalf("fieldtest runtime verdict names not registered in principal verdict registry (FB-34.1):\n%s",
			strings.Join(missing, "\n"))
	}
}
