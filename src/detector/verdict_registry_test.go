package detector

import (
	"testing"

	"github.com/daniellavrushin/b4/validation"
)

// FB-34.1 (b4x-ewc): the READY verdicts emitted by detector release gates
// must be registered principal verdicts. Mutation of a verdict string in the
// producer fails this test, so runtime can never drift from the registry.
//
// ABD_FIELD_VALIDATION_PENDING and
// ABD_CLIENT_RESOLUTION_BLOCKED_MISSING_EVIDENCE are deliberately excluded:
// they are diagnostic status strings ("not yet ready"), not principal
// verdicts, and carry no normative source in the registry.
func TestPrincipalVerdictRuntimeNamesRegistered(t *testing.T) {
	ready := ABDReleaseGate{
		DetectorTestsPassed: true, MonitorAdapterReady: true,
		ClientResolutionReady: true, MultiVantageReady: true,
		CapacitySafe: true, ExternalRouterValidated: true,
		AndroidValidated: true, PrivacyValidated: true,
		DirectApplyDisabled: true,
	}
	names := []string{
		ready.Verdict(),
		(ResolutionExperimentSummary{Flags: EvidenceCompleteness{AllAddressesCovered: true}}).ClientReadiness(),
	}
	if missing := validation.VerifyPrincipalVerdictNames(names); len(missing) != 0 {
		t.Fatalf("detector release verdict names not registered (FB-34.1): %v", missing)
	}
}
