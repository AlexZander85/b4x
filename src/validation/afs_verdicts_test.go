package validation

import "testing"

func completeAFSLabEvidence() AFSReadinessEvidence {
	deps := map[string]Verdict{}
	afsNames := map[string]struct{}{
		AFSVerdictBehavioralFingerprint: {},
		AFSVerdictConstrainedSynthesis:  {},
		AFSVerdictSynthesizedDiscovery:  {},
		AFSVerdictAutonomousAdaptation:  {},
	}
	for name := range afsNames {
		entry, ok := PrincipalVerdictByCanonical(name)
		if !ok {
			continue
		}
		for _, dep := range entry.Dependencies {
			if _, internal := afsNames[dep]; !internal {
				deps[dep] = Pass
			}
	}
	counters := make(map[string]uint64, len(AFSZeroToleranceCounters))
	for _, name := range AFSZeroToleranceCounters {
		counters[name] = 0
	}
	return AFSReadinessEvidence{
		Lab: AFSLabEvidence{
			UserOptInContract:          true,
			PersistentRegressionGate:   true,
			BehavioralPanelBounded:     true,
			BehavioralEvidenceBound:    true,
			DDIOperatorConstraints:     true,
			FiniteGrammarValidated:     true,
			DeterministicSearch:        true,
			ActionPlannerBridge:        true,
			SharedDiscoveryScoring:     true,
			MandatoryControlsValidated: true,
			NoDirectApplyValidated:     true,
			TransactionalPromotion:     true,
			FaultInjectionValidated:    true,
		},
		DependencyVerdicts:   deps,
		ZeroToleranceCounters: counters,
		TestRefs: []string{
			"focused-ci:35085703795",
			"zero-tolerance-fault-injection",
		},
		ArtifactRefs: []string{
			"reports/AFS_REFERENCE_AUDIT.md",
			"reports/AFS_SYNTHETIC_DPI_MATRIX.json",
			"reports/AFS_CANDIDATE_GENERATION_REPORT.json",
			"reports/AFS_DISCOVERY_INTEGRATION_REPORT.json",
		},
	}
}

func completeAFSTargetEvidence() AFSTargetEvidence {
	return AFSTargetEvidence{
		Available:                    true,
		KeeneticRouterValidated:      true,
		ForwardedAndroidCanaryPassed: true,
		TargetAndControlsPassed:      true,
		ResourceBoundsValidated:      true,
		CleanupValidated:             true,
		RollbackValidated:            true,
		RecoveryObserved:             true,
		StableWindowValidated:        true,
	}
}

func TestAFSPrincipalVerdictsAreCanonicalRegistryEntries(t *testing.T) {
	for _, name := range []string{
		AFSVerdictBehavioralFingerprint,
		AFSVerdictConstrainedSynthesis,
		AFSVerdictSynthesizedDiscovery,
		AFSVerdictAutonomousAdaptation,
	} {
		canonical, ok := CanonicalVerdictName(name)
		if !ok || canonical != name {
			t.Fatalf("AFS principal verdict %q is not canonical: canonical=%q ok=%v", name, canonical, ok)
		}
	}
}

func TestAFSLabPassesFirstThreeButBlocksAutonomousWithoutTargetEvidence(t *testing.T) {
	evidence := completeAFSLabEvidence()
	result := EvaluateAFSPrincipalVerdicts(evidence)

	for _, name := range []string{AFSVerdictBehavioralFingerprint, AFSVerdictConstrainedSynthesis, AFSVerdictSynthesizedDiscovery} {
		if got := result.Results[name].Verdict; got != Pass {
			t.Fatalf("%s verdict=%s, want PASS: %+v", name, got, result.Results[name])
		}
	}
	if got := result.Results[AFSVerdictAutonomousAdaptation].Verdict; got == Pass {
		t.Fatal("autonomous adaptation became PASS without target evidence")
	}
	if result.ReleaseStatus != AFSReleaseLabBlocked || result.ProductionReady {
		t.Fatalf("release status=%q production_ready=%v", result.ReleaseStatus, result.ProductionReady)
	}
	if !containsString(result.Results[AFSVerdictAutonomousAdaptation].Limitations, "BLOCKED_BY_TARGET_EVIDENCE") {
		t.Fatalf("target blocker not surfaced: %+v", result.Results[AFSVerdictAutonomousAdaptation])
	}
}

func TestAFSAutonomousPassRequiresCompleteTargetEvidence(t *testing.T) {
	evidence := completeAFSLabEvidence()
	evidence.Target = completeAFSTargetEvidence()
	result := EvaluateAFSPrincipalVerdicts(evidence)
	if got := result.Results[AFSVerdictAutonomousAdaptation].Verdict; got != Pass {
		t.Fatalf("autonomous verdict=%s, want PASS: %+v", got, result.Results[AFSVerdictAutonomousAdaptation])
	}
	if result.ReleaseStatus != AFSReleaseProductionReady || !result.ProductionReady {
		t.Fatalf("release status=%q production_ready=%v", result.ReleaseStatus, result.ProductionReady)
	}
}

func TestAFSNonzeroZeroToleranceCounterBlocksAllStages(t *testing.T) {
	evidence := completeAFSLabEvidence()
	evidence.Target = completeAFSTargetEvidence()
	evidence.ZeroToleranceCounters["synthesis_candidate_direct_apply_total"] = 1
	result := EvaluateAFSPrincipalVerdicts(evidence)
	for _, name := range []string{AFSVerdictBehavioralFingerprint, AFSVerdictConstrainedSynthesis, AFSVerdictSynthesizedDiscovery, AFSVerdictAutonomousAdaptation} {
		if result.Results[name].Verdict == Pass {
			t.Fatalf("%s passed with a non-zero zero-tolerance counter", name)
		}
	}
	if result.ProductionReady {
		t.Fatal("production readiness survived zero-tolerance violation")
	}
}

func TestAFSMissingZeroToleranceCounterFailsClosed(t *testing.T) {
	evidence := completeAFSLabEvidence()
	delete(evidence.ZeroToleranceCounters, "synthesis_cleanup_incomplete_total")
	result := EvaluateAFSPrincipalVerdicts(evidence)
	if result.Results[AFSVerdictBehavioralFingerprint].Verdict == Pass {
		t.Fatal("missing counter evidence was treated as zero")
	}
}

func TestAFSMissingExistingDependencyFailsClosed(t *testing.T) {
	evidence := completeAFSLabEvidence()
	entry, ok := PrincipalVerdictByCanonical(AFSVerdictBehavioralFingerprint)
	if !ok || len(entry.Dependencies) == 0 {
		t.Skip("registry has no external dependency for behavioral verdict")
	}
	delete(evidence.DependencyVerdicts, entry.Dependencies[0])
	result := EvaluateAFSPrincipalVerdicts(evidence)
	if result.Results[AFSVerdictBehavioralFingerprint].Verdict == Pass {
		t.Fatalf("missing dependency %q was treated as PASS", entry.Dependencies[0])
	}
}

func TestAFSTargetEvidenceCannotBypassMissingLabProof(t *testing.T) {
	evidence := completeAFSLabEvidence()
	evidence.Target = completeAFSTargetEvidence()
	evidence.Lab.FiniteGrammarValidated = false
	result := EvaluateAFSPrincipalVerdicts(evidence)
	if result.Results[AFSVerdictConstrainedSynthesis].Verdict == Pass || result.Results[AFSVerdictAutonomousAdaptation].Verdict == Pass {
		t.Fatal("target evidence bypassed missing constrained-synthesis proof")
	}
	if result.ProductionReady {
		t.Fatal("production readiness survived missing lab proof")
	}
}
