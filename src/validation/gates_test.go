package validation

import (
	"errors"
	"testing"
)

func TestHardGateCount(t *testing.T) {
	// Registry totals are computed, not hard-coded (owner decision).
	// These assertions pin the extraction against the addenda.
	if n := HardGateCount(); n != 282 {
		t.Fatalf("HardGateCount() = %d, want 282", n)
	}
}

func TestApplicableHardGates(t *testing.T) {
	gates := ApplicableHardGates()
	// All 24 FB-03 scope gate producers are verified (2026-08-01): CSI-18
	// unrelated_control_action_total, 19 RST/GSO metrics and 4 PPE metrics.
	// Each has a real Metrics.Inc call site, an executed fixture and, for the
	// 9 zero-tolerance gates, an executed mutation run.
	if len(gates) != 24 {
		t.Fatalf("ApplicableHardGates() = %d gates, want 24", len(gates))
	}
	for _, g := range gates {
		if g.ProducerStatus != "verified" || g.RuntimeProducer.Symbol == "" {
			t.Fatalf("applicable gate %q has no verified producer: %+v", g.GateID, g.RuntimeProducer)
		}
		// Verified producers must carry a machine-readable consumer chain,
		// test fixtures and evidence (FB-03 verdict-consumer chain).
		if len(g.VerdictConsumers) == 0 {
			t.Fatalf("applicable gate %q has no verdict consumers", g.GateID)
		}
		if len(g.TestProducers) == 0 {
			t.Fatalf("applicable gate %q has no test fixtures", g.GateID)
		}
		if len(g.EvidenceArtifacts) == 0 {
			t.Fatalf("applicable gate %q has no evidence artifacts", g.GateID)
		}
	}
}

func TestRequiredHardGatesSelection(t *testing.T) {
	scope := ReleaseScope{WARPBase: true}
	caps := CapabilitySet{}
	gates, err := RequiredHardGates(scope, caps, "WARP_CAUSAL_TRACE_READY", GenerationSet{})
	if err != nil {
		t.Fatal(err)
	}
	if len(gates) == 0 {
		t.Fatal("WARP base scope selected no gates")
	}
	// base transport (10) + causal trace (26) = 36
	if len(gates) != 36 {
		t.Fatalf("WARPBase selected %d gates, want 36 (10 base + 26 causal)", len(gates))
	}
	// camouflage and non-RU gates must NOT be selected.
	for _, gid := range gates {
		g, ok := HardGateByName(string(gid))
		if !ok {
			t.Fatalf("selected unknown gate %q", gid)
		}
		if g.GlobalGateClass == "camouflage" || g.GlobalGateClass == "non_ru" {
			t.Fatalf("gate %q (class %s) selected without camouflage/non-RU scope", gid, g.GlobalGateClass)
		}
	}
}

func TestRequiredHardGatesCamouflageAndNonRU(t *testing.T) {
	scope := ReleaseScope{WARPBase: true, WARPCamouflage: true, WARPNonRU: true}
	gates, err := RequiredHardGates(scope, CapabilitySet{}, "", GenerationSet{})
	if err != nil {
		t.Fatal(err)
	}
	// 36 base/causal + 8 non-RU + 12 camouflage = 56
	if len(gates) != 56 {
		t.Fatalf("full WARP scope selected %d gates, want 56", len(gates))
	}
}

func TestRequiredHardGatesEmptyScope(t *testing.T) {
	if _, err := RequiredHardGates(ReleaseScope{}, nil, "", GenerationSet{}); !errors.Is(err, ErrEmptyScope) {
		t.Fatalf("empty scope error = %v, want ErrEmptyScope", err)
	}
}

func TestRequiredHardGatesServiceProfilesRequireCapability(t *testing.T) {
	scope := ReleaseScope{SP: true}
	// Without the service_profiles capability the SP family is NOT applicable.
	gates, err := RequiredHardGates(scope, nil, "", GenerationSet{})
	if err != nil {
		t.Fatal(err)
	}
	if len(gates) != 0 {
		t.Fatalf("SP without capability selected %d gates, want 0", len(gates))
	}
	gates, err = RequiredHardGates(scope, CapabilitySet{"service_profiles": true}, "", GenerationSet{})
	if err != nil {
		t.Fatal(err)
	}
	if len(gates) != 14 {
		t.Fatalf("SP with capability selected %d gates, want 14", len(gates))
	}
}

func TestEvaluateHardGatesPass(t *testing.T) {
	scope := ReleaseScope{PPE: true, CSI: true}
	// PPE family: b4_ppe_rule_reapply_total etc. are produced by
	// capture/ppe/product_service.go; unrelated_control_action_total by
	// crossservice/validation.go. All zero => PASS.
	counters := map[string]uint64{
		"b4_capture_visibility_degrade_total": 0,
		"b4_hold_disabled_visibility_total":   0,
		"b4_ppe_rule_reapply_total":           0,
		"b4_ppe_self_test_total":              0,
		"unrelated_control_action_total":      0,
	}
	produced := map[string]bool{
		"b4_capture_visibility_degrade_total": true,
		"b4_hold_disabled_visibility_total":   true,
		"b4_ppe_rule_reapply_total":           true,
		"b4_ppe_self_test_total":              true,
		"unrelated_control_action_total":      true,
	}
	eval := EvaluateHardGates(scope, nil, "", GenerationSet{}, counters, produced)
	if eval.Verdict != GatePass {
		t.Fatalf("verdict = %s, want PASS (violations=%d missing=%d)", eval.Verdict, len(eval.Violations), len(eval.Missing))
	}
}

func TestEvaluateHardGatesViolation(t *testing.T) {
	scope := ReleaseScope{CSI: true}
	counters := map[string]uint64{"unrelated_control_action_total": 3}
	produced := map[string]bool{"unrelated_control_action_total": true}
	eval := EvaluateHardGates(scope, nil, "", GenerationSet{}, counters, produced)
	if eval.Verdict != GateFail {
		t.Fatalf("verdict = %s, want FAIL", eval.Verdict)
	}
	if len(eval.Violations) != 1 || eval.Violations[0].Count != 3 {
		t.Fatalf("violations = %+v, want single count=3", eval.Violations)
	}
}

func TestEvaluateHardGatesMissingProducer(t *testing.T) {
	scope := ReleaseScope{WARPBase: true}
	counters := map[string]uint64{}
	produced := map[string]bool{}
	eval := EvaluateHardGates(scope, nil, "", GenerationSet{}, counters, produced)
	// No WARP gate has a runtime producer yet => BLOCKED, not PASS (v2 §0.6.3).
	if eval.Verdict != GateBlocked {
		t.Fatalf("verdict = %s, want BLOCKED (missing producers)", eval.Verdict)
	}
	if len(eval.Missing) == 0 {
		t.Fatal("expected missing gates")
	}
}

func TestEvaluateHardGatesNotApplicable(t *testing.T) {
	eval := EvaluateHardGates(ReleaseScope{}, nil, "", GenerationSet{}, nil, nil)
	if eval.Verdict != GateNotApplicable {
		t.Fatalf("verdict = %s, want NOT_APPLICABLE", eval.Verdict)
	}
}

func TestLegacyAliasMigration(t *testing.T) {
	cases := map[string]string{
		// exact canonical names map to themselves
		"detector_single_probe_confirmed_total": "detector_single_probe_confirmed_total",
		"unrelated_control_action_total":        "unrelated_control_action_total",
		// renamed gates migrate to canonical metric
		"destination_only_state_total":           "silent_failure_destination_only_state_total",
		"parent_generation_mismatch_total":       "warp_nested_parent_generation_mismatch_total",
		"dns_direct_leak_total":                  "nonru_route_active_with_direct_dns",
		"ipv6_unvalidated_egress_total":          "nonru_route_active_with_unvalidated_ipv6",
		"cleanup_foreign_resource_removed_total": "warp_foreign_resource_removed_total",
		"trace_required_event_drop_total":        "warp_trace_dropped_required_event_total",
	}
	for legacy, want := range cases {
		got, ok := CanonicalGateID(legacy)
		if !ok {
			t.Fatalf("CanonicalGateID(%q) not found", legacy)
		}
		if string(got) != want {
			t.Fatalf("CanonicalGateID(%q) = %q, want %q", legacy, got, want)
		}
		if _, ok := HardGateByName(want); !ok {
			t.Fatalf("canonical target %q missing from registry", want)
		}
	}
	// retired aliases resolve to nothing
	for _, retired := range []string{"route_counter_missing_total", "forwarded_binding_missing_total", "stale_generation_event_total"} {
		if _, ok := CanonicalGateID(retired); ok {
			t.Fatalf("retired alias %q must not resolve", retired)
		}
	}
	// alias must not create a second counter: the canonical name is the
	// registry key and the alias resolves to it (no extra metric).
	if n := len(LegacyGateAliases); n != 17 {
		t.Fatalf("LegacyGateAliases has %d entries, want 17", n)
	}
}

func TestEvaluateHardGatesAliasDoesNotDoubleCount(t *testing.T) {
	// An alias name in counters must not be treated as a separate gate:
	// evaluation only reads canonical metric names.
	scope := ReleaseScope{SPF: true}
	canonical := "silent_failure_destination_only_state_total"
	counters := map[string]uint64{canonical: 0, "destination_only_state_total": 5}
	produced := map[string]bool{canonical: true, "destination_only_state_total": true}
	eval := EvaluateHardGates(scope, nil, "", GenerationSet{}, counters, produced)
	// destination_only_state_total (legacy) is not a canonical gate; the
	// canonical one is zero, but SPF family has 22 gates with producers
	// missing => BLOCKED. The legacy counter must not appear in violations.
	if eval.Verdict != GateBlocked {
		t.Fatalf("verdict = %s, want BLOCKED (missing SPF producers)", eval.Verdict)
	}
	for _, v := range eval.Violations {
		if v.Metric == "destination_only_state_total" {
			t.Fatalf("legacy alias counted as violation: %+v", v)
		}
	}
}
