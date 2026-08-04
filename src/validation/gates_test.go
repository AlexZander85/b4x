package validation

import (
	"errors"
	"testing"
)

func TestHardGateCount(t *testing.T) {
	// Registry totals are computed, not hard-coded (owner decision).
	// These assertions pin the extraction against the addenda.
	if n := HardGateCount(); n != 283 {
		t.Fatalf("HardGateCount() = %d, want 283 (282 addendum + mon_production_ready FB-28)", n)
	}
}

func TestApplicableHardGates(t *testing.T) {
	gates := ApplicableHardGates()
	// 24 FB-03 scope gate producers + 10 WARP base-transport producers
	// (FB-02 §72, verified via warp.Runtime in src/warp/runtime.go)
	// + 2 FB-29 resolution first-success-erasure producers (monitor_/
	// detector_first_success_erased_address_failures_total)
	// + 9 FB-30 multi-vantage producers (monitor_/detector variants of
	// http_hypothesis_from_tcp_tls_only_observer, observer_unavailable_as_
	// target_failure, exact_endpoint_service_resolution_conflated,
	// observer_capability_unproven + detector_multivantage_stage_mismatch,
	// verified via RecordMultiVantageViolation in src/detector/abd_path.go).
	// + 22 SPF silent-path failure producers (FB-02 45, verified via the
	// lifecycle guards in src/silentpath/hard_gate_producers.go).
	// + 24 DDI/TGB producers (FB-02 32/33: 14 guided-discovery guards in
	// src/discovery/hard_gate_producers.go + 10 bridge guards in
	// src/mtproto/hard_gate_producers.go)
	// + 52 MON producers (FB-02 84-92: guards in
	// src/monitoring/hard_gate_producers.go).
	// Each has a real Metrics.Inc call site, an executed fixture and (for
	// zero-tolerance gates) an executed mutation run.
	if len(gates) != 143 {
		t.Fatalf("ApplicableHardGates() = %d gates, want 143", len(gates))
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

func TestEvaluateHardGatesWindowDelta(t *testing.T) {
	// Owner decision 2026-08-01: zero-tolerance evaluation is performed on
	// the delta of the current validation window, never on the lifetime
	// absolute total. This test is the mutation guard for the window-delta
	// aggregation: if the baseline subtraction is removed, the "clean
	// window" case below FAILs instead of PASSing.
	scope := ReleaseScope{CSI: true}
	produced := map[string]bool{"unrelated_control_action_total": true}

	// Lifetime total 5, window baseline 5 => delta 0 => PASS.
	clean := EvaluateHardGatesWindow(scope, nil, "", GenerationSet{},
		map[string]uint64{"unrelated_control_action_total": 5},
		map[string]uint64{"unrelated_control_action_total": 5}, produced)
	if clean.Verdict != GatePass {
		t.Fatalf("clean window verdict = %s, want PASS (lifetime 5, delta 0)", clean.Verdict)
	}
	if !clean.WindowBaseline {
		t.Fatal("WindowBaseline must be true when a baseline is supplied")
	}

	// Lifetime total 7, window baseline 5 => delta 2 => FAIL with delta count.
	violated := EvaluateHardGatesWindow(scope, nil, "", GenerationSet{},
		map[string]uint64{"unrelated_control_action_total": 7},
		map[string]uint64{"unrelated_control_action_total": 5}, produced)
	if violated.Verdict != GateFail {
		t.Fatalf("dirty window verdict = %s, want FAIL (lifetime 7, delta 2)", violated.Verdict)
	}
	if len(violated.Violations) != 1 || violated.Violations[0].Count != 2 {
		t.Fatalf("violations = %+v, want single violation with delta count 2", violated.Violations)
	}

	// Counter reset inside the window (current < baseline) is
	// BLOCKED_COUNTER_RESET: the delta is undefined and a reset must not hide
	// violations accumulated in the same session. Owner requirement: add
	// baseline=5, current=0 -> BLOCKED test.
	reset := EvaluateHardGatesWindow(scope, nil, "", GenerationSet{},
		map[string]uint64{"unrelated_control_action_total": 3},
		map[string]uint64{"unrelated_control_action_total": 10}, produced)
	if reset.Verdict != GateBlocked {
		t.Fatalf("reset window verdict = %s, want BLOCKED (BLOCKED_COUNTER_RESET)", reset.Verdict)
	}
	if len(reset.CounterReset) != 1 || reset.CounterReset[0] != "unrelated_control_action_total" {
		t.Fatalf("CounterReset = %+v, want [unrelated_control_action_total]", reset.CounterReset)
	}
	if len(reset.Violations) != 0 {
		t.Fatalf("violations = %+v, want none (reset is not a delta violation)", reset.Violations)
	}

	// Owner-mandated exact case: baseline=5, current=0 -> BLOCKED_COUNTER_RESET.
	resetExact := EvaluateHardGatesWindow(scope, nil, "", GenerationSet{},
		map[string]uint64{"unrelated_control_action_total": 0},
		map[string]uint64{"unrelated_control_action_total": 5}, produced)
	if resetExact.Verdict != GateBlocked || len(resetExact.CounterReset) != 1 {
		t.Fatalf("baseline=5,current=0 = %+v, want BLOCKED_COUNTER_RESET", resetExact)
	}

	// No baseline: window spans the process lifetime, delta == current.
	lifetime := EvaluateHardGates(scope, nil, "", GenerationSet{},
		map[string]uint64{"unrelated_control_action_total": 2}, produced)
	if lifetime.Verdict != GateFail || lifetime.Violations[0].Count != 2 {
		t.Fatalf("lifetime window = %+v, want FAIL with count 2", lifetime)
	}
	if lifetime.WindowBaseline {
		t.Fatal("WindowBaseline must be false without a baseline")
	}
}

func TestEvaluateHardGatesReadinessInputsNeverBlock(t *testing.T) {
	// current_generation_readiness_input gates (GSO offload/checksum/token,
	// capture visibility degrade) are inputs to current-generation readiness,
	// not lifetime zero-tolerance blockers: they are reported in
	// ReadinessInputs and never flip the verdict on their own.
	scope := ReleaseScope{RSTGSO: true, PPE: true}
	counters := map[string]uint64{
		"nfqueue_gso_truncated_total":            5,
		"nfqueue_gso_csum_not_ready_total":       3,
		"nfqueue_gso_token_miss_total":           1,
		"b4_capture_visibility_degrade_total":    2,
		"nfqueue_gso_packets_total":              100,
		"b4_hold_disabled_visibility_total":      4,
		"b4_ppe_rule_reapply_total":              1,
		"b4_ppe_self_test_total":                 1,
		"passive_rst_fail_open_total":            1,
		"classifier_layout_parity_fail_total":    0,
		"passive_rst_reconnect_regression_total": 0,
		"passive_rst_observed_total":             50,
	}
	produced := make(map[string]bool, len(counters))
	for name := range counters {
		produced[name] = true
	}
	eval := EvaluateHardGates(scope, nil, "", GenerationSet{}, counters, produced)
	if eval.Verdict != GatePass {
		t.Fatalf("verdict = %s, want PASS (readiness inputs + telemetry never block; violations=%d missing=%d)",
			eval.Verdict, len(eval.Violations), len(eval.Missing))
	}
	if len(eval.ReadinessInputs) != 4 {
		t.Fatalf("ReadinessInputs = %+v, want 4 readiness inputs", eval.ReadinessInputs)
	}
	got := map[string]uint64{}
	for _, v := range eval.ReadinessInputs {
		got[v.Metric] = v.Count
	}
	if got["nfqueue_gso_truncated_total"] != 5 || got["nfqueue_gso_csum_not_ready_total"] != 3 ||
		got["nfqueue_gso_token_miss_total"] != 1 || got["b4_capture_visibility_degrade_total"] != 2 {
		t.Fatalf("readiness counts = %+v, want truncated=5 csum=3 token=1 degrade=2", got)
	}
	// Telemetry is reported separately and never blocks either: all 17
	// telemetry counters of the RSTGSO+PPE scope are observed (count 0 when
	// not produced yet).
	if len(eval.Telemetry) != 17 {
		t.Fatalf("Telemetry has %d entries, want 17 (RSTGSO+PPE telemetry)", len(eval.Telemetry))
	}
	telemetrySeen := map[string]bool{}
	for _, v := range eval.Telemetry {
		telemetrySeen[v.Metric] = true
	}
	// Safe-degradation / safety-guard counters must be informational
	// telemetry (owner decision 2026-08-01), never violations.
	for _, name := range []string{"passive_rst_fail_open_total", "b4_hold_disabled_visibility_total"} {
		if !telemetrySeen[name] {
			t.Fatalf("telemetry %q missing from Telemetry report", name)
		}
	}
}

func TestEvaluateHardGatesScopeIsolation(t *testing.T) {
	// A zero-tolerance violation in a non-applicable scope must not affect
	// the evaluation: only gates of enabled families are selected.
	scope := ReleaseScope{CSI: true}
	counters := map[string]uint64{
		"classifier_layout_parity_fail_total": 9, // rst_gso family, not in scope
		"unrelated_control_action_total":      0,
	}
	produced := map[string]bool{
		"classifier_layout_parity_fail_total": true,
		"unrelated_control_action_total":      true,
	}
	eval := EvaluateHardGates(scope, nil, "", GenerationSet{}, counters, produced)
	if eval.Verdict != GatePass {
		t.Fatalf("verdict = %s, want PASS (rst_gso violation outside CSI scope)", eval.Verdict)
	}
	if len(eval.Violations) != 0 {
		t.Fatalf("violations = %+v, want none (out-of-scope counter ignored)", eval.Violations)
	}
}

func TestEvaluateReadinessOwnerStateEffect(t *testing.T) {
	// Owner requirement (phase E2): for the 4 readiness inputs prove the
	// owner-state effect — non-zero input + applicable unsafe owner state
	// -> DEGRADED/BLOCKED; successful revalidation of a new generation
	// (owner state back to safe) restores readiness.
	inputs := []GateViolation{
		{GateID: "nfqueue_gso_truncated_total", Metric: "nfqueue_gso_truncated_total", Count: 5},
		{GateID: "nfqueue_gso_csum_not_ready_total", Metric: "nfqueue_gso_csum_not_ready_total", Count: 3},
		{GateID: "nfqueue_gso_token_miss_total", Metric: "nfqueue_gso_token_miss_total", Count: 1},
		{GateID: "b4_capture_visibility_degrade_total", Metric: "b4_capture_visibility_degrade_total", Count: 2},
	}

	// 1) Unsafe owner states: every non-zero input blocks current-generation
	// readiness. The GSO trio is a DEFERRED dependency (FB-27/PPE) and is
	// wired as Unknown in production => DEGRADED; capture visibility is wired
	// and Unsafe => BLOCKED.
	unsafe := EvaluateReadiness(inputs, map[GateID]OwnerReadinessState{
		"nfqueue_gso_truncated_total":         OwnerStateUnknown,
		"nfqueue_gso_csum_not_ready_total":    OwnerStateUnknown,
		"nfqueue_gso_token_miss_total":        OwnerStateUnknown,
		"b4_capture_visibility_degrade_total": OwnerStateUnsafe,
	})
	if unsafe.Verdict != ReadinessBlocked {
		t.Fatalf("verdict = %s, want BLOCKED (unsafe owner state)", unsafe.Verdict)
	}
	got := map[string]ReadinessStatus{}
	for _, g := range unsafe.Gates {
		got[g.Metric] = g.Status
	}
	if got["b4_capture_visibility_degrade_total"] != ReadinessBlocked {
		t.Fatalf("visibility degrade must be BLOCKED with unsafe owner: %+v", got)
	}
	for _, m := range []string{"nfqueue_gso_truncated_total", "nfqueue_gso_csum_not_ready_total", "nfqueue_gso_token_miss_total"} {
		if got[m] != ReadinessDegraded {
			t.Fatalf("%s must be DEGRADED with unknown owner (DEFERRED): %+v", m, got)
		}
	}

	// 2) All-unsafe: BLOCKED across the board.
	allUnsafe := EvaluateReadiness(inputs, map[GateID]OwnerReadinessState{
		"nfqueue_gso_truncated_total": OwnerStateUnsafe, "nfqueue_gso_csum_not_ready_total": OwnerStateUnsafe,
		"nfqueue_gso_token_miss_total": OwnerStateUnsafe, "b4_capture_visibility_degrade_total": OwnerStateUnsafe,
	})
	if allUnsafe.Verdict != ReadinessBlocked {
		t.Fatalf("all-unsafe verdict = %s, want BLOCKED", allUnsafe.Verdict)
	}

	// 3) Successful revalidation of a new generation: owner state returns to
	// safe (visibility complete after revalidation, GSO re-observed) and
	// readiness is restored even though inputs remain non-zero.
	revalidated := EvaluateReadiness(inputs, map[GateID]OwnerReadinessState{
		"nfqueue_gso_truncated_total":         OwnerStateSafe,
		"nfqueue_gso_csum_not_ready_total":    OwnerStateSafe,
		"nfqueue_gso_token_miss_total":        OwnerStateSafe,
		"b4_capture_visibility_degrade_total": OwnerStateSafe,
	})
	if revalidated.Verdict != ReadinessReady {
		t.Fatalf("revalidation verdict = %s, want READY (owner state restored)", revalidated.Verdict)
	}
	for _, g := range revalidated.Gates {
		if g.Status != ReadinessReady {
			t.Fatalf("gate %s = %s, want READY after revalidation", g.Metric, g.Status)
		}
	}

	// 4) Zero inputs are always READY regardless of owner state.
	zeroInputs := []GateViolation{
		{GateID: "nfqueue_gso_truncated_total", Metric: "nfqueue_gso_truncated_total", Count: 0},
		{GateID: "nfqueue_gso_csum_not_ready_total", Metric: "nfqueue_gso_csum_not_ready_total", Count: 0},
		{GateID: "nfqueue_gso_token_miss_total", Metric: "nfqueue_gso_token_miss_total", Count: 0},
		{GateID: "b4_capture_visibility_degrade_total", Metric: "b4_capture_visibility_degrade_total", Count: 0},
	}
	zero := EvaluateReadiness(zeroInputs, map[GateID]OwnerReadinessState{
		"nfqueue_gso_truncated_total": OwnerStateUnsafe, "b4_capture_visibility_degrade_total": OwnerStateUnsafe,
	})
	for _, g := range zero.Gates {
		if g.Input != 0 || g.Status != ReadinessReady {
			t.Fatalf("zero-input gate %+v must be READY", g)
		}
	}
	if zero.Verdict != ReadinessReady {
		t.Fatalf("zero-input verdict = %s, want READY", zero.Verdict)
	}
}

func TestBaselineForRunWindowSemantics(t *testing.T) {
	// Production window store (phase E2): the same generation reuses the same
	// baseline; a new process/run/generation starts a new baseline. A counter
	// reset inside the same session must surface as BLOCKED_COUNTER_RESET, not
	// as a rebaseline (rebase is allowed only for a new process/run/generation).
	ResetProductionWindow()
	t.Cleanup(ResetProductionWindow)

	scope := ReleaseScope{CSI: true}
	produced := map[string]bool{"unrelated_control_action_total": true}

	// First evaluation of generation "gen-1": baseline captured at 5.
	b1 := BaselineForRun("gen-1", map[string]uint64{"unrelated_control_action_total": 5})
	eval1 := EvaluateHardGatesWindow(scope, nil, "", GenerationSet{}, map[string]uint64{"unrelated_control_action_total": 7}, b1, produced)
	if eval1.Verdict != GateFail || eval1.Violations[0].Count != 2 {
		t.Fatalf("gen-1 first eval = %+v, want FAIL delta 2", eval1)
	}
	if info := ProductionWindowInfo(); !info.Active || info.Generation != "gen-1" {
		t.Fatalf("window info = %+v, want active gen-1", info)
	}

	// Retry of the same generation keeps the baseline: the delta accumulates.
	b2 := BaselineForRun("gen-1", map[string]uint64{"unrelated_control_action_total": 9})
	eval2 := EvaluateHardGatesWindow(scope, nil, "", GenerationSet{}, map[string]uint64{"unrelated_control_action_total": 9}, b2, produced)
	if eval2.Verdict != GateFail || eval2.Violations[0].Count != 4 {
		t.Fatalf("gen-1 retry = %+v, want FAIL delta 4 (same baseline reused)", eval2)
	}

	// Counter reset in the same session is NOT a rebaseline: BLOCKED.
	b3 := BaselineForRun("gen-1", map[string]uint64{"unrelated_control_action_total": 0})
	eval3 := EvaluateHardGatesWindow(scope, nil, "", GenerationSet{}, map[string]uint64{"unrelated_control_action_total": 0}, b3, produced)
	if eval3.Verdict != GateBlocked || len(eval3.CounterReset) != 1 {
		t.Fatalf("reset in same session = %+v, want BLOCKED_COUNTER_RESET", eval3)
	}

	// New generation "gen-2" starts a new window: baseline at 2, delta 0.
	b4 := BaselineForRun("gen-2", map[string]uint64{"unrelated_control_action_total": 2})
	eval4 := EvaluateHardGatesWindow(scope, nil, "", GenerationSet{}, map[string]uint64{"unrelated_control_action_total": 2}, b4, produced)
	if eval4.Verdict != GatePass {
		t.Fatalf("gen-2 clean window = %+v, want PASS (new generation => new baseline)", eval4)
	}
	if info := ProductionWindowInfo(); info.Generation != "gen-2" {
		t.Fatalf("window info = %+v, want gen-2", info)
	}

	// Process restart (ResetProductionWindow): fresh baseline allowed.
	ResetProductionWindow()
	if info := ProductionWindowInfo(); info.Active {
		t.Fatalf("window must be inactive after reset: %+v", info)
	}
	b5 := BaselineForRun("gen-2", map[string]uint64{"unrelated_control_action_total": 10})
	eval5 := EvaluateHardGatesWindow(scope, nil, "", GenerationSet{}, map[string]uint64{"unrelated_control_action_total": 10}, b5, produced)
	if eval5.Verdict != GatePass {
		t.Fatalf("fresh window = %+v, want PASS", eval5)
	}
}
