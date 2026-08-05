package validation

import (
	"sort"
	"strings"
	"testing"
)

// FB-34 (b4x-xgc): the generated Canonical Principal Verdict Registry must be
// deterministic, internally consistent, and match its declared total. These
// tests run against the generated Go registry only (no YAML access), so
// `go test` inside CI fails closed on any registry-integrity regression:
// duplicate names/state, ARCH-graph dependency aggregation, alias
// compatibility migration and stale/missing-evidence invalidation.

func TestPrincipalVerdictDeclaredTotalMatches(t *testing.T) {
	got := len(principalVerdicts)
	if got != PrincipalVerdictDeclaredTotal {
		t.Fatalf("computed verdict total=%d, declared_total=%d (FB-34: totals computed, never hard-coded)", got, PrincipalVerdictDeclaredTotal)
	}
	if got <= 0 {
		t.Fatalf("registry empty: computed verdict total=%d", got)
	}
}

func TestPrincipalVerdictRegistryValid(t *testing.T) {
	errs := ValidatePrincipalVerdictRegistry()
	if len(errs) != 0 {
		t.Fatalf("principal verdict registry integrity violations: %d\n%s", len(errs), strings.Join(errs, "\n"))
	}
	if !PrincipalVerdictRegistryValid() {
		t.Fatal("PrincipalVerdictRegistryValid()=false while ValidatePrincipalVerdictRegistry() returned no errors")
	}
}

func TestPrincipalVerdictNoDuplicateNames(t *testing.T) {
	// FB-34 criterion: duplicate state/name detection. Canonical names unique,
	// aliases unique, and no alias may collide with a canonical name (an
	// ambiguous spelling must never resolve silently).
	seen := map[string]bool{}
	for _, v := range principalVerdicts {
		if seen[v.Canonical] {
			t.Fatalf("duplicate canonical %q in generated registry", v.Canonical)
		}
		seen[v.Canonical] = true
		for _, a := range v.Aliases {
			if a == "" {
				t.Fatalf("empty alias on %q", v.Canonical)
			}
			if seen[a] {
				t.Fatalf("alias %q of %q duplicates another canonical or alias", a, v.Canonical)
			}
			seen[a] = true
		}
	}
}

func TestCanonicalVerdictNameAliasMapping(t *testing.T) {
	// FB-34 criterion: compatibility migration. Legacy/superseded spellings
	// must resolve to the canonical name (FB18-07 supersession mapping);
	// unknown names must fail closed.
	cases := []struct {
		in, want string
	}{
		{"TGB_PRODUCTION_READY", "TGB_PRODUCTION_READY"},             // canonical form
		{"TELEGRAM_BRIDGE_PRODUCTION_READY", "TGB_PRODUCTION_READY"}, // ARCH §142 legacy alias
		{"DETECTOR_GUIDED_STRATEGY_SEARCH_READY", "DETECTOR_GUIDED_STRATEGY_SEARCH_READY"},
		{"GUIDED_DISCOVERY_READY", "DETECTOR_GUIDED_STRATEGY_SEARCH_READY"}, // ARCH §142 legacy alias
		{"ABD_PRODUCTION_READY", "ABD_PRODUCTION_READY"},
		{"BLOCKED_TARGET_VALIDATION", "BLOCKED_TARGET_VALIDATION"},
	}
	for _, c := range cases {
		got, ok := CanonicalVerdictName(c.in)
		if !ok {
			t.Fatalf("CanonicalVerdictName(%q): not found", c.in)
		}
		if got != c.want {
			t.Fatalf("CanonicalVerdictName(%q)=%q, want %q", c.in, got, c.want)
		}
	}
	if got, ok := CanonicalVerdictName("NO_SUCH_VERDICT_NAME"); ok || got != "" {
		t.Fatalf("CanonicalVerdictName(unknown)=(%q,%t), want (\"\",false) — fail closed", got, ok)
	}
	// Every alias in the registry must round-trip to its owner canonical name.
	for _, v := range principalVerdicts {
		for _, a := range v.Aliases {
			got, ok := CanonicalVerdictName(a)
			if !ok || got != v.Canonical {
				t.Fatalf("alias %q of %q resolves to (%q,%t)", a, v.Canonical, got, ok)
			}
		}
	}
}

func TestVerdictDependencyClosureFollowsARCHGraph(t *testing.T) {
	// FB-34 criterion: dependency aggregation follows the ARCH graph. The
	// closure of ABD_PRODUCTION_READY must include the whole §52 ABD chain
	// plus the monitor adapter dependency (aggregation is transitive), and
	// the closure must be topologically sorted (dependencies first).
	closure, err := VerdictDependencyClosure("ABD_PRODUCTION_READY")
	if err != nil {
		t.Fatalf("VerdictDependencyClosure(ABD_PRODUCTION_READY): %v", err)
	}
	want := map[string]bool{
		"ABD_TARGET_PLAN_READY":       true,
		"ABD_CLEAN_BASELINE_READY":    true,
		"ABD_DNS_EVIDENCE_READY":      true,
		"ABD_TLS_HTTP_EVIDENCE_READY": true,
		"ABD_QUIC_EVIDENCE_READY":     true,
		"ABD_L4_PROFILER_READY":       true,
		"ABD_DYNAMIC_CONTROLS_READY":  true,
		"ABD_EVIDENCE_GRAPH_READY":    true,
		"ABD_BLOCKING_PROFILE_READY":  true,
		"ABD_DDI_ADAPTER_READY":       true,
		"ABD_ROUTER_VALIDATED":        true,
		"ABD_ANDROID_VALIDATED":       true,
		"ABD_MULTI_VANTAGE_READY":     true,
		"ABD_MONITOR_ADAPTER_READY":   true,
		"MON_PRODUCTION_READY":        true,
		"DDI_SCHEMA_READY":            true,
	}
	pos := map[string]int{}
	for i, n := range closure {
		pos[n] = i
	}
	for w := range want {
		if _, ok := pos[w]; !ok {
			t.Fatalf("dependency closure of ABD_PRODUCTION_READY missing %q (ARCH graph aggregation)", w)
		}
	}
	if closure[len(closure)-1] != "ABD_PRODUCTION_READY" {
		t.Fatalf("closure must end with the requested verdict, got ...%q", closure[len(closure)-1])
	}
	// Topological order: every dependency appears before its dependents.
	byName := map[string]PrincipalVerdict{}
	for _, v := range principalVerdicts {
		byName[v.Canonical] = v
	}
	for i, n := range closure {
		for _, d := range byName[n].Dependencies {
			if dp, ok := pos[d]; !ok || dp > i {
				t.Fatalf("closure order violated: %q depends on %q but appears first", n, d)
			}
		}
	}
	// The requested verdict itself must never be its own dependency.
	if _, ok := pos["ABD_PRODUCTION_READY"]; !ok {
		t.Fatal("closure missing the requested verdict")
	}
}

func TestVerdictDependencyClosureEveryVerdictAcyclic(t *testing.T) {
	for _, v := range principalVerdicts {
		closure, err := VerdictDependencyClosure(v.Canonical)
		if err != nil {
			t.Fatalf("VerdictDependencyClosure(%q): %v (cyclic or unknown dependency)", v.Canonical, err)
		}
		if len(closure) == 0 || closure[len(closure)-1] != v.Canonical {
			t.Fatalf("closure of %q must end with itself", v.Canonical)
		}
	}
	if _, err := VerdictDependencyClosure("NO_SUCH_VERDICT_NAME"); err == nil {
		t.Fatal("VerdictDependencyClosure(unknown) must fail closed")
	}
}

func TestPrincipalVerdictBlockedVariantsResolve(t *testing.T) {
	// Blocked verdicts are real registry entries of kind=blocked; blocked is
	// never equivalent to PASS_WITH_LIMITATIONS.
	byName := map[string]PrincipalVerdict{}
	for _, v := range principalVerdicts {
		byName[v.Canonical] = v
	}
	for _, v := range principalVerdicts {
		for _, b := range v.BlockedVariants {
			tgt, ok := byName[b]
			if !ok {
				t.Fatalf("blocked_variant %q of %q not registered", b, v.Canonical)
			}
			if tgt.Kind != "blocked" {
				t.Fatalf("blocked_variant %q of %q has kind %q, want blocked", b, v.Canonical, tgt.Kind)
			}
		}
	}
	// Every blocked verdict must be referenced by at least one ready verdict
	// (a blocked variant that is never applicable is dead state).
	refd := map[string]bool{}
	for _, v := range principalVerdicts {
		for _, b := range v.BlockedVariants {
			refd[b] = true
		}
	}
	for _, v := range principalVerdicts {
		if v.Kind == "blocked" && !refd[v.Canonical] {
			t.Fatalf("blocked verdict %q is never referenced as a blocked_variant", v.Canonical)
		}
	}
}

func TestPrincipalVerdictExpiryIncludesEvidenceInvalidation(t *testing.T) {
	// FB-34 criterion: stale/missing evidence invalidation. Every verdict
	// carries invalidation rules including evidence-generation-bound.
	for _, v := range principalVerdicts {
		if len(v.Expiry) == 0 {
			t.Fatalf("verdict %q has no expiry/invalidation rules", v.Canonical)
		}
		found := false
		for _, e := range v.Expiry {
			if e == "evidence-generation-bound" {
				found = true
			}
		}
		if !found {
			t.Fatalf("verdict %q expiry %v missing evidence-generation-bound", v.Canonical, v.Expiry)
		}
	}
}

func TestPrincipalVerdictNamesSorted(t *testing.T) {
	names := PrincipalVerdictNames()
	if !sort.StringsAreSorted(names) {
		t.Fatal("PrincipalVerdictNames() must be sorted (deterministic output)")
	}
	if len(names) != len(principalVerdicts) {
		t.Fatalf("PrincipalVerdictNames()=%d entries, registry=%d", len(names), len(principalVerdicts))
	}
}

func TestPrincipalVerdictSourceCoverage(t *testing.T) {
	// Every §142 principal verdict must be present (ARCH coverage), and the
	// superseded ARCH spellings must exist as aliases rather than canonical
	// names (FB18-07 precedence rule).
	for _, want := range []string{
		"CSI_PRODUCTION_READY", "GSO_RUNTIME_READY", "PASSIVE_RST_OBSERVE_READY",
		"PPE_BIDIRECTIONAL_VISIBILITY_READY", "SILENT_PATH_OBSERVATION_READY",
		"SILENT_PATH_RECOVERY_READY", "MON_PRODUCTION_READY",
		"ABD_MONITOR_ADAPTER_READY", "ABD_CLIENT_RESOLUTION_READY",
		"ABD_MULTI_VANTAGE_READY", "ABD_PRODUCTION_READY", "DDI_PRODUCTION_READY",
		"WARP_BASE_READY", "WARP_CAUSAL_TRACE_READY",
		"PROFILE_WARP_RECOMMENDATION_READY",
	} {
		if _, ok := PrincipalVerdictByCanonical(want); !ok {
			t.Fatalf("ARCH §142 principal verdict %q missing from registry", want)
		}
	}
	// Superseded ARCH spellings must resolve via alias mapping (migration).
	for _, alias := range []string{"GUIDED_DISCOVERY_READY", "TELEGRAM_BRIDGE_PRODUCTION_READY"} {
		if _, ok := PrincipalVerdictByCanonical(alias); ok {
			t.Fatalf("superseded ARCH spelling %q must not be a canonical name (FB18-07)", alias)
		}
		if _, ok := CanonicalVerdictName(alias); !ok {
			t.Fatalf("superseded ARCH spelling %q must resolve via alias mapping", alias)
		}
	}
	// §88 ADNS chain and §83 synthesis chain must be fully registered.
	for _, want := range []string{
		"ADNS_DETECTOR_READY", "ADNS_NATIVE_CLASSIC_READY", "ADNS_TCP_SEGMENT_EXPERIMENT_READY",
		"ADNS_NATIVE_ENCRYPTED_READY", "ADNS_MANAGED_BACKEND_READY", "ADNS_PROFILE_READY",
		"ADNS_FAILOVER_READY", "ADNS_ANDROID_CANARY_READY", "ADNS_PRODUCTION_READY",
		"BEHAVIORAL_FINGERPRINT_BOUNDED_READY", "CONSTRAINED_SYNTHESIS_READY",
		"SYNTHESIZED_DISCOVERY_READY", "AUTONOMOUS_DPI_ADAPTATION_READY",
	} {
		if _, ok := PrincipalVerdictByCanonical(want); !ok {
			t.Fatalf("verdict %q missing from registry", want)
		}
	}
}
