package validation

import (
	"errors"
	"fmt"
	"sort"
)

// FB-34 (b4x-xgc): Canonical Principal Verdict Registry.
//
// The single machine-readable source of truth for every principal verdict
// name (specs/registries/principal_verdicts.yaml, generated into
// principal_verdicts.gen.go) unifying ARCH §142, IV §52/§52.1, §83 and §88.
//
// Alias policy: aliases are compatibility metadata only — there is no
// separate state store. Runtime, API, UI and reports must use the canonical
// name; CanonicalVerdictName resolves any legacy/alias spelling to the
// canonical name (FB18-07 supersession mapping; e.g. GUIDED_DISCOVERY_READY
// -> DETECTOR_GUIDED_STRATEGY_SEARCH_READY,
// TELEGRAM_BRIDGE_PRODUCTION_READY -> TGB_PRODUCTION_READY).

// CanonicalVerdictName resolves a verdict spelling to its canonical name.
// Returns ("", false) for unknown names, so callers can fail closed instead
// of silently accepting a name that is not in the registry.
func CanonicalVerdictName(name string) (string, bool) {
	if _, ok := PrincipalVerdictByCanonical(name); ok {
		return name, true
	}
	for _, v := range principalVerdicts {
		for _, a := range v.Aliases {
			if a == name {
				return v.Canonical, true
			}
		}
	}
	return "", false
}

// VerdictDependencyClosure returns the transitive dependency closure of a
// canonical verdict name, topologically sorted (dependencies first), with the
// verdict itself appended last. Aggregation follows the ARCH graph encoded in
// the registry (FB-34 criterion: dependency aggregation follows ARCH graph).
//
// Returns an error for an unknown name or a cyclic dependency graph, so
// consumers can fail closed instead of aggregating a partial set.
func VerdictDependencyClosure(canonical string) ([]string, error) {
	byName := map[string]PrincipalVerdict{}
	for _, v := range principalVerdicts {
		byName[v.Canonical] = v
	}
	if _, ok := byName[canonical]; !ok {
		return nil, fmt.Errorf("unknown principal verdict %q", canonical)
	}

	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var order []string

	var visit func(n string) error
	visit = func(n string) error {
		color[n] = gray
		for _, d := range byName[n].Dependencies {
			if _, ok := byName[d]; !ok {
				return fmt.Errorf("dependency %q of %q is not a registered principal verdict", d, n)
			}
			switch color[d] {
			case gray:
				return fmt.Errorf("cyclic dependency graph involving %q", d)
			case white:
				if err := visit(d); err != nil {
					return err
				}
			}
		}
		color[n] = black
		order = append(order, n)
		return nil
	}

	if err := visit(canonical); err != nil {
		return nil, err
	}
	return order, nil
}

// ValidatePrincipalVerdictRegistry runs the FB-34 registry-integrity checks
// over the generated registry. It never reads the YAML: the generated file is
// the only runtime reference, so this function is deterministic and safe to
// run inside `go test` (CI) without a repository checkout.
//
// Checks (FB-34 criteria):
//   - duplicate:      every canonical name is unique;
//   - alias:          aliases are unique and never collide with a canonical
//     name (no ambiguous resolution);
//   - blocked:        every blocked_variants reference resolves to a
//     kind=blocked entry (blocked != PASS_WITH_LIMITATIONS);
//   - dependency:     every dependency resolves to a registered verdict and
//     the dependency graph is acyclic (aggregation follows ARCH graph);
//   - gates/evidence: required gate references use family:<name> form;
//   - expiry:         every entry carries invalidation rules, including
//     evidence-generation-bound (stale/missing evidence invalidation);
//   - totals:         declared total equals the computed total.
func ValidatePrincipalVerdictRegistry() []string {
	var errs []string

	byName := map[string]PrincipalVerdict{}
	for _, v := range principalVerdicts {
		if _, dup := byName[v.Canonical]; dup {
			errs = append(errs, "duplicate canonical "+v.Canonical)
		}
		byName[v.Canonical] = v

		if v.Canonical == "" {
			errs = append(errs, "missing canonical name")
		}
		if v.Kind != "ready" && v.Kind != "blocked" {
			errs = append(errs, "unknown kind "+v.Kind+" ("+v.Canonical+")")
		}
		if v.OwnerFamily == "" {
			errs = append(errs, "missing owner_family ("+v.Canonical+")")
		}
		if v.DependencyExpression == "" {
			errs = append(errs, "missing dependency_expression ("+v.Canonical+")")
		}
		if len(v.Expiry) == 0 {
			errs = append(errs, "missing expiry (invalidation rules) ("+v.Canonical+")")
		} else if !containsString(v.Expiry, "evidence-generation-bound") {
			errs = append(errs, "expiry must include evidence-generation-bound ("+v.Canonical+")")
		}
		for _, g := range v.RequiredGates {
			if len(g) < 7 || g[:7] != "family:" {
				errs = append(errs, "required_gates must use family:<name> form, got "+g+" ("+v.Canonical+")")
			}
		}
	}

	// Alias pass: uniqueness and no canonical collision.
	seenAliases := map[string]bool{}
	for _, v := range principalVerdicts {
		for _, a := range v.Aliases {
			if a == "" {
				errs = append(errs, "empty alias ("+v.Canonical+")")
				continue
			}
			if _, isCanonical := byName[a]; isCanonical {
				errs = append(errs, "alias collides with canonical name "+a+" ("+v.Canonical+")")
			}
			if seenAliases[a] {
				errs = append(errs, "duplicate alias "+a+" ("+v.Canonical+")")
			}
			seenAliases[a] = true
		}
	}

	// Dependency pass: all references resolve and the graph is acyclic.
	for _, v := range principalVerdicts {
		for _, d := range v.Dependencies {
			if _, ok := byName[d]; !ok {
				errs = append(errs, "unknown dependency "+d+" ("+v.Canonical+")")
			}
		}
		for _, b := range v.BlockedVariants {
			t, ok := byName[b]
			if !ok {
				errs = append(errs, "unknown blocked_variant "+b+" ("+v.Canonical+")")
			} else if t.Kind != "blocked" {
				errs = append(errs, "blocked_variant "+b+" does not reference kind=blocked entry ("+v.Canonical+")")
			}
		}
	}
	for _, v := range principalVerdicts {
		if _, err := VerdictDependencyClosure(v.Canonical); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if PrincipalVerdictDeclaredTotal != len(principalVerdicts) {
		errs = append(errs, "declared_total != computed verdict total")
	}
	return errs
}

// PrincipalVerdictRegistryValid is the boolean form of
// ValidatePrincipalVerdictRegistry (registry consistency PASS gate).
func PrincipalVerdictRegistryValid() bool { return len(ValidatePrincipalVerdictRegistry()) == 0 }

// PrincipalVerdictNames returns all canonical names, sorted (deterministic
// output for reports/UI).
func PrincipalVerdictNames() []string {
	out := make([]string, 0, len(principalVerdicts))
	for _, v := range principalVerdicts {
		out = append(out, v.Canonical)
	}
	sort.Strings(out)
	return out
}

// PrincipalVerdictAliases returns the alias list of a canonical verdict.
func PrincipalVerdictAliases(canonical string) []string {
	if v, ok := PrincipalVerdictByCanonical(canonical); ok {
		return v.Aliases
	}
	return nil
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// VerifyPrincipalVerdictNames fails closed on unregistered runtime verdict
// names (FB-34.1). Runtime, API, UI and report layers must emit verdict
// names only through the registry: the guard returns every input name that
// is neither a canonical name nor a registered alias, so consumers can
// reject an unregistered state name instead of silently emitting it.
// Returns nil when every name resolves.
func VerifyPrincipalVerdictNames(names []string) []string {
	var missing []string
	for _, n := range names {
		if _, ok := CanonicalVerdictName(n); !ok {
			missing = append(missing, n)
		}
	}
	return missing
}

// ErrUnknownPrincipalVerdict is returned by lookups that fail closed.
var ErrUnknownPrincipalVerdict = errors.New("unknown principal verdict")
