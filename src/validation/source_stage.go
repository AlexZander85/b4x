package validation

import "sort"

// FB-33 (b4x-yzt): Canonical Exact Source-Stage Registry.
//
// The single machine-readable registry of all normative requirements
// (specs/registries/source_stage_registry.yaml, generated into
// source_stage_registry.gen.go) supersedes the manual totals of
// B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md §23.1/§45/§58:
//
//	criteria_total = count(valid canonical registry entries)
//
// All totals are computed, never hard-coded; a declared total that differs
// from the computed total is a registry-integrity failure (FB-14 решения 6/7;
// CI fails on duplicate/orphan/missing hash/stage/dependency/verdict).

// CriteriaTotal returns the computed canonical criteria total
// (count of valid registry entries). This is the single source for every
// prose total: registry reports, CLI output and release summaries must use
// CriteriaTotal() instead of manual numbers.
func CriteriaTotal() int { return len(sourceStageRequirements) }

// SourceStageTotalsByCategory returns computed totals grouped by category
// (deterministic: sorted keys, stable order).
func SourceStageTotalsByCategory() map[string]int {
	out := map[string]int{}
	for _, r := range sourceStageRequirements {
		out[r.Category]++
	}
	return out
}

// SourceStageCategories returns the sorted category names present in the
// registry (deterministic output for reports/UI).
func SourceStageCategories() []string {
	seen := map[string]bool{}
	for _, r := range sourceStageRequirements {
		seen[r.Category] = true
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// SourceStageCoverage returns requirement IDs grouped by source document
// (deterministic). Used by the release bundle to prove "all normative
// documents covered" without delta lists being authoritative.
func SourceStageCoverageByDocument() map[string][]string {
	out := map[string][]string{}
	for _, r := range sourceStageRequirements {
		out[r.SourceDocument] = append(out[r.SourceDocument], r.RequirementID)
	}
	for _, ids := range out {
		sort.Strings(ids)
	}
	return out
}

// ValidateSourceStageRegistry runs the FB-33 registry-integrity checks over
// the generated registry. It never reads the YAML: the generated file is the
// only runtime reference, so this function is deterministic and safe to run
// inside `go test` (CI) without a repository checkout.
//
// Checks (FB-14 решение 7 / FB-33 criteria):
//   - duplicate:       every requirement ID is unique;
//   - orphan:          every dependency/suite reference resolves to a
//     registered requirement (no dangling references);
//   - missing hash:    every entry carries a 64-hex source SHA-256 and its
//     document is registered;
//   - stage/category/applicability: every entry has them (empty = error);
//   - dependency:      every dependency resolves (see orphan);
//   - verdict:         every verdict is a known principal-verdict family;
//   - totals:          declared total equals the computed criteria total.
func ValidateSourceStageRegistry() []string {
	var errs []string

	ids := make(map[string]bool, len(sourceStageRequirements))
	for _, r := range sourceStageRequirements {
		if ids[r.RequirementID] {
			errs = append(errs, "duplicate requirement_id "+r.RequirementID)
		}
		ids[r.RequirementID] = true

		if r.SourceDocument == "" {
			errs = append(errs, "missing source_document (req "+r.RequirementID+")")
		}
		if len(r.SourceSHA256) != 64 {
			errs = append(errs, "missing source_sha256 (req "+r.RequirementID+")")
		}
		if r.Section == "" {
			errs = append(errs, "missing section (req "+r.RequirementID+")")
		}
		if r.Stage == "" {
			errs = append(errs, "missing stage (req "+r.RequirementID+")")
		}
		if r.Category == "" {
			errs = append(errs, "missing category (req "+r.RequirementID+")")
		}
		if r.Applicability == "" {
			errs = append(errs, "missing applicability (req "+r.RequirementID+")")
		}

		for _, v := range r.Verdicts {
			if _, ok := knownVerdictFamilies[v]; !ok {
				errs = append(errs, "unknown verdict "+v+" (req "+r.RequirementID+")")
			}
		}
	}

	// Second pass: every dependency/suite reference must resolve to a
	// registered requirement (checked after the ID set is complete, so
	// forward references are valid).
	for _, r := range sourceStageRequirements {
		for _, d := range r.Dependencies {
			if !ids[d] {
				errs = append(errs, "missing dependency "+d+" (req "+r.RequirementID+")")
			}
		}
		for _, s := range r.Suites {
			if !ids[s] {
				errs = append(errs, "missing suite "+s+" (req "+r.RequirementID+")")
			}
		}
	}

	docNames := map[string]bool{}
	for _, d := range sourceStageDocuments {
		docNames[d.Name] = true
	}
	for _, r := range sourceStageRequirements {
		if r.SourceDocument != "" && !docNames[r.SourceDocument] {
			errs = append(errs, "orphan source_document "+r.SourceDocument+" (req "+r.RequirementID+")")
		}
	}

	if SourceStageDeclaredTotal != CriteriaTotal() {
		errs = append(errs, "declared_total != computed criteria_total")
	}
	return errs
}

// SourceStageRegistryValid is the boolean form of ValidateSourceStageRegistry
// (registry consistency PASS gate for meta-suite consumers).
func SourceStageRegistryValid() bool { return len(ValidateSourceStageRegistry()) == 0 }

// knownVerdictFamilies mirrors VERDICT_FAMILIES in the generator; a verdict
// not listed here is a registry-integrity failure (never silently accepted).
var knownVerdictFamilies = map[string]bool{
	"CSI": true, "RST_GSO": true, "PPE": true, "SPF": true, "MON": true,
	"ABD": true, "DDI": true, "TGB": true, "WARP": true, "SP": true, "FT": true,
}
