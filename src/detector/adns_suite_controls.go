package detector

import "strings"

// CanonicalSuiteWithControls builds the field-safe suite with two distinct
// controls. CONTROL_SAME must be a reviewed sibling of the target service;
// CONTROL_UNRELATED must be an unrelated known-positive domain. Keeping these
// names distinct prevents the historical bug where CONTROL_SAME was merely a
// duplicate of the target A probe and therefore proved nothing.
func CanonicalSuiteWithControls(target, sameServiceControl, unrelatedControl string) []ADNSSuiteCase {
	target = normalizeSuiteName(target)
	sameServiceControl = normalizeSuiteName(sameServiceControl)
	unrelatedControl = normalizeSuiteName(unrelatedControl)
	if sameServiceControl == "" || sameServiceControl == target {
		sameServiceControl = defaultSameServiceControl(target)
	}
	return []ADNSSuiteCase{
		{ID: "A", Name: target, QType: 1},
		{ID: "AAAA", Name: target, QType: 28},
		{ID: "CNAME", Name: target, QType: 5},
		{ID: "HTTPS", Name: target, QType: 65},
		{ID: "NXDOMAIN", Name: "nonexistent." + target, QType: 1},
		{ID: "CONTROL_SAME", Name: sameServiceControl, QType: 1},
		{ID: "CONTROL_UNRELATED", Name: unrelatedControl, QType: 1},
	}
}

func defaultSameServiceControl(target string) string {
	target = normalizeSuiteName(target)
	if target == "" {
		return ""
	}
	if strings.HasPrefix(target, "www.") && len(target) > len("www.") {
		return strings.TrimPrefix(target, "www.")
	}
	return "www." + target
}

func normalizeSuiteName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}
