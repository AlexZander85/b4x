package serviceprofile

import (
	"errors"
	"sort"
	"strings"
)

type DetectorMode string

const (
	DetectorOff      DetectorMode = "off"
	DetectorQuick    DetectorMode = "quick"
	DetectorStandard DetectorMode = "standard"
	DetectorDeep     DetectorMode = "deep"
)

type DetectorTargetPlanSpec struct {
	ComponentID                                                                          string
	Primary, SameServiceControls, SameProviderControls, UnrelatedControls, CustomDomains []string
	Protocols                                                                            []string
	Mode                                                                                 DetectorMode
}
type DetectorPlan struct {
	ComponentID string
	Targets     []string
	Controls    []string
	Mode        DetectorMode
	SafetyHash  string
}

func CompileDetectorPlan(s DetectorTargetPlanSpec, trusted []string) (DetectorPlan, error) {
	if s.ComponentID == "" {
		return DetectorPlan{}, errors.New("component required")
	}
	if s.Mode == "" {
		s.Mode = DetectorQuick
	}
	if s.Mode != DetectorOff && s.Mode != DetectorQuick && s.Mode != DetectorStandard && s.Mode != DetectorDeep {
		return DetectorPlan{}, errors.New("invalid detector mode")
	}
	set := map[string]bool{}
	for _, v := range append(append(append(append([]string{}, s.Primary...), s.SameServiceControls...), s.SameProviderControls...), s.CustomDomains...) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			set[v] = true
		}
	}
	for _, v := range trusted {
		set[strings.ToLower(strings.TrimSpace(v))] = true
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	controls := append([]string{}, s.SameServiceControls...)
	controls = append(controls, s.SameProviderControls...)
	controls = append(controls, s.UnrelatedControls...)
	return DetectorPlan{ComponentID: s.ComponentID, Targets: out, Controls: controls, Mode: s.Mode, SafetyHash: strings.Join(out, "|")}, nil
}
