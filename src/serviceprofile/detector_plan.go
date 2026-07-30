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

type DetectorCapabilities struct {
	DNS, TLS12, TLS13, QUIC, L4, CleanPath, CaptureVisibility bool
	ResourceDowngrade, PrivacyDowngrade                       string
}
type EvidenceView struct {
	Hypothesis, Confidence, NetworkContextID, Age string
	Contradictions, Suppressors, EvidenceFamilies []string
	Redacted                                      bool
}

func (v EvidenceView) Valid() bool {
	return v.Hypothesis != "" && v.Confidence != "" && v.NetworkContextID != "" && v.Redacted
}

type GuidedPlan struct {
	MandatoryBaselines, GuidedCandidates []string
	FullFallbackLimit, TargetControls    int
	EstimatedSeconds                     int
	FallbackUsed                         bool
	QualityDelta                         float64
	Canary, Promoted, RolledBack         bool
}

func (g GuidedPlan) TruthfulSavings() bool {
	return !g.FallbackUsed && g.QualityDelta >= 0 && len(g.MandatoryBaselines) > 0
}

type TelegramBridgePolicy struct {
	Enabled                                    bool
	FirstBytePolicy, OverflowPolicy            string
	FailOpen                                   bool
	SoftDeadlineMS, HardDeadlineMS, MaxPending int
}

func (p TelegramBridgePolicy) Valid() bool {
	return p.SoftDeadlineMS > 0 && p.HardDeadlineMS > p.SoftDeadlineMS && p.MaxPending > 0 && (p.OverflowPolicy == "worker-failopen" || p.OverflowPolicy == "fallback")
}

type TelegramBridgeStatus struct {
	Pending, Overflow, Fallback       int
	PrefixPreserved, AndroidValidated bool
	DegradedReason                    string
}
type PackReleaseVerdict struct {
	ProfileID, ABD, DDI, TGB, SafetyHash string
	Ready                                bool
	Reason                               string
}

func (v PackReleaseVerdict) Valid() bool {
	return v.ProfileID != "" && v.SafetyHash != "" && v.ABD != "" && v.DDI != "" && v.TGB != ""
}

func (c DetectorCapabilities) Effective(m DetectorMode) DetectorMode {
	if !c.CleanPath || !c.CaptureVisibility {
		return DetectorOff
	}
	if m == DetectorDeep && (!c.QUIC || c.ResourceDowngrade != "") {
		return DetectorStandard
	}
	return m
}
