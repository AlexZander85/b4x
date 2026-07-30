package fieldtest

type DetectorFieldVerdict string

const (
	ABDTargetPlanReady      DetectorFieldVerdict = "ABD_TARGET_PLAN_READY"
	ABDCleanBaselineReady   DetectorFieldVerdict = "ABD_CLEAN_BASELINE_READY"
	ABDDNSEvidenceReady     DetectorFieldVerdict = "ABD_DNS_EVIDENCE_READY"
	ABDTLSEvidenceReady     DetectorFieldVerdict = "ABD_TLS_HTTP_EVIDENCE_READY"
	ABDQUICEvidenceReady    DetectorFieldVerdict = "ABD_QUIC_EVIDENCE_READY"
	ABDL4Ready              DetectorFieldVerdict = "ABD_L4_PROFILER_READY"
	ABDDynamicReady         DetectorFieldVerdict = "ABD_DYNAMIC_CONTROLS_READY"
	ABDEvidenceGraphReady   DetectorFieldVerdict = "ABD_EVIDENCE_GRAPH_READY"
	ABDBlockingProfileReady DetectorFieldVerdict = "ABD_BLOCKING_PROFILE_READY"
)

type DetectorMode string

const (
	DetectorQuick    DetectorMode = "quick"
	DetectorStandard DetectorMode = "standard"
	DetectorDeep     DetectorMode = "deep"
)

type TargetPlan struct {
	ComponentID               string
	Primary, Controls, Custom []string
	Mode                      DetectorMode
	Ownership                 string
	SafetyHash                string
}

func (p TargetPlan) Valid() bool {
	return p.ComponentID != "" && p.Mode != "" && p.Ownership != "" && p.SafetyHash != "" && len(p.Primary) > 0
}

type CleanBaseline struct {
	NetworkContextID, ConfigGeneration           string
	Visibility, NativeDirect, ControlsHealthy    bool
	DirtyState, ActiveWARP, IncompleteVisibility bool
}

func (b CleanBaseline) Ready() bool {
	return b.NetworkContextID != "" && b.ConfigGeneration != "" && b.Visibility && b.NativeDirect && b.ControlsHealthy && !b.DirtyState && !b.ActiveWARP && !b.IncompleteVisibility
}
