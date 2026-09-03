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

type ProtocolEvidence struct {
	DNSConsensus, DNSSpoof, TLS12, TLS13, HTTP, QUIC, TCPComparison, L4, MultipleOrigins, ControlsHealthy bool
	WirePackets, UniqueBytes                                                                              uint64
	RetransmissionNonProgress                                                                             bool
}
type DynamicEvidence struct {
	ProviderID, CacheKey, ContentHash, NetworkContextID                          string
	Fresh, OwnershipValidated, Immutable, PrivacyRedacted, NoActionAuthorization bool
	Families                                                                     int
	Contradiction                                                                bool
}
type GuidedABResult struct {
	ProfileID, PriorHash, BaselineWinner, GuidedWinner, FullWinner string
	GuidedWallMS, FullWallMS                                       int64
	GuidedProbes, FullProbes                                       int
	QualityDelta, Tolerance                                        float64
	Revalidated, ControlsValidated, ActionAuthorized               bool
}

func (r GuidedABResult) Ready() bool {
	return r.ProfileID != "" && r.PriorHash != "" && r.BaselineWinner != "" && r.GuidedWinner != "" && r.FullWinner != "" && r.Revalidated && r.ControlsValidated && r.ActionAuthorized && r.QualityDelta >= -r.Tolerance
}

func (e DynamicEvidence) Ready() bool {
	return e.ProviderID != "" && e.CacheKey != "" && e.ContentHash != "" && e.NetworkContextID != "" && e.Fresh && e.OwnershipValidated && e.Immutable && e.PrivacyRedacted && e.NoActionAuthorization && e.Families >= 2 && !e.Contradiction
}

func (e ProtocolEvidence) Ready() bool {
	return e.DNSConsensus && e.TLS12 && e.TLS13 && e.HTTP && e.QUIC && e.TCPComparison && e.L4 && e.MultipleOrigins && e.ControlsHealthy && !e.DNSSpoof && !e.RetransmissionNonProgress
}
