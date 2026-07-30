package fieldtest

import "errors"

type CapabilityValue struct {
	Supported                                                      bool
	State, Version, Hash, ValidatedAt, DegradedReason, TargetScope string
}
type Capabilities struct {
	Commit                                                        string
	APIVersions                                                   []string
	NFQueue, CaptureEnvelope, OffloadVisibility, PCAP, AndroidAPI bool
	SandboxCapacity                                               int
	ResourceBudget                                                map[string]float64
	Transports                                                    []string
	Features                                                      map[string]CapabilityValue
}

func (c Capabilities) Allows(name string) bool {
	v, ok := c.Features[name]
	return ok && v.Supported && v.State != "" && v.DegradedReason == "" && v.ValidatedAt != ""
}

type DiscoveryRunRequest struct {
	TargetClientID, Mode, Profile, PromotionMode string
	Variants                                     map[string][]string
	Controls                                     []string
	RequireZeroUnrelatedActions                  bool
	RunsQuick, RunsValidate, RunsPromote         int
}
type DiscoveryRun struct {
	RunID     string
	Request   DiscoveryRunRequest
	Status    string
	ReportURL string
}

func ValidateDiscoveryRequest(r DiscoveryRunRequest) error {
	if r.TargetClientID == "" || r.Mode == "" || r.Profile == "" {
		return errors.New("discovery request requires target and profile")
	}
	if r.PromotionMode == "full-auto" {
		return errors.New("full-auto requires explicit protected scope")
	}
	if r.RunsQuick < 0 || r.RunsValidate < 0 || r.RunsPromote < 0 {
		return errors.New("run counts cannot be negative")
	}
	return nil
}

type AuthorizationAudit struct {
	TargetFlowCount, ControlFlowCount, TargetActions, UnrelatedControlActionTotal, DestinationOnlyStateTotal, NegativeSNIFailures int
	Violations                                                                                                                    []AuditViolation
}
type AuditViolation struct {
	FlowID, ClientID, Role, ComponentID, EvidenceSource, AuthorizationResult, ActionType string
	ConfigGeneration                                                                     uint64
}

func (a AuthorizationAudit) Clean() bool {
	return a.UnrelatedControlActionTotal == 0 && a.DestinationOnlyStateTotal == 0 && a.NegativeSNIFailures == 0 && len(a.Violations) == 0
}
