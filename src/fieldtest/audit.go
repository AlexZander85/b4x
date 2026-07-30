package fieldtest

type AuthorizationRecord struct {
	FlowID, Role, SetID, ComponentID, EvidenceSource, AuthorizationResult, ActionType, Owner string
	ConfigGeneration                                                                         uint64
}

func Audit(records []AuthorizationRecord) AuthorizationAudit {
	a := AuthorizationAudit{}
	for _, r := range records {
		if r.Role == string(TargetRole) {
			a.TargetFlowCount++
			if r.ActionType != "" {
				a.TargetActions++
			}
		} else if r.Role == string(ControlRole) {
			a.ControlFlowCount++
			if r.ActionType != "" {
				a.UnrelatedControlActionTotal++
				a.Violations = append(a.Violations, AuditViolation{FlowID: r.FlowID, Role: r.Role, ComponentID: r.ComponentID, EvidenceSource: r.EvidenceSource, AuthorizationResult: r.AuthorizationResult, ActionType: r.ActionType, ConfigGeneration: r.ConfigGeneration})
			}
		}
	}
	return a
}
