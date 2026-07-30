package nfq

// HardeningRuntimeStatus is a read-only snapshot for the local control plane.
// It contains no packet bytes, clear SNI, or private ClientHello material.
type HardeningRuntimeStatus struct {
	Capability       GSOCapabilityStatus       `json:"capability"`
	WorkerCapability []GSOCapabilityStatus     `json:"worker_capability,omitempty"`
	TokenStats       GSOPassTokenStats         `json:"token_stats"`
	ActiveTokens     int                       `json:"active_tokens"`
	PassiveRSTStats  PassiveRSTStoreStats      `json:"passive_rst_stats"`
	RecentRST        []PassiveRSTEvidence      `json:"recent_rst,omitempty"`
	RecentRollbacks  []PassiveRSTRollbackState `json:"recent_rollbacks,omitempty"`
}

func (p *Pool) HardeningRuntimeStatus(limit int) HardeningRuntimeStatus {
	if limit <= 0 {
		limit = 32
	}
	out := HardeningRuntimeStatus{Capability: GSOCapabilityStatus{Level: GSOCapabilityUnsupported, Reason: "NFQUEUE pool unavailable"}}
	if p == nil {
		return out
	}
	out.WorkerCapability = make([]GSOCapabilityStatus, 0, len(p.Workers))
	for _, worker := range p.Workers {
		if worker == nil {
			continue
		}
		status := worker.GSOCapabilityStatus()
		out.WorkerCapability = append(out.WorkerCapability, status)
		if len(out.WorkerCapability) == 1 || gsoCapabilityRank(status.Level) < gsoCapabilityRank(out.Capability.Level) {
			out.Capability = status
		}
	}
	if p.state == nil {
		return out
	}
	if p.state.gsoPassTokens != nil {
		out.TokenStats = p.state.gsoPassTokens.Stats()
		out.ActiveTokens = p.state.gsoPassTokens.Len()
	}
	if p.state.passiveRST != nil {
		out.PassiveRSTStats = p.state.passiveRST.Stats()
		out.RecentRST = p.state.passiveRST.Recent(limit)
		out.RecentRollbacks = p.state.passiveRST.RecentRollbacks(limit)
	}
	return out
}

func gsoCapabilityRank(level GSOCapabilityLevel) int {
	switch level {
	case GSOCapabilityFailed:
		return 0
	case GSOCapabilityUnsupported:
		return 1
	case GSOCapabilitySupportedUnvalidated:
		return 2
	case GSOCapabilityObserveOnly:
		return 3
	case GSOCapabilityClassifyReady:
		return 4
	case GSOCapabilityFullActionReady:
		return 5
	default:
		return 0
	}
}
