package fieldtest

var RequiredHardGates = []string{"detector_single_probe_confirmed_total", "detector_exception_string_only_confirmed_total", "detector_static_target_only_high_confidence_total", "detector_self_interference_total", "detector_control_failure_ignored_total", "detector_unverified_mitm_verdict_total", "detector_quic_single_target_global_udp_verdict_total", "unrelated_control_action_total", "destination_only_state_total", "route_counter_missing_total", "forwarded_binding_missing_total", "stale_generation_event_total", "parent_generation_mismatch_total", "dns_direct_leak_total", "ipv6_unvalidated_egress_total", "cleanup_foreign_resource_removed_total", "trace_required_event_drop_total"}

func HardGatesPass(counters map[string]uint64, produced map[string]bool) bool {
	for _, name := range RequiredHardGates {
		if !produced[name] || counters[name] != 0 {
			return false
		}
	}
	return true
}

type StageReport struct {
	Stage, Verdict, SourceAddendumHash string
	Requirements                       []string
	HardGates                          []string
	AutomatedTests                     []string
	FieldEvidenceRequired              []string
}

func (r StageReport) Valid() bool {
	return r.Stage != "" && r.Verdict != "" && r.SourceAddendumHash != "" && len(r.Requirements) > 0 && len(r.HardGates) > 0
}
