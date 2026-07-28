package config

func (s classifierRuntimeValidation) validateFlowControls() {
	s.defaultInt(&s.r.Reassembly.MaxFlows, s.d.Reassembly.MaxFlows)
	s.defaultInt(&s.r.Reassembly.MaxBytesPerFlow, s.d.Reassembly.MaxBytesPerFlow)
	s.defaultInt(&s.r.Reassembly.MaxBytesTotal, s.d.Reassembly.MaxBytesTotal)
	s.defaultInt(&s.r.Reassembly.MaxSegments, s.d.Reassembly.MaxSegments)
	s.defaultInt(&s.r.Reassembly.MaxClientHello, s.d.Reassembly.MaxClientHello)
	s.defaultInt(&s.r.Reassembly.TimeoutMS, s.d.Reassembly.TimeoutMS)
	s.outOfRange("system.classifier.runtime.reassembly.max_flows", s.r.Reassembly.MaxFlows, 1, 16384)
	s.outOfRange("system.classifier.runtime.reassembly.max_bytes_per_flow", s.r.Reassembly.MaxBytesPerFlow, 2048, 64*1024)
	s.outOfRange("system.classifier.runtime.reassembly.max_bytes_total", s.r.Reassembly.MaxBytesTotal, s.r.Reassembly.MaxBytesPerFlow, 64*1024*1024)
	s.outOfRange("system.classifier.runtime.reassembly.max_segments", s.r.Reassembly.MaxSegments, 2, 256)
	s.outOfRange("system.classifier.runtime.reassembly.max_client_hello", s.r.Reassembly.MaxClientHello, 2048, 64*1024)
	s.outOfRange("system.classifier.runtime.reassembly.timeout_ms", s.r.Reassembly.TimeoutMS, 100, 30000)
	if s.r.Reassembly.MaxClientHello > s.r.Reassembly.MaxBytesPerFlow {
		s.v.add("system.classifier.runtime.reassembly.max_client_hello", "exceeds_flow_budget", "ClientHello cap must not exceed per-flow reassembly budget", nil)
	}

	s.defaultInt(&s.r.HoldReplay.MaxFlows, s.d.HoldReplay.MaxFlows)
	s.defaultInt(&s.r.HoldReplay.MaxPacketsPerFlow, s.d.HoldReplay.MaxPacketsPerFlow)
	s.defaultInt(&s.r.HoldReplay.MaxBytesTotal, s.d.HoldReplay.MaxBytesTotal)
	s.defaultInt(&s.r.HoldReplay.TimeoutMS, s.d.HoldReplay.TimeoutMS)
	s.outOfRange("system.classifier.runtime.hold_replay.max_flows", s.r.HoldReplay.MaxFlows, 1, 4096)
	s.outOfRange("system.classifier.runtime.hold_replay.max_packets_per_flow", s.r.HoldReplay.MaxPacketsPerFlow, 1, 64)
	s.outOfRange("system.classifier.runtime.hold_replay.max_bytes_total", s.r.HoldReplay.MaxBytesTotal, 4096, 16*1024*1024)
	s.outOfRange("system.classifier.runtime.hold_replay.timeout_ms", s.r.HoldReplay.TimeoutMS, 50, 5000)
	if !s.r.HoldReplay.ReleaseOnPressure {
		s.v.add("system.classifier.runtime.hold_replay.release_on_pressure", "fail_open_required", "hold/replay must release unchanged packets under pressure", nil)
	}

	s.defaultInt(&s.r.Actions.MaxWritesPerHello, s.d.Actions.MaxWritesPerHello)
	s.defaultInt(&s.r.Actions.MaxFakeBytes, s.d.Actions.MaxFakeBytes)
	if s.r.Actions.MaxAmplification <= 0 {
		s.r.Actions.MaxAmplification = s.d.Actions.MaxAmplification
	}
	s.outOfRange("system.classifier.runtime.actions.max_writes_per_hello", s.r.Actions.MaxWritesPerHello, 1, 128)
	s.outOfRange("system.classifier.runtime.actions.max_fake_bytes", s.r.Actions.MaxFakeBytes, 1, 1024*1024)
	if s.r.Actions.MaxAmplification < 1 || s.r.Actions.MaxAmplification > 16 {
		s.v.add("system.classifier.runtime.actions.max_amplification", "out_of_range", "amplification must be in [1,16]", map[string]any{"min": 1, "max": 16})
	}
}
