package validation

var WARPTraceRequirements = []string{"WARP-1", "WARP-2", "WARP-3", "WARP-4", "WARP-5", "WARP-6", "WARP-7", "WARP-8", "WARP-9", "WARP-10", "WARP-C1", "WARP-C2", "WARP-C3", "WARP-C4", "WARP-C5", "WARP-C6", "WARP-C7", "WARP-C8", "WARP-C9", "WARP-C10", "FT-AC", "FT-AD", "FT-AE"}

type TraceEnvelopeCheck struct {
	Schema, Compatibility, CommonFields, GenerationFields, ParentLinks, MonotonicOrder, RuntimeConsistency, RequiredDurability, Redaction bool
	Missing, Duplicate, Reordered, OldGeneration, Impossible, RuntimeMismatch, RequiredDropped                                            int
}

func (c TraceEnvelopeCheck) Ready() bool {
	return c.Schema && c.Compatibility && c.CommonFields && c.GenerationFields && c.ParentLinks && c.MonotonicOrder && c.RuntimeConsistency && c.RequiredDurability && c.Redaction && c.Missing == 0 && c.Duplicate == 0 && c.Reordered == 0 && c.OldGeneration == 0 && c.Impossible == 0 && c.RuntimeMismatch == 0 && c.RequiredDropped == 0
}

type WARPTraceValidation struct {
	Requirements, TestIDs, Artifacts                                                                          []string
	Envelope                                                                                                  TraceEnvelopeCheck
	PathProof, ForwardedCorrelation, NestedDependency, GeoQuorum, DNSIPv6, CleanupOwnership, CamouflageCutoff bool
	KeeneticCounters, AndroidEvidence                                                                         bool
	MutantsDetected                                                                                           int
	HardGateViolations                                                                                        []string
}

func (w WARPTraceValidation) Ready() bool {
	if len(w.Requirements) != len(WARPTraceRequirements) || len(w.TestIDs) == 0 || len(w.Artifacts) < 7 || !w.Envelope.Ready() || !w.PathProof || !w.ForwardedCorrelation || !w.NestedDependency || !w.GeoQuorum || !w.DNSIPv6 || !w.CleanupOwnership || !w.CamouflageCutoff || !w.KeeneticCounters || !w.AndroidEvidence || w.MutantsDetected < 1 || len(w.HardGateViolations) > 0 {
		return false
	}
	return true
}
func (w WARPTraceValidation) Verdict() Verdict {
	if w.Ready() {
		return Pass
	}
	return Blocked
}
