// MASQUE transport-camouflage gate trace types (addendum v1.2 SECT 73A
// transport camouflage hard gates, SECT C.4 camouflage phases and mandatory
// cutoff). The violated-branch producers live in masque_runtime.go; the
// remaining SECT 73A evaluations reuse the existing pure types
// (TransportControlAuthorization, TransportCamouflageAdapter, Candidate /
// CandidateResult, CoverSNIConfig, DialPolicy, RSTObservation).
package warp

import "time"

// MasqueCutoffTrace is the SECT C.4 hard-cutoff evaluation record: the
// active camouflage adapter, the accumulated packet/byte counts and the
// wall-clock deadline. A missing lifecycle event must never leave mutation
// enabled indefinitely, so mutation is a violation once any of the hard
// ceilings (max_packets / max_payload_bytes / max_duration) is exceeded.
type MasqueCutoffTrace struct {
	Adapter      TransportCamouflageAdapter
	PacketCount  int
	PayloadBytes int
	Deadline     time.Time
	Now          time.Time
}

// CeilingsExceeded reports whether any hard cutoff ceiling was exceeded.
func (t MasqueCutoffTrace) CeilingsExceeded() bool {
	return t.PacketCount > t.Adapter.Budget.MaxPackets ||
		t.PayloadBytes > t.Adapter.Budget.MaxBytes ||
		(!t.Deadline.IsZero() && !t.Now.Before(t.Deadline))
}