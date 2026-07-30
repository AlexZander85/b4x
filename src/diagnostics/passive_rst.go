package diagnostics

import (
	"net/netip"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/observability"
)

type PassiveRSTSignalDetail struct {
	Signal   string `json:"signal"`
	Strength string `json:"strength"`
	Reason   string `json:"reason,omitempty"`
}

type PassiveRSTWindowDetail struct {
	Reliable bool `json:"reliable"`
	InWindow bool `json:"in_window"`
}

type PassiveRSTFailureDetails struct {
	FlowID                string                   `json:"flow_id"`
	SetID                 string                   `json:"set_id,omitempty"`
	DeviceScope           string                   `json:"device_scope,omitempty"`
	ConfigGeneration      uint64                   `json:"config_generation"`
	TCPPhase              string                   `json:"tcp_phase"`
	ServerPayloadProgress bool                     `json:"server_payload_progress"`
	Signals               []PassiveRSTSignalDetail `json:"signals,omitempty"`
	BaselineQuality       string                   `json:"baseline_quality"`
	BaselineSpread        uint8                    `json:"baseline_spread"`
	Sequence              PassiveRSTWindowDetail   `json:"sequence"`
	Acknowledgment        PassiveRSTWindowDetail   `json:"acknowledgment"`
	OptionFingerprint     string                   `json:"option_fingerprint"`
	Decision              string                   `json:"decision"`
	RequestedMode         string                   `json:"requested_mode"`
	EffectiveMode         string                   `json:"effective_mode"`
	PostDecisionOutcome   string                   `json:"post_decision_outcome"`
	OutcomeObservedAt     time.Time                `json:"outcome_observed_at,omitempty"`
}

func normalizePassiveRSTFailure(in *PassiveRSTFailureDetails) *PassiveRSTFailureDetails {
	if in == nil {
		return nil
	}
	out := *in
	out.FlowID = observability.RedactIdentifier(strings.TrimSpace(in.FlowID))
	out.SetID = observability.RedactIdentifier(strings.TrimSpace(in.SetID))
	out.DeviceScope = observability.RedactIdentifier(strings.TrimSpace(in.DeviceScope))
	out.TCPPhase = limitPassiveRSTText(in.TCPPhase, 48)
	out.BaselineQuality = limitPassiveRSTText(in.BaselineQuality, 48)
	out.OptionFingerprint = limitPassiveRSTText(in.OptionFingerprint, 48)
	out.Decision = limitPassiveRSTText(in.Decision, 32)
	out.RequestedMode = limitPassiveRSTText(in.RequestedMode, 32)
	out.EffectiveMode = limitPassiveRSTText(in.EffectiveMode, 32)
	out.PostDecisionOutcome = limitPassiveRSTText(in.PostDecisionOutcome, 48)
	if out.PostDecisionOutcome == "" {
		out.PostDecisionOutcome = "pending"
	}
	if len(in.Signals) > 16 {
		in.Signals = in.Signals[:16]
	}
	out.Signals = make([]PassiveRSTSignalDetail, 0, len(in.Signals))
	for _, signal := range in.Signals {
		out.Signals = append(out.Signals, PassiveRSTSignalDetail{
			Signal: limitPassiveRSTText(signal.Signal, 64), Strength: limitPassiveRSTText(signal.Strength, 32), Reason: limitPassiveRSTText(signal.Reason, 128),
		})
	}
	return &out
}

func clonePassiveRSTFailure(in *PassiveRSTFailureDetails) *PassiveRSTFailureDetails {
	if in == nil {
		return nil
	}
	out := *in
	out.Signals = append([]PassiveRSTSignalDetail(nil), in.Signals...)
	return &out
}

func limitPassiveRSTText(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		value = value[:max]
	}
	return value
}

// UpdatePassiveRSTOutcome adds causal follow-up without converting a
// suppression into a success verdict. Candidate expiry remains absolute.
func (i *FailureInbox) UpdatePassiveRSTOutcome(client classifier.ClientKey, destinationIP string, destinationPort uint16, protocol uint8, outcome string, observedAt time.Time) bool {
	if i == nil || client.IsZero() || destinationPort == 0 {
		return false
	}
	addr, err := parseFailureAddr(destinationIP)
	if err != nil {
		return false
	}
	if observedAt.IsZero() || observedAt.After(i.clock.Now()) {
		observedAt = i.clock.Now()
	}
	key := failureKey{Client: normalizeClient(client), DestinationIP: addr, DestinationPort: destinationPort, Protocol: protocol}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.pruneLocked(observedAt)
	candidate := i.candidates[key]
	if candidate == nil || candidate.PassiveRST == nil {
		return false
	}
	candidate.PassiveRST.PostDecisionOutcome = limitPassiveRSTText(outcome, 48)
	candidate.PassiveRST.OutcomeObservedAt = observedAt
	candidate.LastSeen = observedAt
	return true
}

func parseFailureAddr(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap(), nil
}
