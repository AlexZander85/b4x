package discovery

import (
	"errors"
	"strings"
)

type PassiveRSTVariant string

const (
	PassiveRSTVariantDirect       PassiveRSTVariant = "direct"
	PassiveRSTVariantProduction   PassiveRSTVariant = "production"
	PassiveRSTVariantCandidate    PassiveRSTVariant = "candidate"
	PassiveRSTVariantObserve      PassiveRSTVariant = "candidate-passive-rst-observe"
	PassiveRSTVariantConservative PassiveRSTVariant = "candidate-passive-rst-conservative"
)

type PassiveRSTTrial struct {
	Variant          PassiveRSTVariant `json:"variant"`
	Environment      string            `json:"environment"`
	Samples          int               `json:"samples"`
	TransportSuccess int               `json:"transport_success"`
	ServerProgress   int               `json:"server_progress"`
	Suppressions     int               `json:"suppressions"`
	ReconnectFailure int               `json:"reconnect_failure"`
	ControlFailure   int               `json:"control_failure"`
}

type PassiveRSTComparison struct {
	Variant         PassiveRSTVariant `json:"variant"`
	Eligible        bool              `json:"eligible"`
	SuccessProof    bool              `json:"success_proof"`
	SuppressionOnly bool              `json:"suppression_only"`
	Reason          string            `json:"reason"`
}

// ComparePassiveRSTTrial enforces the Discovery contract: suppression is an
// observation, never an independent success proof or aggressive promotion.
func ComparePassiveRSTTrial(trial PassiveRSTTrial) (PassiveRSTComparison, error) {
	environment := strings.ToLower(strings.TrimSpace(trial.Environment))
	if environment != "candidate" && environment != "discovery" {
		return PassiveRSTComparison{}, errors.New("passive RST trial must remain in candidate/discovery isolation")
	}
	switch trial.Variant {
	case PassiveRSTVariantDirect, PassiveRSTVariantProduction, PassiveRSTVariantCandidate, PassiveRSTVariantObserve, PassiveRSTVariantConservative:
	default:
		return PassiveRSTComparison{}, errors.New("unsupported passive RST Discovery variant")
	}
	out := PassiveRSTComparison{Variant: trial.Variant}
	if trial.Samples <= 0 {
		out.Reason = "no bounded samples"
		return out, nil
	}
	if trial.ControlFailure > 0 || trial.ReconnectFailure > 0 {
		out.Reason = "control or reconnect regression"
		return out, nil
	}
	out.SuppressionOnly = trial.Suppressions > 0 && trial.TransportSuccess == 0 && trial.ServerProgress == 0
	if out.SuppressionOnly {
		out.Reason = "RST suppression alone is not success proof"
		return out, nil
	}
	out.SuccessProof = trial.TransportSuccess > 0 && trial.ServerProgress > 0
	out.Eligible = out.SuccessProof
	if out.Eligible {
		out.Reason = "transport and server progress independently confirmed"
	} else {
		out.Reason = "independent transport progress is incomplete"
	}
	return out, nil
}
