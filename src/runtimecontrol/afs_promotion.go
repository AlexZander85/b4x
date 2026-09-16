package runtimecontrol

import (
	"errors"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

// SynthesizedPromotionProof binds an AFS winner to the existing transactional
// runtime path. It is evidence/gating metadata only: runtimecontrol still owns
// the single Prepare -> Canary -> Promote/Rollback implementation.
type SynthesizedPromotionProof struct {
	CandidateID      string `json:"candidate_id"`
	ServiceProfileID string `json:"service_profile_id"`
	ComponentID      string `json:"component_id"`
	SourceClientRole string `json:"source_client_role"` // forwarded | router-origin

	CandidateConfigGeneration     uint64    `json:"candidate_config_generation"`
	CurrentConfigGeneration       uint64    `json:"current_config_generation"`
	ActionAuthorizationID         string    `json:"action_authorization_id"`
	AuthorizationConfigGeneration uint64    `json:"authorization_config_generation"`
	AuthorizationValidUntil       time.Time `json:"authorization_valid_until"`

	TargetEvidenceRefs     []string `json:"target_evidence_refs"`
	SameServiceControlRefs []string `json:"same_service_control_refs"`
	UnrelatedControlRefs   []string `json:"unrelated_control_refs"`

	RollbackReady          bool      `json:"rollback_ready"`
	CleanupReady           bool      `json:"cleanup_ready"`
	StableObservationReady bool      `json:"stable_observation_ready"`
	CheckedAt              time.Time `json:"checked_at"`
	ValidUntil             time.Time `json:"valid_until"`
}

func (p *SynthesizedPromotionProof) validatePrepare(now time.Time, canary CanarySpec) error {
	if p == nil {
		return nil
	}
	if now.IsZero() || p.CheckedAt.IsZero() || (!p.ValidUntil.IsZero() && !now.Before(p.ValidUntil)) {
		return errors.New("synthesized promotion proof is stale")
	}
	if strings.TrimSpace(p.CandidateID) == "" || strings.TrimSpace(p.ServiceProfileID) == "" || strings.TrimSpace(p.ComponentID) == "" {
		observability.RecordSynthesisViolation(observability.MetricSynthesisScopeEscape)
		return errors.New("synthesized promotion requires exact candidate/service/component scope")
	}
	if p.SourceClientRole != "forwarded" && p.SourceClientRole != "router-origin" {
		observability.RecordSynthesisViolation(observability.MetricSynthesisScopeEscape)
		return errors.New("synthesized promotion source client role is invalid")
	}
	if strings.TrimSpace(canary.SetID) != strings.TrimSpace(p.ServiceProfileID) {
		observability.RecordSynthesisViolation(observability.MetricSynthesisScopeEscape)
		return errors.New("synthesized promotion canary set does not match service profile")
	}
	if p.CandidateConfigGeneration == 0 || p.CurrentConfigGeneration == 0 || p.CandidateConfigGeneration != p.CurrentConfigGeneration {
		observability.RecordSynthesisViolation(observability.MetricSynthesisStaleGenerationUsed)
		return errors.New("synthesized promotion candidate generation is stale")
	}
	if strings.TrimSpace(p.ActionAuthorizationID) == "" || p.AuthorizationConfigGeneration == 0 || p.AuthorizationConfigGeneration != p.CurrentConfigGeneration || (!p.AuthorizationValidUntil.IsZero() && !now.Before(p.AuthorizationValidUntil)) {
		observability.RecordSynthesisViolation(observability.MetricSynthesisWithoutActionAuthorization)
		return errors.New("current ActionAuthorization proof is required for synthesized promotion")
	}
	if !hasEvidenceRefs(p.TargetEvidenceRefs) || !hasEvidenceRefs(p.SameServiceControlRefs) || !hasEvidenceRefs(p.UnrelatedControlRefs) {
		observability.RecordSynthesisViolation(observability.MetricSynthesisMissingMandatoryControl)
		return errors.New("target, same-service control and unrelated control proof are mandatory")
	}
	if !p.RollbackReady {
		observability.RecordSynthesisViolation(observability.MetricSynthesisPromotionWithoutRollbackReady)
		return errors.New("synthesized promotion requires rollback readiness")
	}
	if !p.CleanupReady {
		observability.RecordSynthesisViolation(observability.MetricSynthesisCleanupIncomplete)
		return errors.New("synthesized promotion requires cleanup readiness")
	}
	if !p.StableObservationReady {
		return errors.New("synthesized promotion requires a stable observation window")
	}
	return nil
}

func (p *SynthesizedPromotionProof) validatePromote(now time.Time, canary CanarySpec, outcome CanaryOutcome, rollbackStateReady bool) error {
	if p == nil {
		return nil
	}
	if err := p.validatePrepare(now, canary); err != nil {
		return err
	}
	if !rollbackStateReady {
		observability.RecordSynthesisViolation(observability.MetricSynthesisPromotionWithoutRollbackReady)
		return errors.New("transactional runtime has no active generation available for rollback")
	}
	// CanarySpec admits only ip:/mac: client groups. A passed outcome on this
	// same existing canary path is therefore the required forwarded-client
	// proof, including for router-origin discoveries.
	if !outcome.Passed || outcome.Samples == 0 {
		if p.SourceClientRole == "router-origin" {
			observability.RecordSynthesisViolation(observability.MetricSynthesisRouterOriginPromotedNoAndroid)
		}
		return errors.New("passed forwarded-client canary is required for synthesized promotion")
	}
	if p.SourceClientRole == "router-origin" && strings.TrimSpace(canary.ClientGroup) == "" {
		observability.RecordSynthesisViolation(observability.MetricSynthesisRouterOriginPromotedNoAndroid)
		return errors.New("router-origin synthesized winner lacks forwarded-client canary")
	}
	return nil
}

func hasEvidenceRefs(refs []string) bool {
	for _, ref := range refs {
		if strings.TrimSpace(ref) != "" {
			return true
		}
	}
	return false
}
