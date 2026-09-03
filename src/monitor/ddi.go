package monitor

import (
	"errors"
	"time"
)

type DDIProfileRef struct {
	ProfileID          string
	Scope              MonitorScopeKey
	CreatedAt          time.Time
	ExpiresAt          time.Time
	NetworkContextID   string
	ConfigGeneration   uint64
	CompatibilityHash  string
	AuthoritativeRunID string
}

func (p DDIProfileRef) FreshCompatible(now time.Time, scope MonitorScopeKey, compatibilityHash string) bool {
	return p.ProfileID != "" && p.Scope == scope && p.NetworkContextID == scope.NetworkContextID && p.ConfigGeneration == scope.ConfigGeneration && p.CompatibilityHash == compatibilityHash && p.AuthoritativeRunID != "" && (p.ExpiresAt.IsZero() || now.Before(p.ExpiresAt))
}

type GuidedDiscoveryRequest struct {
	RequestID             string
	Scope                 MonitorScopeKey
	AuthoritativeABDRunID string
	DDI                   DDIProfileRef
	MandatoryBaselines    []string
	CompatibilityHash     string
	RequestedAt           time.Time
}

func (r GuidedDiscoveryRequest) Valid(now time.Time) bool {
	return r.RequestID != "" && r.Scope.Valid() && r.AuthoritativeABDRunID != "" && r.DDI.FreshCompatible(now, r.Scope, r.CompatibilityHash) && len(r.MandatoryBaselines) > 0
}

type PathEvidence struct {
	EvidenceID string
	IPHash     string
	PathKind   string
	ObservedAt time.Time
	Success    bool
}

type TransportRecommendation struct {
	RecommendationID string
	Scope            MonitorScopeKey
	DDIProfileID     string
	CandidateID      string
	PathEvidence     []PathEvidence
	Explanation      string
	CreatedAt        time.Time
}

func (r TransportRecommendation) Valid() bool {
	if r.RecommendationID == "" || !r.Scope.Valid() || r.DDIProfileID == "" || r.CandidateID == "" || len(r.PathEvidence) == 0 {
		return false
	}
	for _, e := range r.PathEvidence {
		if e.EvidenceID == "" || e.IPHash == "" || e.PathKind == "" || e.ObservedAt.IsZero() {
			return false
		}
	}
	return true
}

var ErrDiscoveryNotReady = errors.New("discovery prerequisites are not ready")

func BuildGuidedDiscovery(now time.Time, req GuidedDiscoveryRequest) (GuidedDiscoveryRequest, error) {
	if !req.Valid(now) {
		return GuidedDiscoveryRequest{}, ErrDiscoveryNotReady
	}
	return req, nil
}

func BuildTransportRecommendation(now time.Time, scope MonitorScopeKey, ddi DDIProfileRef, candidateID, explanation string, evidence []PathEvidence) (TransportRecommendation, error) {
	r := TransportRecommendation{RecommendationID: candidateID + "/" + now.UTC().Format("20060102T150405.000000000Z"), Scope: scope, DDIProfileID: ddi.ProfileID, CandidateID: candidateID, PathEvidence: append([]PathEvidence(nil), evidence...), Explanation: explanation, CreatedAt: now}
	if !r.Valid() {
		return TransportRecommendation{}, errors.New("recommendation requires scoped DDI and IP path evidence")
	}
	return r, nil
}
