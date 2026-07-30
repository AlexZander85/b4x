package serviceprofile

import (
	"errors"
	"time"
)

type TransportRecommendationState string

const (
	RecommendationNotApplicable   TransportRecommendationState = "not-applicable"
	RecommendationUnavailable     TransportRecommendationState = "unavailable"
	RecommendationEligibleToTest  TransportRecommendationState = "eligible-to-test"
	RecommendationTesting         TransportRecommendationState = "testing"
	RecommendationValidated       TransportRecommendationState = "validated"
	RecommendationRejected        TransportRecommendationState = "rejected"
	RecommendationExpired         TransportRecommendationState = "expired"
	RecommendationBlockedBySafety TransportRecommendationState = "blocked-by-safety"
)

type TransportRecommendation struct {
	RecommendationID                                                                                                 string
	State                                                                                                            TransportRecommendationState
	ServiceProfileID, ComponentID, ClientScopeHash, SetID, BlockingProfileID, BlockingHypothesisID, NetworkContextID string
	EvidenceRefs, ContradictionRefs                                                                                  []string
	Confidence, ReasonCode                                                                                           string
	TransportKind, TransportMode, FailurePolicyPreview                                                               string
	RequiredCapabilities, MissingCapabilities                                                                        []string
	ValidationPlanID, ValidationResultID                                                                             string
	ConfigGen, SessionGen, RouteGen                                                                                  uint64
	CreatedAt, ExpiresAt                                                                                             time.Time
}

var supportedIPHypotheses = map[string]bool{"path_local_syn_filter_probable": true, "path_local_syn_filter_confirmed": true, "service_ip_filter_probable": true, "service_cidr_filter_probable": true, "multi_origin_direct_connect_failure_with_reference_success": true, "shared_transport_path_block_probable": true}

func CompileRecommendation(now time.Time, r TransportRecommendation) (TransportRecommendation, error) {
	if r.TransportKind != "cloudflare-warp-masque" || r.TransportMode != "base" {
		return TransportRecommendation{}, errors.New("only base builtin warp recommendation is supported")
	}
	if !supportedIPHypotheses[r.BlockingHypothesisID] {
		r.State = RecommendationNotApplicable
		return r, nil
	}
	if r.ClientScopeHash == "" || r.ComponentID == "" || r.NetworkContextID == "" || r.BlockingProfileID == "" || len(r.EvidenceRefs) < 2 {
		return TransportRecommendation{}, errors.New("fresh scoped independent evidence required")
	}
	if r.FailurePolicyPreview == "" {
		r.FailurePolicyPreview = "fail-open"
	}
	r.State = RecommendationEligibleToTest
	r.CreatedAt = now
	if r.ExpiresAt.IsZero() {
		r.ExpiresAt = now.Add(10 * time.Minute)
	}
	return r, nil
}
func (r TransportRecommendation) Fresh(now time.Time) bool {
	return r.State == RecommendationEligibleToTest && r.ExpiresAt.After(now) && r.ConfigGen > 0 && r.SessionGen > 0 && r.RouteGen > 0
}
