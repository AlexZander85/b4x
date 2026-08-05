package serviceprofile

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/validation"
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

// supportedIPHypothesis reports whether the blocking hypothesis is eligible
// to recommend WARP (FB-31, b4x-cka). The supported set is NOT hardcoded
// here: a hypothesis is supported exactly when the causal eligibility matrix
// maps it to a failure family that declares scoped-eligible-to-test
// transport (ip_cidr_route_block today). If the matrix is edited, the
// compiler follows it automatically and fails closed on unknown hypotheses.
func supportedIPHypothesis(h string) bool {
	family, ok := validation.CausalEligibilityFamilyForHypothesis(h)
	return ok && validation.TransportEligibleFamily(family)
}

func CompileRecommendation(now time.Time, r TransportRecommendation) (TransportRecommendation, error) {
	if r.TransportKind != "cloudflare-warp-masque" || r.TransportMode != "base" {
		return TransportRecommendation{}, errors.New("only base builtin warp recommendation is supported")
	}
	if !supportedIPHypothesis(r.BlockingHypothesisID) {
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

type RecommendationUX struct {
	State                                                              TransportRecommendationState
	ScopeText, DirectStatus, WARPStatus, ControlsStatus, FailurePolicy string
	PermanentRulesChanged                                              bool
	SetupRequired                                                      bool
	ForwardedCanaryRequired                                            bool
}
type RecommendationValidation struct {
	RecommendationID                                                                                            string
	DirectFailed, WARPReached, ControlsHealthy, PathProofCurrent, ForwardedCanaryPassed, LeaksAbsent, CleanedUp bool
	ResultID                                                                                                    string
}

func ValidateRecommendation(v RecommendationValidation) TransportRecommendationState {
	if !v.CleanedUp {
		return RecommendationBlockedBySafety
	}
	if v.DirectFailed && v.WARPReached && v.ControlsHealthy && v.PathProofCurrent && v.ForwardedCanaryPassed && v.LeaksAbsent {
		return RecommendationValidated
	}
	return RecommendationRejected
}

type RecommendationTransaction struct {
	Recommendation       TransportRecommendation
	Validation           RecommendationValidation
	TestToken            string
	ProductionAuthorized bool
	RolledBack           bool
}

func (t *RecommendationTransaction) BeginTest() error {
	if t.Recommendation.State != RecommendationEligibleToTest {
		return errors.New("recommendation is not eligible")
	}
	t.Recommendation.State = RecommendationTesting
	t.TestToken = t.Recommendation.RecommendationID + "/test"
	return nil
}
func (t *RecommendationTransaction) Finish(v RecommendationValidation) {
	t.Validation = v
	t.Recommendation.State = ValidateRecommendation(v)
	t.TestToken = ""
}
func (t *RecommendationTransaction) EnableAfterValidation() error {
	if t.Recommendation.State != RecommendationValidated {
		return errors.New("current scoped validation required")
	}
	t.ProductionAuthorized = true
	return nil
}

type RecommendationReleaseVerdict struct {
	State                                                                                    string
	ABDReferenceReady, ABDProductionReady, DDIProductionReady, WARPBaseReady, WARPTraceReady bool
	FieldTests                                                                               []string
	Umbrella                                                                                 []string
	HardGateViolations                                                                       []string
	SafetyHash                                                                               string
}

const ProfileWARPRecommendationReady = "PROFILE_WARP_RECOMMENDATION_READY"

func (v RecommendationReleaseVerdict) Ready() bool {
	return v.ABDReferenceReady && v.ABDProductionReady && v.DDIProductionReady && v.WARPBaseReady && v.WARPTraceReady && len(v.FieldTests) > 0 && len(v.Umbrella) > 0 && len(v.HardGateViolations) == 0 && v.SafetyHash != ""
}

type RecommendationMetrics struct{ RecommendedWithoutIP, DestinationIPOnly, OriginDead, UnhealthyControls, CrossService, StaleProfile, WithoutTrace, EnabledWithoutCanary, ReusedTestToken, IgnoredRegression, HiddenFailPolicy, NonRUSuggested, CamouflageSuggested int }
