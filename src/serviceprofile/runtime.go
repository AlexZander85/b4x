// Package serviceprofile runtime — production controller of the WARP
// recommendation lifecycle (FB-02 sp section, §28A.11).
//
// src/serviceprofile is a pure library of recommendation primitives
// (compiler, ownership, preview diff, transactional apply/rollback,
// capability projection, WARP recommendation state machine) with no
// observability. This file is the production layer: it owns the
// recommendation lifecycle state machine (compile -> begin-test -> validate
// -> enable / promote) and calls the fourteen §28A.11 hard-gate guards on
// the violating branch of each real check. The violating branches are the
// production violation paths: a count != 0 in a validation window is a
// genuine WARP-recommendation violation, not synthetic telemetry.
//
// The runtime is a controller loop: Start() launches the worker, Stop()
// shuts it down, Submit() feeds bounded lifecycle events from the future
// HTTP/CLI/control-plane callers. The direct methods (Compile, Validate,
// BeginTest, Enable, ValidatePolicy, Promote) are the same handlers the
// loop dispatches to, so integration tests enter through the same
// production roots as the daemon.
package serviceprofile

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// RuntimeConfig is the production tuning of the recommendation lifecycle
// controller.
type RuntimeConfig struct {
	BusCapacity int
}

// DefaultConfig returns the production runtime defaults.
func DefaultConfig() RuntimeConfig {
	return RuntimeConfig{BusCapacity: 64}
}

// LifecycleEventKind is the kind of a lifecycle control event dispatched to
// the runtime loop.
type LifecycleEventKind string

const (
	EventCompile        LifecycleEventKind = "compile"
	EventValidate       LifecycleEventKind = "validate"
	EventBeginTest      LifecycleEventKind = "begin-test"
	EventEnable         LifecycleEventKind = "enable"
	EventValidatePolicy LifecycleEventKind = "validate-policy"
	EventPromote        LifecycleEventKind = "promote"
)

// LifecycleEvent is one bounded control-plane event for the runtime loop.
// Every field is the exact argument set of the corresponding handler;
// unused fields are zero values.
type LifecycleEvent struct {
	Kind            LifecycleEventKind
	Now             time.Time
	Recommendation  TransportRecommendation
	Validation      RecommendationValidation
	Regression      bool
	Projection      WARPProjection
	Camouflage      CamouflagePolicy
	NonRU           NonRUPolicy
	Health          WARPHealth
	TargetCanary    bool
	Controls        bool
	IPPathEvidence  bool
	OriginAlive     bool
	ControlsHealthy bool
	ConsumerService string
	IPBlockTarget   bool
	// EvidenceAuthority is the FB-30 authority level of the evidence behind
	// the recommendation (passive-monitoring, provisional-fast,
	// authoritative-abd, android-canary). The causal eligibility gate
	// (FB-31) requires authoritative-abd or above for scoped transport.
	EvidenceAuthority string
}

// recommendationState is the per-recommendation lifecycle state of the
// controller.
type recommendationState struct {
	recommendation TransportRecommendation
	transaction    *RecommendationTransaction
}

// Runtime owns the production WARP-recommendation lifecycle state and the
// fourteen §28A.11 hard-gate producers.
type Runtime struct {
	cfg RuntimeConfig

	mu         sync.Mutex
	recs       map[string]*recommendationState
	projection WARPProjection

	events chan LifecycleEvent
	stop   chan struct{}
	wg     sync.WaitGroup
}

// NewRuntime builds the production recommendation lifecycle controller from
// the library primitives. It is a production call site of the §28A.11
// lifecycle functions (FB-02 wiring probe).
func NewRuntime(cfg RuntimeConfig) *Runtime {
	if cfg.BusCapacity <= 0 {
		cfg.BusCapacity = 64
	}
	return &Runtime{
		cfg:    cfg,
		recs:   map[string]*recommendationState{},
		events: make(chan LifecycleEvent, cfg.BusCapacity),
	}
}

// Start launches the lifecycle controller loop. Safe to call once.
func (rt *Runtime) Start() {
	if rt == nil || rt.stop != nil {
		return
	}
	rt.stop = make(chan struct{})
	rt.wg.Add(1)
	go rt.loop()
}

// Stop shuts down the controller loop. Safe to call on a stopped runtime.
func (rt *Runtime) Stop() {
	if rt == nil || rt.stop == nil {
		return
	}
	close(rt.stop)
	rt.wg.Wait()
}

// Submit feeds one bounded lifecycle event into the loop; returns false when
// the runtime is stopped or the bounded bus is full (never blocks callers).
func (rt *Runtime) Submit(ev LifecycleEvent) bool {
	if rt == nil || rt.stop == nil {
		return false
	}
	select {
	case rt.events <- ev:
		return true
	default:
		return false
	}
}

// loop is the controller loop: it dispatches bounded lifecycle events to the
// same handlers the direct methods expose.
func (rt *Runtime) loop() {
	defer rt.wg.Done()
	for {
		select {
		case <-rt.stop:
			return
		case ev := <-rt.events:
			switch ev.Kind {
			case EventCompile:
				_, _ = rt.Compile(ev.Now, ev.Recommendation, ev)
			case EventValidate:
				_ = rt.Validate(ev.Validation, ev.Regression)
			case EventBeginTest:
				_, _ = rt.BeginTest(ev.Now, ev.Recommendation)
			case EventEnable:
				_ = rt.Enable(ev.Recommendation.RecommendationID, ev.Projection, ev.Validation.ForwardedCanaryPassed)
			case EventValidatePolicy:
				_ = rt.ValidatePolicy(ev.Projection, ev.Camouflage, ev.NonRU, ev.IPBlockTarget)
			case EventPromote:
				_ = rt.Promote(ev.Projection, ev.Health, ev.TargetCanary, ev.Controls)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// §28A.11 hard-gate producers (violating branches only)
// ---------------------------------------------------------------------------

// Compile compiles a WARP recommendation. Violating branches (in evaluation
// order) call exactly one §28A.11 guard each and never reach the library
// compiler: recommendation without IP-path evidence, destination-only scope,
// dead origin, unhealthy controls, cross-service consumption, missing
// failure-policy preview, missing causal-trace gate, hypothesis outside the
// FB-31 causal eligibility for scoped transport.
func (rt *Runtime) Compile(now time.Time, r TransportRecommendation, ctx LifecycleEvent) (TransportRecommendation, error) {
	if rt == nil {
		return TransportRecommendation{}, errors.New("recommendation runtime not initialized")
	}
	if !RecommendedWithoutIPPathEvidenceAllowed(ctx.IPPathEvidence) {
		return TransportRecommendation{}, errors.New("recommendation without IP-path evidence")
	}
	if !RecommendedFromDestinationIPOnlyAllowed(r) {
		return TransportRecommendation{}, errors.New("destination-only recommendation")
	}
	if !RecommendedForOriginDeadAllowed(ctx.OriginAlive) {
		return TransportRecommendation{}, errors.New("origin-dead recommendation")
	}
	if !RecommendedWithUnhealthyControlsAllowed(ctx.ControlsHealthy) {
		return TransportRecommendation{}, errors.New("unhealthy control probes")
	}
	if !CrossServiceRecommendationAllowed(r.ServiceProfileID, ctx.ConsumerService) {
		return TransportRecommendation{}, errors.New("cross-service recommendation")
	}
	if !HiddenFailPolicyAllowed(r.FailurePolicyPreview) {
		return TransportRecommendation{}, errors.New("hidden failure policy")
	}
	if !WithoutCausalTraceGateAllowed(ctx.Projection) {
		return TransportRecommendation{}, errors.New("recommendation without causal-trace gate")
	}
	if !RecommendedOutsideCausalEligibilityAllowed(r.BlockingHypothesisID, ctx.EvidenceAuthority) {
		return TransportRecommendation{}, errors.New("recommendation outside FB-31 causal eligibility")
	}
	return CompileRecommendation(now, r)
}

// Validate evaluates a validation result. Violating branches call exactly one
// §28A.11 guard each: ignored control regression, incomplete cleanup.
func (rt *Runtime) Validate(v RecommendationValidation, regressionReported bool) TransportRecommendationState {
	if rt == nil {
		return RecommendationBlockedBySafety
	}
	if !IgnoredControlRegressionAllowed(regressionReported, v.ControlsHealthy) {
		return RecommendationBlockedBySafety
	}
	if !RecommendationCleanupFailureAllowed(v) {
		return RecommendationBlockedBySafety
	}
	return ValidateRecommendation(v)
}

// BeginTest opens a test transaction for an eligible recommendation. The
// violating branch calls the stale-profile guard before the transaction
// starts.
func (rt *Runtime) BeginTest(now time.Time, r TransportRecommendation) (*RecommendationTransaction, error) {
	if rt == nil {
		return nil, errors.New("recommendation runtime not initialized")
	}
	if !StaleProfileRecommendationAllowed(r, now) {
		return nil, errors.New("stale profile recommendation")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	tx := &RecommendationTransaction{Recommendation: r}
	if err := tx.BeginTest(); err != nil {
		return nil, err
	}
	rt.recs[r.RecommendationID] = &recommendationState{recommendation: r, transaction: tx}
	return tx, nil
}

// Enable authorizes production after validation for one recommendation.
// Violating branches call exactly one §28A.11 guard each: reused test token
// (a transaction carrying a live test token is never a production
// authorization), missing target canary.
func (rt *Runtime) Enable(id string, p WARPProjection, forwardedCanaryPassed bool) error {
	if rt == nil {
		return errors.New("recommendation runtime not initialized")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st := rt.recs[id]
	if st == nil || st.transaction == nil {
		return errors.New("recommendation not found")
	}
	if !TestTokenReusedAsProductionAuthorizationAllowed(*st.transaction) {
		return errors.New("test token reused as production authorization")
	}
	if !EnabledWithoutTargetCanaryAllowed(p, forwardedCanaryPassed) {
		return errors.New("enablement without target canary")
	}
	return st.transaction.EnableAfterValidation()
}

// ValidatePolicy validates the WARP policy bundle. Violating branches call
// exactly one §28A.11 guard each: non-RU without geo requirement, camouflage
// suggested for an IP-block target.
func (rt *Runtime) ValidatePolicy(p WARPProjection, c CamouflagePolicy, n NonRUPolicy, ipBlockTarget bool) error {
	if rt == nil {
		return errors.New("recommendation runtime not initialized")
	}
	if !NonRUSuggestedWithoutGeoRequirementAllowed(n) {
		return errors.New("non-ru suggested without geo requirement")
	}
	if !CamouflageSuggestedForTargetIPBlockAllowed(ipBlockTarget, c) {
		return errors.New("camouflage suggested for target ip block")
	}
	return ValidateWARPPolicy(p, c, n)
}

// Promote evaluates WARP promotion readiness. The violating branch calls the
// target-canary guard before the library promotion check.
func (rt *Runtime) Promote(p WARPProjection, health WARPHealth, targetCanary, controls bool) PromotionState {
	if rt == nil {
		return PromotionBlocked
	}
	if !EnabledWithoutTargetCanaryAllowed(p, targetCanary) {
		return PromotionBlocked
	}
	return PromoteWARP(p, health, targetCanary, controls)
}

// RecommendationSnapshot is the read-only control-plane projection of one
// recommendation transaction (SP-31 §28A.6 status / SP-30 §28A.8 advanced
// preview). TestToken is never exported: the API may report only whether a
// test token is active, not the secret itself.
type RecommendationSnapshot struct {
	RecommendationID                string
	State                           TransportRecommendationState
	ServiceProfileID                string
	ComponentID                     string
	ClientScopeHash                 string
	SetID                           string
	BlockingProfileID               string
	BlockingHypothesisID            string
	NetworkContextID                string
	TransportKind                   string
	FailurePolicyPreview            string
	ConfigGen, SessionGen, RouteGen uint64
	CreatedAt, ExpiresAt            time.Time
	TestTokenActive                 bool
	RolledBack                      bool
	ProductionAuthorized            bool
}

// Snapshot returns the control-plane projection of one recommendation
// transaction, or false when the recommendation is unknown. The projection is
// redacted by construction: it never carries the test token, evidence refs or
// safety hash.
func (rt *Runtime) Snapshot(id string) (RecommendationSnapshot, bool) {
	if rt == nil {
		return RecommendationSnapshot{}, false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st, ok := rt.recs[id]
	if !ok || st == nil {
		return RecommendationSnapshot{}, false
	}
	return rt.snapshotLocked(st), true
}

func (rt *Runtime) snapshotLocked(st *recommendationState) RecommendationSnapshot {
	// The transaction owns the authoritative lifecycle state after
	// begin-test (the same source Enable reads); the rec copy predates the
	// mutation. Everything else comes from the recommendation.
	r := st.recommendation
	txr := r
	if st.transaction != nil {
		txr = st.transaction.Recommendation
	}
	out := RecommendationSnapshot{
		RecommendationID:     txr.RecommendationID,
		State:                txr.State,
		ServiceProfileID:     txr.ServiceProfileID,
		ComponentID:          txr.ComponentID,
		ClientScopeHash:      txr.ClientScopeHash,
		SetID:                txr.SetID,
		BlockingProfileID:    txr.BlockingProfileID,
		BlockingHypothesisID: txr.BlockingHypothesisID,
		NetworkContextID:     txr.NetworkContextID,
		TransportKind:        txr.TransportKind,
		FailurePolicyPreview: txr.FailurePolicyPreview,
		ConfigGen:            txr.ConfigGen,
		SessionGen:           txr.SessionGen,
		RouteGen:             txr.RouteGen,
		CreatedAt:            txr.CreatedAt,
		ExpiresAt:            txr.ExpiresAt,
	}
	if st.transaction != nil {
		out.TestTokenActive = st.transaction.TestToken != ""
		out.ProductionAuthorized = st.transaction.ProductionAuthorized
		out.RolledBack = st.transaction.RolledBack
	}
	return out
}

// Recommendations returns the redacted control-plane projections of every
// tracked recommendation, ordered by creation time. Read-only: the API uses
// this to present the current recommendation inventory without exposing any
// test secret.
func (rt *Runtime) Recommendations() []RecommendationSnapshot {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]RecommendationSnapshot, 0, len(rt.recs))
	for _, st := range rt.recs {
		out = append(out, rt.snapshotLocked(st))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// SetProjection stores the current §28A.5 runtime capability projection of
// the production device. The projection is the read-only truth the status
// endpoint renders as warp_recommendation; it is supplied by the daemon when
// it observes the capability landscape (bundled engine, base transport,
// causal trace, path proof) and updated whenever those capabilities change.
func (rt *Runtime) SetProjection(p WARPProjection) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.projection = p
}

// Projection returns the current §28A.5 capability projection, or the zero
// value when the controller has not been given one yet.
func (rt *Runtime) Projection() WARPProjection {
	if rt == nil {
		return WARPProjection{}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.projection
}

// ValidateTransaction commits a completed validation result to the live
// recommendation transaction: it requires the recommendation to be in the
// bounded testing transaction (§28A.6), runs the validation hard-gate checks
// (ignored control regression, cleanup failure) through the same production
// roots the loop uses, stores the verdict into the transaction and returns
// the resulting state. A blocked verdict never authorizes production: the
// transaction stays at blocked-by-safety until the operator handles the
// cause.
func (rt *Runtime) ValidateTransaction(id string, v RecommendationValidation, regressionReported bool) (TransportRecommendationState, error) {
	if rt == nil {
		return RecommendationBlockedBySafety, errors.New("recommendation runtime not initialized")
	}
	if id == "" {
		return "", errors.New("recommendation id is required")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st, ok := rt.recs[id]
	if !ok || st == nil || st.transaction == nil {
		return "", fmt.Errorf("recommendation %q has no open test transaction", id)
	}
	if st.transaction.Recommendation.State != RecommendationTesting {
		return "", fmt.Errorf("recommendation %q is not in the bounded testing transaction (state %s)", id, st.transaction.Recommendation.State)
	}
	// The same violating branches the loop dispatches: a regression-reported
	// validation with evidence of unhealthy controls stays blocked; an
	// incomplete cleanup stays blocked. The closed transition always moves
	// the transaction out of testing.
	state := rt.Validate(v, regressionReported)
	if state == RecommendationBlockedBySafety {
		st.transaction.RolledBack = true
		st.transaction.Recommendation.State = RecommendationBlockedBySafety
		return state, fmt.Errorf("validation of %s blocked by safety (regression or cleanup)", id)
	}
	st.transaction.Finish(v)
	st.recommendation = st.transaction.Recommendation
	return state, nil
}
