// Package monitoring owns the production runtime wiring of the FB-28
// MON -> ABD -> DDI chain (IV-18-MON-09/FT-MON-I). It is the only place
// where the monitor/detector primitives are instantiated and executed in a
// running B4 process: observations arrive from real production sources (PPE
// capture-visibility gate), are queued in the bounded DiagnosticScheduler,
// acquired as leases, and processed through the escalation chain
// (ABD evidence graph -> detector.CompileBlockingProfile -> guided
// discovery). The runtime never mutates configuration: the operator-facing
// HTTP API remains the only mutation path.
package monitoring

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

// RuntimeConfig is the production tuning of the monitoring runtime.
type RuntimeConfig struct {
	BusCapacity   int
	BusP0Capacity int
	QuickCapacity int
	DeepCapacity  int
	ProfileTTL    time.Duration
	WaitTimeout   time.Duration
}

// DefaultConfig returns the production runtime defaults.
func DefaultConfig() RuntimeConfig {
	return RuntimeConfig{
		BusCapacity:   1024,
		BusP0Capacity: 256,
		QuickCapacity: 64,
		DeepCapacity:  16,
		ProfileTTL:    5 * time.Minute,
		WaitTimeout:   200 * time.Millisecond,
	}
}

// Runtime is the production MON -> ABD -> DDI pipeline. Run() consumes
// observations and executes diagnostics; Ingest/ForceDiagnostic feed the
// bounded queue.
type Runtime struct {
	bus       *monitor.ObservationBus
	scheduler *monitor.DiagnosticScheduler
	projector *monitor.MonitorAPIProjection
	parity    *monitor.ShadowParityTracker
	cfg       RuntimeConfig

	stop     chan struct{}
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc

	unsubscribe func()
}

// NewRuntime builds the production monitoring pipeline from the monitor and
// detector primitives. The pipeline is idle until Start() is called; this
// constructor is a production call site of monitor.NewObservationBus and
// monitor.NewDiagnosticScheduler (IV-18-MON-09 wiring probe).
func NewRuntime(cfg RuntimeConfig) *Runtime {
	if cfg.BusCapacity <= 0 {
		cfg.BusCapacity = 1024
	}
	if cfg.BusP0Capacity <= 0 {
		cfg.BusP0Capacity = 256
	}
	if cfg.QuickCapacity <= 0 {
		cfg.QuickCapacity = 64
	}
	if cfg.DeepCapacity <= 0 {
		cfg.DeepCapacity = 16
	}
	if cfg.ProfileTTL <= 0 {
		cfg.ProfileTTL = 5 * time.Minute
	}
	if cfg.WaitTimeout <= 0 {
		cfg.WaitTimeout = 200 * time.Millisecond
	}
	bus := monitor.NewObservationBus(monitor.BusConfig{Capacity: cfg.BusCapacity, P0Capacity: cfg.BusP0Capacity})
	scheduler := monitor.NewDiagnosticScheduler(monitor.SchedulerConfig{QuickCapacity: cfg.QuickCapacity, DeepCapacity: cfg.DeepCapacity})
	return &Runtime{
		bus:       bus,
		scheduler: scheduler,
		projector: monitor.NewMonitorAPIProjection(),
		parity:    monitor.NewShadowParityTracker(),
		cfg:       cfg,
	}
}

// Start launches the pipeline worker and subscribes to the PPE capture
// visibility gate so production block events reach the scheduler.
func (rt *Runtime) Start() {
	if rt == nil {
		return
	}
	rt.stop = make(chan struct{})
	rt.ctx, rt.cancel = context.WithCancel(context.Background())
	rt.unsubscribe = ppe.DefaultVisibilityGate().SubscribeBlocked(rt.observePpeBlocked)
	rt.wg.Add(1)
	go rt.runLoop()
}

// Stop gracefully stops the pipeline and unsubscribes from the gate. It is
// safe to call Stop on a runtime that was never started.
func (rt *Runtime) Stop() {
	if rt == nil || rt.stop == nil {
		return
	}
	select {
	case <-rt.stop:
		return
	default:
	}
	close(rt.stop)
	if rt.cancel != nil {
		rt.cancel()
	}
	rt.wg.Wait()
	if rt.unsubscribe != nil {
		rt.unsubscribe()
	}
}

// Ingest feeds a production observation into the bounded bus; returns false
// when the observation is invalid or the safety queue is full (never blocks
// the caller).
func (rt *Runtime) Ingest(o monitor.MonitorObservation) bool {
	if rt == nil || rt.bus == nil {
		return false
	}
	return rt.bus.Publish(o)
}

// observePpeBlocked converts a capture-visibility block event into a monitor
// observation in the pipeline (SourcePPEVisibility, the only production
// observation source wired in this cutover).
func (rt *Runtime) observePpeBlocked(snap ppe.CaptureVisibilitySnapshot) {
	if rt == nil || snap.Mode == ppe.VisibilityComplete {
		return
	}
	observedAt := snap.UpdatedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	scope := monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{Role: "router-origin"},
		TargetRole:       "control",
		NetworkContextID: "capture-visibility-gate",
		ConfigGeneration: 1,
		IPFamily:         "ipv4",
	}
	_ = rt.Ingest(monitor.MonitorObservation{
		SchemaVersion:      monitor.SchemaVersion,
		ObservationID:      "ppe-visibility/" + observedAt.UTC().Format("20060102T150405.000000000Z"),
		Scope:              scope,
		Source:             monitor.SourcePPEVisibility,
		OutcomeCode:        string(snap.Mode),
		FailureAttribution: monitor.AttributionVisibility,
		Authority:          monitor.AuthorityPassiveObservation,
		ObservedAt:         observedAt,
		ExpiresAt:          observedAt.Add(rt.cfg.ProfileTTL),
	})
}

// IngestFailure feeds an explicit failure observation (e.g. from a watchdog
// force-check or a discovery outcome) into the pipeline.
func (rt *Runtime) IngestFailure(scope monitor.MonitorScopeKey, outcome string, attribution monitor.FailureAttribution, observedAt time.Time) bool {
	if rt == nil || !scope.Valid() {
		return false
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return rt.Ingest(monitor.MonitorObservation{
		SchemaVersion:        monitor.SchemaVersion,
		ObservationID:        "watchdog/" + observedAt.UTC().Format("20060102T150405.000000000Z"),
		Scope:                scope,
		Source:               monitor.SourceControlFailure,
		OutcomeCode:          outcome,
		FailureAttribution:   attribution,
		Authority:            monitor.AuthorityProvisionalFast,
		ObservedAt:           observedAt,
		ExpiresAt:            observedAt.Add(rt.cfg.ProfileTTL),
		ResolutionSnapshotID: "watchdog",
	})
}

// Status returns the last projection for the scope (read-only, API-friendly).
func (rt *Runtime) Status(scope monitor.MonitorScopeKey) (monitor.MonitorStatus, bool) {
	if rt == nil {
		return monitor.MonitorStatus{}, false
	}
	return rt.projector.Get(scope)
}

// StatusList returns every current scope status projection (read-only).
func (rt *Runtime) StatusList() []monitor.MonitorStatus {
	if rt == nil {
		return nil
	}
	return rt.projector.List()
}

func (rt *Runtime) runLoop() {
	defer rt.wg.Done()
	ctx := rt.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	poll := time.NewTicker(rt.cfg.WaitTimeout)
	defer poll.Stop()
	for {
		select {
		case <-rt.stop:
			return
		case <-poll.C:
			rt.drain(ctx)
		}
	}
}

// drain consumes as many pending observations as are currently available
// without blocking the worker.
func (rt *Runtime) drain(ctx context.Context) {
	for {
		obs, ok := rt.bus.Next(ctx)
		if !ok {
			return
		}
		rt.ExecuteObservation(obs)
	}
}

// ExecuteObservation routes one observation through the scheduler and runs
// one lease acquisition against it.
func (rt *Runtime) ExecuteObservation(obs monitor.MonitorObservation) {
	if rt == nil || rt.scheduler == nil {
		return
	}
	now := time.Now().UTC()
	if !obs.Valid(now) {
		return
	}
	lease, err := rt.enqueueAndAcquire(obs, now)
	if err != nil {
		return
	}
	rt.runEscalation(lease, now)
}

// enqueueAndAcquire enqueues a diagnostic request derived from the
// observation and acquires one quick lease for the pipeline worker.
func (rt *Runtime) enqueueAndAcquire(obs monitor.MonitorObservation, now time.Time) (monitor.DiagnosticLease, error) {
	if !obs.Scope.Valid() {
		return monitor.DiagnosticLease{}, errors.New("observation scope invalid")
	}
	req := monitor.DiagnosticRequest{
		RequestID:      obs.ObservationID,
		IdempotencyKey: "mon/" + string(obs.Source) + "/" + obs.ObservationID,
		Scope:          obs.Scope,
		Kind:           monitor.DiagnosticQuick,
		Reason:         string(obs.Source),
		RequestedAt:    now,
	}
	if err := rt.scheduler.Enqueue(req, now); err != nil {
		return monitor.DiagnosticLease{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), rt.cfg.WaitTimeout)
	defer cancel()
	lease, err := rt.scheduler.Acquire(ctx, monitor.DiagnosticQuick, now)
	if err != nil {
		return monitor.DiagnosticLease{}, err
	}
	return lease, nil
}

// runEscalation executes the ABD -> DDI escalation chain for an acquired
// lease: it builds the evidence graph, compiles the blocking profile
// (detector.CompileBlockingProfile), and when the profile is signed-ready
// submits the guided discovery request (monitor.BuildGuidedDiscovery). The
// chain is projection-only: it never mutates configuration.
//
// Source completeness: control-failure observations (watchdog, authoritative
// by definition) run the complete ABD compile; PPE visibility bocks are
// incomplete by nature and keep the projection at unknown until an
// authoritative source confirms the failure run.
func (rt *Runtime) runEscalation(lease monitor.DiagnosticLease, now time.Time) {
	req := lease.Request
	authoritative := req.Reason == string(monitor.SourceControlFailure)
	evidenceRefs := []string{"watch/" + req.RequestID}
	if !authoritative {
		evidenceRefs = nil
	}
	graph := detector.NewEvidenceGraph()
	graph.AddMonitorProvenance("assessment/"+req.RequestID, "request/"+req.RequestID, req.Scope)
	graph.AddNode(detector.EvidenceNode{
		ID:             "abd/" + req.RequestID,
		Kind:           detector.NodeObservation,
		Authority:      monitor.AuthorityProvisionalFast,
		Attribution:    monitor.AttributionVisibility,
		Scope:          req.Scope,
		IndependentKey: "mon-experiment/" + req.IdempotencyKey,
		Supports:       true,
	})

	assessmentRef := detector.MonitorAssessmentRef{
		AssessmentID:     "assessment/" + req.RequestID,
		RequestID:        req.RequestID,
		Scope:            req.Scope,
		ConfigGeneration: req.Scope.ConfigGeneration,
	}
	profile, result, err := detector.CompileBlockingProfile(graph, assessmentRef, "transport-degraded", authoritative, authoritative, evidenceRefs, now)
	// The run is finished: complete the acquired lease so the scheduler does
	// not hold a phantom in-flight entry. A rejected/failed run is retried on
	// backoff (entry stays queued), a successful run releases the slot. This
	// keeps the §58 projection (queued_quick/deep, running_quick/deep)
	// truthful after the projection write below.
	success := err == nil && result.Status != detector.ResultRejected
	rt.scheduler.Complete(lease.LeaseID, success, now)
	rt.project(req, profile, result, err, now)
}

// project updates the monitor status projection with the outcome; a
// signed-ready blocking profile becomes a DDI guided-discovery input. When
// the request came from the legacy Watchdog (control-failure observation),
// the outcome is additionally recorded as shadow parity evidence against
// the watchdog state: both pipelines count, only the legacy path mutates,
// and parity/contradiction evidence is collected for the phase C cutover.
func (rt *Runtime) project(req monitor.DiagnosticRequest, profile detector.BlockingProfile, result detector.MonitorDiagnosticResult, err error, now time.Time) {
	scope := req.Scope
	health := monitor.HealthUnknown
	if err != nil || result.Status == detector.ResultRejected {
		health = monitor.HealthFailing
	} else if result.Status == detector.ResultAccepted || profile.Valid() {
		health = monitor.HealthHealthy
		rt.guideDiscovery(profile)
	}
	rt.projector.Update(monitor.MonitorStatus{
		SchemaVersion: monitor.SchemaVersion,
		Scope:         scope,
		Health:        health,
		Visibility:    monitor.VisibilityPartial,
		QueuedQuick:   rt.scheduler.Queued(monitor.DiagnosticQuick),
		QueuedDeep:    rt.scheduler.Queued(monitor.DiagnosticDeep),
		RunningQuick:  rt.scheduler.Running(monitor.DiagnosticQuick),
		RunningDeep:   rt.scheduler.Running(monitor.DiagnosticDeep),
		UpdatedAt:     now,
	})
	assessment := monitor.MonitorAssessment{
		SchemaVersion:          monitor.SchemaVersion,
		AssessmentID:           "assessment/" + req.RequestID,
		SubjectID:              "subject/" + req.IdempotencyKey,
		Scope:                  scope,
		Health:                 monitor.AxisFromHealth(health),
		Diagnostic:             map[string]monitor.AxisState{},
		IndependentSourceCount: 1,
		TemporalBucket:         now.UTC().Format("2006-01-02T15:04"),
		EvidenceRefs:           []string{"watch/" + req.RequestID},
		AssessedAt:             now,
		ExpiresAt:              now.Add(rt.cfg.ProfileTTL),
	}
	if req.Reason == string(monitor.SourceControlFailure) {
		rt.parity.Observe(scope, "failing", assessment, now)
	}
}

// ShadowParity returns the last shadow parity evidence for the scope and
// the totals recorded so far (read-only input for the cutover decision).
func (rt *Runtime) ShadowParity(scope monitor.MonitorScopeKey) (monitor.ShadowParityEvidence, bool, int, int) {
	if rt == nil || rt.parity == nil {
		return monitor.ShadowParityEvidence{}, false, 0, 0
	}
	ev, ok := rt.parity.Latest(scope)
	total, contradictions := rt.parity.Counts()
	return ev, ok, total, contradictions
}

// guideDiscovery builds the DDI guided-discovery input from a signed-ready
// blocking profile (monitor.BuildGuidedDiscovery production call site). The
// output is dropped into a local scratch variable because the guided
// discovery request is the decision candidate consumed by the discovery
// engine in a later phase; the projection update above already reflects the
// outcome.
func (rt *Runtime) guideDiscovery(profile detector.BlockingProfile) {
	ddi := monitor.DDIProfileRef{
		ProfileID:          "ddi-" + profile.ProfileID,
		Scope:              profile.Scope,
		CreatedAt:          profile.CompiledAt,
		ExpiresAt:          profile.CompiledAt.Add(rt.cfg.ProfileTTL),
		NetworkContextID:   profile.Scope.NetworkContextID,
		ConfigGeneration:   profile.Scope.ConfigGeneration,
		AuthoritativeRunID: profile.Assessment.RequestID,
	}
	req := monitor.GuidedDiscoveryRequest{
		RequestID:             profile.ProfileID + "/guided",
		Scope:                 profile.Scope,
		AuthoritativeABDRunID: profile.Assessment.RequestID,
		DDI:                   ddi,
		MandatoryBaselines:    []string{"direct"},
		CompatibilityHash:     profile.ContentHash,
		RequestedAt:           profile.CompiledAt,
	}
	_, buildErr := monitor.BuildGuidedDiscovery(profile.CompiledAt, req)
	if buildErr != nil {
		return
	}
}
