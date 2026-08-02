package ppe

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

const DefaultManagedSourceSet = "b4_managed_devices"

type ProductAuditEvent struct {
	At         time.Time `json:"at"`
	Operation  string    `json:"operation"`
	Generation string    `json:"generation,omitempty"`
	Success    bool      `json:"success"`
	Reason     string    `json:"reason,omitempty"`
}

type ProductStatus struct {
	Capabilities     CapabilityReport                         `json:"capabilities"`
	Diagnostics      DiagnosticsReport                        `json:"diagnostics"`
	Desired          *DesiredState                            `json:"desired,omitempty"`
	Reconciler       ReconcilerStatus                         `json:"reconciler"`
	Visibility       CaptureVisibilitySnapshot                `json:"visibility"`
	Features         map[VisibilityFeature]VisibilityDecision `json:"features"`
	LastSelfTest     *CaptureVisibilityResult                 `json:"last_self_test,omitempty"`
	Audit            []ProductAuditEvent                      `json:"audit,omitempty"`
	RulesPresent     bool                                     `json:"rules_present"`
	ConfiguredPolicy string                                   `json:"configured_policy"`
	Effective        string                                   `json:"effective"`
}

type ProductService struct {
	mu               sync.Mutex
	provider         ConfigProvider
	managedSourceSet string
	runner           Runner
	detector         *Detector
	transactions     *TransactionManager
	lifecycle        LifecycleManager
	reconciler       *Reconciler
	diagnostics      *DiagnosticsService
	passive          *PassiveTracker
	bus              *ObservationBus
	selfTest         SelfTestRunner
	selfTestStore    SelfTestResultStore
	hook             NDMHookInstaller
	bridgeStop       func()
	passiveStop      func()
	metricsStop      func()
	visibilityStop   func()
	lifecycleCtx     context.Context
	lifecycleCancel  context.CancelFunc
	lastSelfTest     *CaptureVisibilityResult
	audit            []ProductAuditEvent
	idempotencyMu    sync.Mutex
	idempotency      map[string]*productIdempotencyEntry
	selfTestMu       sync.Mutex
	selfTestFlight   atomic.Bool
	started          bool
}

type productIdempotencyEntry struct {
	ready  chan struct{}
	status ProductStatus
	err    error
}

func NewProductService(provider ConfigProvider, passive *PassiveTracker, managedSourceSet string) *ProductService {
	if strings.TrimSpace(managedSourceSet) == "" {
		managedSourceSet = DefaultManagedSourceSet
	}
	if passive == nil {
		passive = NewPassiveTracker(4096, 10*time.Minute)
	}
	runner := OSRunner{}
	detector := NewDetector(runner)
	transactions := NewTransactionManager(NewIPTablesBackend(runner))
	gate := DefaultVisibilityGate()
	lifecycle := WrapLifecycleWithVisibility(transactions, gate)
	interval := 55 * time.Second
	if provider != nil {
		if cfg := provider(); cfg != nil {
			if seconds := cfg.System.Classifier.Runtime.Capture.PPE.ReassertIntervalSec; seconds > 0 {
				interval = time.Duration(seconds) * time.Second
			}
		}
	}
	lifecycle = productLifecycleMetrics{next: lifecycle}
	reconciler := NewReconciler(lifecycle, DefaultReconcilerConfig(interval))
	bus := NewObservationBus()
	passiveStop := bus.Subscribe(passive)
	metricsStop := bus.Subscribe(productVisibilityMetricSink{})
	store := NewMemorySelfTestStore(64)
	counters := NewRuleCounterCollector(runner)
	service := &ProductService{
		provider: provider, managedSourceSet: managedSourceSet, runner: runner, detector: detector,
		transactions: transactions, lifecycle: lifecycle, reconciler: reconciler,
		diagnostics: NewDiagnosticsService(provider, detector, counters, passive, managedSourceSet),
		passive:     passive, bus: bus, selfTestStore: store, hook: NDMHookInstaller{},
		passiveStop: passiveStop, metricsStop: metricsStop, idempotency: make(map[string]*productIdempotencyEntry),
	}
	service.visibilityStop = gate.SubscribeBlocked(func(snapshot CaptureVisibilitySnapshot) {
		recorder := observability.Default()
		recorder.Metrics.Inc(observability.MetricCaptureVisibilityDegrade, map[string]string{"mode": string(snapshot.Mode)}, 1)
		recorder.Metrics.Inc(observability.MetricHoldDisabledVisibility, map[string]string{"mode": string(snapshot.Mode)}, 1)
		recorder.Trace.Record(observability.TraceEvent{Kind: "capture_visibility_degraded", Fields: map[string]string{"mode": string(snapshot.Mode), "reason": snapshot.Reason}})
	})
	controller := NewSelfTestController(
		func(ctx context.Context) (CapabilityReport, error) { return detector.Detect(ctx), nil },
		service.currentPolicy,
		HTTPHealthChecker{},
		CommandProbeExecutor{Runner: runner},
		IPTablesABIsolation{Runner: runner, Current: transactions.Current},
		productCounterSource{collector: counters, current: transactions.Current},
		bus,
		store,
	)
	service.selfTest = WrapSelfTestRunnerWithVisibility(controller, gate)
	return service
}

func (s *ProductService) ObservationBus() *ObservationBus {
	if s == nil {
		return nil
	}
	return s.bus
}

func (s *ProductService) Capabilities(ctx context.Context) CapabilityReport {
	if s == nil || s.detector == nil {
		return CapabilityReport{State: CapabilityUnknown}
	}
	return s.detector.Detect(ctx)
}

// Status preserves the existing read-only diagnostics provider contract.
func (s *ProductService) Status(ctx context.Context) DiagnosticsReport {
	if s == nil || s.diagnostics == nil {
		return DiagnosticsReport{State: DiagnosticConfigurationErr, FunctionalVerdict: FunctionalNotRun}
	}
	report := s.diagnostics.Status(ctx)
	visibility := DefaultVisibilityGate().Snapshot()
	report.FunctionalVerdict = functionalVerdictFor(visibility.LastVerdict)
	report.ProductionReady = visibility.Mode == VisibilityComplete && visibility.LastVerdict == VerdictPASS
	return report
}

func (s *ProductService) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("PPE product service is nil")
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	serviceCtx, cancel := context.WithCancel(ctx)
	s.lifecycleCtx = serviceCtx
	s.lifecycleCancel = cancel
	s.started = true
	s.mu.Unlock()

	cfg := s.currentConfig()
	if cfg == nil {
		cancel()
		s.mu.Lock()
		s.started = false
		s.lifecycleCtx = nil
		s.lifecycleCancel = nil
		s.mu.Unlock()
		return errors.New("PPE configuration snapshot unavailable")
	}
	if cfg.System.Tables.SkipSetup {
		DefaultVisibilityGate().Degrade("", "firewall table setup is disabled; PPE exclusion was not applied")
		s.record("startup-skip-tables", "", false, "system.tables.skip_setup is enabled")
		return nil
	}
	capability := s.Capabilities(ctx)
	observability.Default().Metrics.Inc(observability.MetricPPESupported, map[string]string{"state": string(capability.State), "supported": fmt.Sprintf("%t", capability.Supported)}, 1)
	if cfg.System.Classifier.Runtime.Capture.OffloadPolicy != config.OffloadPolicyExclude {
		DefaultVisibilityGate().DisableRequirement("per-flow PPE exclusion is not active")
		return nil
	}
	if !capability.Supported {
		DefaultVisibilityGate().Degrade("", "PPE capability is unavailable; exclusion was not applied")
		s.record("startup-capability", "", false, string(capability.State))
		return nil
	}
	if _, err := s.ApplyConfig(ctx, cfg); err != nil {
		s.record("startup-apply", "", false, err.Error())
		return nil // fail-open: B4 remains available in observe-only mode
	}
	s.ensureLifecycleStarted(capability)
	return nil
}

func (s *ProductService) ensureLifecycleStarted(capability CapabilityReport) {
	if s == nil || s.reconciler == nil {
		return
	}
	s.mu.Lock()
	ctx := s.lifecycleCtx
	if ctx == nil {
		ctx, s.lifecycleCancel = context.WithCancel(context.Background())
		s.lifecycleCtx = ctx
	}
	startBridge := s.bridgeStop == nil && capability.Platform.NDM
	s.mu.Unlock()
	if _, err := s.hook.Install(capability.Platform); err != nil {
		s.record("ndm-hook-install", "", false, err.Error())
	}
	s.reconciler.Start(ctx)
	if startBridge {
		stop := StartNDMSignalBridge(ctx, s.reconciler)
		s.mu.Lock()
		if s.bridgeStop == nil {
			s.bridgeStop = stop
			stop = nil
		}
		s.mu.Unlock()
		if stop != nil {
			stop()
		}
	}
}

func (s *ProductService) Stop(ctx context.Context) {
	if s == nil {
		return
	}
	s.mu.Lock()
	cancel := s.lifecycleCancel
	s.lifecycleCtx = nil
	s.lifecycleCancel = nil
	s.started = false
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if s.bridgeStop != nil {
		s.bridgeStop()
		s.bridgeStop = nil
	}
	if s.reconciler != nil {
		s.reconciler.Stop()
	}
	if current, ok := s.transactions.Current(); ok {
		_, _ = s.transactions.Remove(ctx, current)
	}
	_, _ = s.hook.Remove()
	if s.passiveStop != nil {
		s.passiveStop()
		s.passiveStop = nil
	}
	if s.metricsStop != nil {
		s.metricsStop()
		s.metricsStop = nil
	}
	if s.visibilityStop != nil {
		s.visibilityStop()
		s.visibilityStop = nil
	}
	DefaultVisibilityGate().DisableRequirement("PPE service stopped")
}

func (s *ProductService) ApplyConfig(ctx context.Context, cfg *config.Config) (ProductStatus, error) {
	if s == nil || cfg == nil {
		return ProductStatus{}, errors.New("PPE apply configuration is unavailable")
	}
	if cfg.System.Tables.SkipSetup {
		return ProductStatus{}, errors.New("PPE exclusion requires firewall table setup; system.tables.skip_setup is enabled")
	}
	policy := cfg.System.Classifier.Runtime.Capture.OffloadPolicy
	if policy == config.OffloadPolicyDisableGlobal {
		return ProductStatus{}, errors.New("global offload disable is not managed automatically; use per-flow exclusion or monitoring mode")
	}
	if policy != config.OffloadPolicyExclude {
		return s.Remove(ctx)
	}
	capability := s.Capabilities(ctx)
	if !capability.Supported {
		return ProductStatus{}, fmt.Errorf("PPE exclusion is unsupported: %s", capability.State)
	}
	desired, err := Compile(CompileInput{Config: cfg, Capabilities: capability, ManagedSourceSet: s.managedSourceSet})
	if err != nil {
		return ProductStatus{}, fmt.Errorf("compile PPE desired state: %w", err)
	}
	if _, err := s.transactions.Apply(ctx, desired); err != nil {
		s.record("apply", desired.Generation, false, err.Error())
		return ProductStatus{}, err
	}
	DefaultVisibilityGate().EnsureRequired(desired.Generation, "controlled bidirectional PPE visibility self-test is required")
	s.ensureLifecycleStarted(capability)
	if s.reconciler != nil {
		s.reconciler.Notify(ReconcileManual)
	}
	s.maybeRunAutomaticSelfTest()
	s.record("apply", desired.Generation, true, "")
	return s.Snapshot(ctx), nil
}

func (s *ProductService) Remove(ctx context.Context) (ProductStatus, error) {
	if s == nil {
		return ProductStatus{}, errors.New("PPE product service is nil")
	}
	current, ok := s.transactions.Current()
	if ok {
		if _, err := s.transactions.Remove(ctx, current); err != nil {
			s.record("remove", current.Generation, false, err.Error())
			return ProductStatus{}, err
		}
	}
	_, _ = s.hook.Remove()
	DefaultVisibilityGate().DisableRequirement("per-flow PPE exclusion removed; monitoring mode is active")
	s.record("remove", current.Generation, true, "")
	return s.Snapshot(ctx), nil
}

func (s *ProductService) RunSelfTest(ctx context.Context, request SelfTestRequest) (CaptureVisibilityResult, error) {
	if s == nil || s.selfTest == nil {
		return CaptureVisibilityResult{}, errors.New("PPE self-test service is unavailable")
	}
	s.selfTestMu.Lock()
	defer s.selfTestMu.Unlock()
	if request.RunID != "" {
		if existing, ok := s.SelfTestResult(request.RunID); ok {
			return existing, nil
		}
	}
	if request.Generation == "" {
		current, ok := s.transactions.Current()
		if !ok {
			return CaptureVisibilityResult{}, ErrNoActiveGeneration
		}
		request.Generation = current.Generation
	}
	started := time.Now()
	result := s.selfTest.Run(ctx, request)
	s.publishSelfTestOutcome(request, result, started, "manual")
	return result, nil
}

// publishSelfTestOutcome records the metric, the last-result snapshot and the
// audit trail for a completed self-test. It is shared by manual (HTTP) and
// automatic runs so both paths emit identical evidence.
func (s *ProductService) publishSelfTestOutcome(request SelfTestRequest, result CaptureVisibilityResult, started time.Time, trigger string) {
	recorder := observability.Default()
	labels := map[string]string{"verdict": string(result.Verdict), "trigger": trigger}
	recorder.Metrics.Inc(observability.MetricPPESelfTest, labels, 1)
	recorder.Metrics.Observe(observability.MetricPPESelfTestDuration, labels, float64(time.Since(started).Milliseconds()))
	s.mu.Lock()
	clone := cloneVisibilityResult(result)
	s.lastSelfTest = &clone
	s.mu.Unlock()
	s.record("self-test", request.Generation, result.Verdict == VerdictPASS, trigger+":"+string(result.Verdict))
}

// automaticSelfTestRequest derives the automatic visibility self-test request
// from the active configuration. It returns false when the configured mode
// does not require an automatic run (off/manual) or when the controlled
// endpoint is not configured — without an endpoint a controlled A/B probe
// cannot be emitted and the automatic run is skipped; the generation-bound
// requirement remains visible in the gate for a manual run.
func (s *ProductService) automaticSelfTestRequest(cfg *config.Config) (SelfTestRequest, bool) {
	if cfg == nil {
		return SelfTestRequest{}, false
	}
	selfTest := cfg.System.Classifier.Runtime.Capture.PPE.SelfTest
	if selfTest.Mode != config.PPESelfTestStartupAndChange {
		return SelfTestRequest{}, false
	}
	endpoint := strings.TrimSpace(selfTest.ControlledEndpoint)
	if endpoint == "" {
		return SelfTestRequest{}, false
	}
	timeout := time.Duration(selfTest.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	sourcePort := uint16(443)
	if ports := cfg.System.Classifier.Runtime.Capture.PPE.TCPPorts; len(ports) > 0 {
		sourcePort = ports[0]
	}
	return SelfTestRequest{
		RunID:              "auto",
		ControlledEndpoint: endpoint,
		Family:             "ipv4",
		TCPSourcePort:      sourcePort,
		Timeout:            timeout,
	}, true
}

// maybeRunAutomaticSelfTest starts an asynchronous self-test when the active
// configuration requires one (mode startup-and-change), a generation is
// active, and the current generation has not been proven yet. The run is
// single-flight: concurrent applies/config changes do not start a second
// probe while one is already in flight.
func (s *ProductService) maybeRunAutomaticSelfTest() {
	if s == nil || s.selfTest == nil {
		return
	}
	request, ok := s.automaticSelfTestRequest(s.currentConfig())
	if !ok {
		return
	}
	current, ok := s.transactions.Current()
	if !ok {
		return
	}
	request.Generation = current.Generation
	request.RunID = "auto-" + current.Generation
	request.TCPFlowID = request.RunID + "-tcp"
	if provenForGeneration(request.Generation) {
		return
	}
	if !s.selfTestFlight.CompareAndSwap(false, true) {
		return
	}
	go s.runAutomaticSelfTest(request)
}

// runAutomaticSelfTest executes the automatic self-test asynchronously. The
// generation and proof state are re-checked after scheduling: a result is
// never published for a generation that was removed or already proven while
// the goroutine was waiting for the single-flight slot.
func (s *ProductService) runAutomaticSelfTest(request SelfTestRequest) {
	defer s.selfTestFlight.Store(false)
	ctx := context.Background()
	s.mu.Lock()
	if s.lifecycleCtx != nil {
		ctx = s.lifecycleCtx
	}
	s.mu.Unlock()
	current, ok := s.transactions.Current()
	if !ok || current.Generation != request.Generation {
		return
	}
	if provenForGeneration(request.Generation) {
		return
	}
	s.selfTestMu.Lock()
	defer s.selfTestMu.Unlock()
	started := time.Now()
	result := s.selfTest.Run(ctx, request)
	s.publishSelfTestOutcome(request, result, started, "automatic")
}

func provenForGeneration(generation string) bool {
	snapshot := DefaultVisibilityGate().Snapshot()
	return snapshot.Mode == VisibilityComplete && snapshot.Generation == generation && snapshot.LastVerdict == VerdictPASS
}

func (s *ProductService) SelfTestResult(runID string) (CaptureVisibilityResult, bool) {
	if s == nil || s.selfTestStore == nil {
		return CaptureVisibilityResult{}, false
	}
	return s.selfTestStore.Get(runID)
}

func (s *ProductService) Snapshot(ctx context.Context) ProductStatus {
	if s == nil {
		return ProductStatus{Effective: "unavailable"}
	}
	report := s.Status(ctx)
	visibility := DefaultVisibilityGate().Snapshot()
	var desired *DesiredState
	if current, ok := s.transactions.Current(); ok {
		clone := cloneDesiredState(current)
		desired = &clone
	}
	s.mu.Lock()
	audit := append([]ProductAuditEvent(nil), s.audit...)
	var last *CaptureVisibilityResult
	if s.lastSelfTest != nil {
		clone := cloneVisibilityResult(*s.lastSelfTest)
		last = &clone
	}
	s.mu.Unlock()
	features := make(map[VisibilityFeature]VisibilityDecision, 8)
	for _, feature := range []VisibilityFeature{
		VisibilityFeatureObserve, VisibilityFeatureStatelessMutation, VisibilityFeatureReassembly,
		VisibilityFeatureHoldReplay, VisibilityFeatureACKReplay, VisibilityFeatureAutomaticDiscovery,
		VisibilityFeatureCanary, VisibilityFeaturePromotion,
	} {
		features[feature] = DefaultVisibilityGate().Decision(feature)
	}
	effective := "monitoring"
	if desired != nil {
		effective = "per-flow-exclusion"
	}
	status := ProductStatus{
		Capabilities: report.Capability, Diagnostics: report, Desired: desired,
		Reconciler: s.reconciler.Status(), Visibility: visibility, Features: features,
		LastSelfTest: last, Audit: audit, ConfiguredPolicy: s.currentPolicy(), Effective: effective,
	}
	status.RulesPresent = status.Reconciler.RulesPresent || (desired != nil && report.RuleCounters.Available)
	return status
}

func (s *ProductService) ExecuteIdempotent(key string, operation func() (ProductStatus, error)) (ProductStatus, error) {
	if s == nil {
		return ProductStatus{}, errors.New("PPE product service is nil")
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return ProductStatus{}, errors.New("idempotency key is required")
	}
	if operation == nil {
		return ProductStatus{}, errors.New("idempotent operation is nil")
	}
	s.idempotencyMu.Lock()
	if previous, ok := s.idempotency[key]; ok {
		s.idempotencyMu.Unlock()
		<-previous.ready
		return previous.status, previous.err
	}
	entry := &productIdempotencyEntry{ready: make(chan struct{})}
	s.idempotency[key] = entry
	s.idempotencyMu.Unlock()

	entry.status, entry.err = operation()
	close(entry.ready)

	s.idempotencyMu.Lock()
	if len(s.idempotency) > 128 {
		for old, candidate := range s.idempotency {
			if old != key {
				select {
				case <-candidate.ready:
					delete(s.idempotency, old)
				default:
				}
				break
			}
		}
	}
	s.idempotencyMu.Unlock()
	return entry.status, entry.err
}

func (s *ProductService) currentConfig() *config.Config {
	if s == nil || s.provider == nil {
		return nil
	}
	return s.provider()
}

func (s *ProductService) currentPolicy() string {
	if cfg := s.currentConfig(); cfg != nil {
		return cfg.System.Classifier.Runtime.Capture.OffloadPolicy
	}
	return config.OffloadPolicyDetect
}

func (s *ProductService) record(operation, generation string, success bool, reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cleanReason := limitProductReason(reason)
	now := time.Now().UTC()
	s.audit = append(s.audit, ProductAuditEvent{At: now, Operation: operation, Generation: generation, Success: success, Reason: cleanReason})
	recorder := observability.Default()
	recorder.Trace.Record(observability.TraceEvent{Timestamp: now, Kind: "ppe_" + operation, Fields: map[string]string{"generation": generation, "success": fmt.Sprintf("%t", success), "reason": cleanReason}})
	switch operation {
	case "apply", "remove", "startup-apply":
		recorder.Metrics.Inc(observability.MetricPPERulesPresent, map[string]string{"present": fmt.Sprintf("%t", success && operation != "remove"), "operation": operation}, 1)
	}
	if len(s.audit) > 128 {
		s.audit = append([]ProductAuditEvent(nil), s.audit[len(s.audit)-128:]...)
	}
}

func functionalVerdictFor(verdict SelfTestVerdict) FunctionalVerdict {
	switch verdict {
	case VerdictPASS:
		return FunctionalPass
	case VerdictFAIL:
		return FunctionalFail
	case VerdictUNSUPPORTED:
		return FunctionalUnsupported
	case VerdictINCONCLUSIVE, VerdictPASSWithLimitations:
		return FunctionalInconclusive
	default:
		return FunctionalNotRun
	}
}

func limitProductReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 256 {
		return reason[:256]
	}
	return reason
}

type productLifecycleMetrics struct{ next LifecycleManager }

func (m productLifecycleMetrics) Current() (DesiredState, bool)    { return m.next.Current() }
func (m productLifecycleMetrics) Assert(ctx context.Context) error { return m.next.Assert(ctx) }
func (m productLifecycleMetrics) Reapply(ctx context.Context) (TransactionResult, error) {
	result, err := m.next.Reapply(ctx)
	label := "success"
	if err != nil {
		label = "failure"
	}
	observability.Default().Metrics.Inc(observability.MetricPPERuleReapply, map[string]string{"result": label}, 1)
	return result, err
}

type productVisibilityMetricSink struct{}

func (productVisibilityMetricSink) Observe(observation PassiveObservation) {
	metric := observability.MetricCaptureOutgoingVisibility
	if observation.Direction == PassiveIncoming {
		metric = observability.MetricCaptureIncomingVisibility
	}
	observability.Default().Metrics.Inc(metric, map[string]string{"family": observation.Family, "protocol": observation.Protocol}, 1)
}

type productCounterSource struct {
	collector *RuleCounterCollector
	current   func() (DesiredState, bool)
}

func (s productCounterSource) RuleCounters(ctx context.Context) (map[string]uint64, error) {
	if s.collector == nil || s.current == nil {
		return nil, errors.New("PPE rule counters unavailable")
	}
	desired, ok := s.current()
	if !ok {
		return nil, ErrNoActiveGeneration
	}
	report := s.collector.Collect(ctx, desired)
	if !report.Available {
		return nil, errors.New("PPE rule counters unavailable")
	}
	out := make(map[string]uint64, len(report.Rules))
	for _, rule := range report.Rules {
		out[rule.Family+"/"+rule.Chain+"/"+rule.Protocol] += rule.Packets
	}
	return out, nil
}
