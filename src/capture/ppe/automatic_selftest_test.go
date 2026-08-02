package ppe

// Automatic self-test (FB-12): the PPE product service must run the
// controlled visibility self-test automatically on startup and on applicable
// configuration changes when the configured mode is startup-and-change,
// without requiring the HTTP trigger.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

// recordingSelfTestRunner records every Run invocation and optionally blocks
// until released, so single-flight behaviour can be asserted deterministically.
type recordingSelfTestRunner struct {
	mu      sync.Mutex
	started chan struct{}
	release chan struct{}
	calls   []SelfTestRequest
}

func (r *recordingSelfTestRunner) Run(ctx context.Context, request SelfTestRequest) CaptureVisibilityResult {
	r.mu.Lock()
	r.calls = append(r.calls, request)
	r.mu.Unlock()
	if r.started != nil {
		select {
		case r.started <- struct{}{}:
		default:
		}
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
		}
	}
	now := time.Now().UTC()
	return CaptureVisibilityResult{RunID: request.RunID, Verdict: VerdictPASS, ProductionReady: true, StartedAt: now, CompletedAt: now}
}

func (r *recordingSelfTestRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *recordingSelfTestRunner) requests() []SelfTestRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]SelfTestRequest(nil), r.calls...)
}

func automaticSelfTestConfig() *config.Config {
	cfg := config.DefaultConfig
	cfg.System.Classifier.Runtime.Capture.OffloadPolicy = config.OffloadPolicyExclude
	cfg.System.Classifier.Runtime.Capture.PPE.SelfTest.Mode = config.PPESelfTestStartupAndChange
	cfg.System.Classifier.Runtime.Capture.PPE.SelfTest.ControlledEndpoint = "https://example.test/health"
	cfg.System.Classifier.Runtime.Capture.PPE.SelfTest.TimeoutMS = 3000
	return &cfg
}

func waitForAutomaticSelfTest(t *testing.T, service *ProductService, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		service.mu.Lock()
		recorded := service.lastSelfTest != nil
		service.mu.Unlock()
		if recorded {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("automatic self-test did not complete")
}

func TestAutomaticSelfTestRequest(t *testing.T) {
	service := &ProductService{}

	request, ok := service.automaticSelfTestRequest(automaticSelfTestConfig())
	if !ok {
		t.Fatal("startup-and-change mode with a controlled endpoint must produce a request")
	}
	if request.Family != "ipv4" {
		t.Errorf("family = %q, want ipv4", request.Family)
	}
	if request.ControlledEndpoint != "https://example.test/health" {
		t.Errorf("controlled_endpoint = %q", request.ControlledEndpoint)
	}
	if request.TCPSourcePort == 0 {
		t.Error("tcp_source_port must be nonzero")
	}
	if request.Timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", request.Timeout)
	}
	if err := request.Validate(); err == nil {
		t.Error("request without generation/flow id must not validate yet (filled by the runner)")
	}

	off := automaticSelfTestConfig()
	off.System.Classifier.Runtime.Capture.PPE.SelfTest.Mode = config.PPESelfTestOff
	if _, ok := service.automaticSelfTestRequest(off); ok {
		t.Error("mode off must not produce an automatic request")
	}

	manual := automaticSelfTestConfig()
	manual.System.Classifier.Runtime.Capture.PPE.SelfTest.Mode = config.PPESelfTestManual
	if _, ok := service.automaticSelfTestRequest(manual); ok {
		t.Error("mode manual must not produce an automatic request")
	}

	noEndpoint := automaticSelfTestConfig()
	noEndpoint.System.Classifier.Runtime.Capture.PPE.SelfTest.ControlledEndpoint = ""
	if _, ok := service.automaticSelfTestRequest(noEndpoint); ok {
		t.Error("empty controlled endpoint must not produce an automatic request")
	}

	if _, ok := service.automaticSelfTestRequest(nil); ok {
		t.Error("nil config must not produce an automatic request")
	}
}

func newAutomaticSelfTestService(runner SelfTestRunner, transactions *TransactionManager, cfg *config.Config) *ProductService {
	if transactions == nil {
		transactions = NewTransactionManager(newFakeTransactionBackend())
	}
	return &ProductService{
		selfTest:     runner,
		transactions: transactions,
		provider:     func() *config.Config { return cfg },
	}
}

func TestMaybeRunAutomaticSelfTestSkipsWithoutGeneration(t *testing.T) {
	DefaultVisibilityGate().DisableRequirement("test reset")
	runner := &recordingSelfTestRunner{}
	service := newAutomaticSelfTestService(runner, nil, automaticSelfTestConfig())
	service.maybeRunAutomaticSelfTest()
	if runner.callCount() != 0 {
		t.Fatalf("automatic self-test must not run without an active generation")
	}
}

func TestMaybeRunAutomaticSelfTestSkipsWhenModeOff(t *testing.T) {
	DefaultVisibilityGate().DisableRequirement("test reset")
	transactions := NewTransactionManager(newFakeTransactionBackend())
	if _, err := transactions.Apply(context.Background(), desiredTransactionState("generation-1")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	cfg := automaticSelfTestConfig()
	cfg.System.Classifier.Runtime.Capture.PPE.SelfTest.Mode = config.PPESelfTestOff
	runner := &recordingSelfTestRunner{}
	service := newAutomaticSelfTestService(runner, transactions, cfg)
	service.maybeRunAutomaticSelfTest()
	if runner.callCount() != 0 {
		t.Fatalf("automatic self-test must not run when mode is off")
	}
}

func TestMaybeRunAutomaticSelfTestSkipsWhenAlreadyProven(t *testing.T) {
	gate := DefaultVisibilityGate()
	gate.PublishSelfTestForGeneration("generation-1", CaptureVisibilityResult{Verdict: VerdictPASS, ProductionReady: true})
	transactions := NewTransactionManager(newFakeTransactionBackend())
	if _, err := transactions.Apply(context.Background(), desiredTransactionState("generation-1")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	runner := &recordingSelfTestRunner{}
	service := newAutomaticSelfTestService(runner, transactions, automaticSelfTestConfig())
	service.maybeRunAutomaticSelfTest()
	if runner.callCount() != 0 {
		t.Fatalf("automatic self-test must not rerun for an already proven generation")
	}
}

func TestMaybeRunAutomaticSelfTestRuns(t *testing.T) {
	gate := DefaultVisibilityGate()
	gate.DisableRequirement("test reset")
	transactions := NewTransactionManager(newFakeTransactionBackend())
	if _, err := transactions.Apply(context.Background(), desiredTransactionState("generation-1")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	recorder := &recordingSelfTestRunner{started: make(chan struct{}, 1), release: make(chan struct{})}
	runner := WrapSelfTestRunnerWithVisibility(recorder, gate)
	service := newAutomaticSelfTestService(runner, transactions, automaticSelfTestConfig())
	service.maybeRunAutomaticSelfTest()

	select {
	case <-recorder.started:
	case <-time.After(2 * time.Second):
		t.Fatal("automatic self-test was not started")
	}
	close(recorder.release)
	waitForAutomaticSelfTest(t, service, 2*time.Second)

	requests := recorder.requests()
	if len(requests) != 1 {
		t.Fatalf("calls = %d, want 1", len(requests))
	}
	request := requests[0]
	if request.Generation != "generation-1" {
		t.Errorf("generation = %q, want generation-1", request.Generation)
	}
	if request.RunID != "auto-generation-1" || request.TCPFlowID != "auto-generation-1-tcp" {
		t.Errorf("unexpected run identifiers: %+v", request)
	}
	if err := request.Validate(); err != nil {
		t.Errorf("automatic request must validate: %v", err)
	}

	service.mu.Lock()
	last := service.lastSelfTest
	service.mu.Unlock()
	if last == nil || last.Verdict != VerdictPASS {
		t.Fatalf("last self-test not recorded: %+v", last)
	}

	snapshot := gate.Snapshot()
	if snapshot.Mode != VisibilityComplete || snapshot.Generation != "generation-1" || snapshot.LastVerdict != VerdictPASS {
		t.Errorf("gate not completed for the generation: %+v", snapshot)
	}

	// The generation is now proven: a second apply of the same generation
	// must not trigger another automatic run.
	service.maybeRunAutomaticSelfTest()
	time.Sleep(50 * time.Millisecond)
	if got := recorder.callCount(); got != 1 {
		t.Fatalf("calls after proven = %d, want 1", got)
	}
}

func TestMaybeRunAutomaticSelfTestSingleFlight(t *testing.T) {
	gate := DefaultVisibilityGate()
	gate.DisableRequirement("test reset")
	transactions := NewTransactionManager(newFakeTransactionBackend())
	if _, err := transactions.Apply(context.Background(), desiredTransactionState("generation-1")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	recorder := &recordingSelfTestRunner{started: make(chan struct{}, 1), release: make(chan struct{})}
	runner := WrapSelfTestRunnerWithVisibility(recorder, gate)
	service := newAutomaticSelfTestService(runner, transactions, automaticSelfTestConfig())

	service.maybeRunAutomaticSelfTest()
	select {
	case <-recorder.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first automatic self-test was not started")
	}
	// While the first run is in flight, a concurrent apply must not start a
	// second probe.
	service.maybeRunAutomaticSelfTest()
	time.Sleep(50 * time.Millisecond)
	if got := recorder.callCount(); got != 1 {
		t.Fatalf("calls while in flight = %d, want 1", got)
	}

	close(recorder.release)
	waitForAutomaticSelfTest(t, service, 2*time.Second)
	if got := recorder.callCount(); got != 1 {
		t.Fatalf("calls after completion = %d, want 1", got)
	}
}
