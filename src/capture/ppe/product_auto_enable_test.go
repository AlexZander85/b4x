package ppe

// FB-21 owner integration: on a fresh installation (no user-chosen
// provenance) a Keenetic NDM + MediaTek platform with a supported capability
// may be auto-integrated into per-flow exclusion, but only through the staged
// readiness pipeline: capability probe, transactional apply, pre-commit
// visibility self-test, durable persist. Any failure leaves the product in
// detect with zero leaked rules. Explicit user choices are never overwritten.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

// verdictSelfTestRunner returns a fixed verdict for every Run invocation.
type verdictSelfTestRunner struct {
	verdict SelfTestVerdict
	calls   int
}

func (r *verdictSelfTestRunner) Run(_ context.Context, request SelfTestRequest) CaptureVisibilityResult {
	r.calls++
	now := time.Now().UTC()
	return CaptureVisibilityResult{RunID: request.RunID, Verdict: r.verdict, ProductionReady: r.verdict == VerdictPASS, StartedAt: now, CompletedAt: now}
}

// autoEnableConfig builds the fresh-install configuration: detect policy with
// no user-chosen provenance and automatic visibility self-test enabled.
func autoEnableConfig() *config.Config {
	cfg := config.DefaultConfig
	cfg.System.Classifier.Runtime.Capture.OffloadPolicy = config.OffloadPolicyDetect
	cfg.System.Classifier.Runtime.Capture.OffloadPolicyUserChosen = false
	cfg.System.Classifier.Runtime.Capture.PPE.SelfTest.Mode = config.PPESelfTestStartupAndChange
	cfg.System.Classifier.Runtime.Capture.PPE.SelfTest.ControlledEndpoint = "https://example.test/health"
	cfg.System.Classifier.Runtime.Capture.PPE.SelfTest.TimeoutMS = 3000
	return &cfg
}

func newAutoEnableService(runner SelfTestRunner, cfg *config.Config, persist func(*config.Config) error) (*ProductService, *fakeTransactionBackend) {
	backend := newFakeTransactionBackend()
	service := &ProductService{
		detector:         NewDetector(supportedRunner()),
		selfTest:         runner,
		transactions:     NewTransactionManager(backend),
		provider:         func() *config.Config { return cfg },
		managedSourceSet: DefaultManagedSourceSet,
	}
	if persist != nil {
		service.SetConfigPersister(persist)
	}
	return service, backend
}

func findAuditEvent(service *ProductService, operation string) *ProductAuditEvent {
	service.mu.Lock()
	defer service.mu.Unlock()
	for i := len(service.audit) - 1; i >= 0; i-- {
		if service.audit[i].Operation == operation {
			event := service.audit[i]
			return &event
		}
	}
	return nil
}

func TestAutoEnableCommitPathOnFreshKeeneticMediaTek(t *testing.T) {
	DefaultVisibilityGate().DisableRequirement("test reset")
	cfg := autoEnableConfig()
	// Zero ports in the config must not break the self-test request: the
	// integration must fall back to a usable source port.
	cfg.System.Classifier.Runtime.Capture.PPE.TCPPorts = []uint16{0, 0}

	var persisted *config.Config
	persistCalls := 0
	runner := &recordingSelfTestRunner{}
	service, _ := newAutoEnableService(runner, cfg, func(c *config.Config) error {
		persistCalls++
		persisted = c
		return nil
	})

	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if persistCalls == 0 {
		t.Fatal("auto-enable must durably commit on a fresh supported platform")
	}
	if persisted == nil {
		t.Fatal("persisted config is nil")
	}
	if got := persisted.System.Classifier.Runtime.Capture.OffloadPolicy; got != config.OffloadPolicyExclude {
		t.Errorf("persisted policy = %q, want %q", got, config.OffloadPolicyExclude)
	}
	if persisted.System.Classifier.Runtime.Capture.OffloadPolicyUserChosen {
		t.Error("auto-enable must not mark the policy as user-chosen")
	}
	if _, ok := service.transactions.Current(); !ok {
		t.Error("no active generation after successful auto-enable")
	}
	if event := findAuditEvent(service, "auto-enable"); event == nil || !event.Success {
		t.Errorf("expected success auto-enable audit event, got %+v", event)
	}
	service.Stop(context.Background())
}

func TestAutoEnableSelfTestRequestUsesFirstNonZeroPort(t *testing.T) {
	cfg := autoEnableConfig()
	cfg.System.Classifier.Runtime.Capture.PPE.TCPPorts = []uint16{0, 0, 8443}
	service, _ := newAutoEnableService(&recordingSelfTestRunner{}, cfg, func(c *config.Config) error { return nil })

	request, ok := service.automaticSelfTestRequest(cfg)
	if !ok {
		t.Fatal("startup-and-change mode with endpoint must produce a request")
	}
	if request.TCPSourcePort != 8443 {
		t.Errorf("source port = %d, want 8443 (first non-zero)", request.TCPSourcePort)
	}

	cfg.System.Classifier.Runtime.Capture.PPE.TCPPorts = []uint16{0}
	request, ok = service.automaticSelfTestRequest(cfg)
	if !ok {
		t.Fatal("request must still be produced when all ports are zero")
	}
	if request.TCPSourcePort == 0 {
		t.Error("zero-only port list must fall back to a usable default")
	}
}

func TestAutoEnableNeverTouchesUserChosenPolicy(t *testing.T) {
	cfg := autoEnableConfig()
	cfg.System.Classifier.Runtime.Capture.OffloadPolicyUserChosen = true

	failed := false
	runner := &recordingSelfTestRunner{}
	service, _ := newAutoEnableService(runner, cfg, func(c *config.Config) error {
		failed = true
		return nil
	})

	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if failed {
		t.Error("auto-enable must not commit when the user chose the policy explicitly")
	}
	if runner.callCount() != 0 {
		t.Errorf("self-test calls = %d, want 0", runner.callCount())
	}
	if got := service.currentPolicy(); got != config.OffloadPolicyDetect {
		t.Errorf("policy = %q, want detect", got)
	}
	if _, ok := service.transactions.Current(); ok {
		t.Error("no rules must be installed for user-chosen detect")
	}
}

func TestAutoEnableSkipsWithoutPersister(t *testing.T) {
	cfg := autoEnableConfig()
	runner := &verdictSelfTestRunner{verdict: VerdictPASS}
	service, backend := newAutoEnableService(runner, cfg, nil)

	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if runner.calls != 0 {
		t.Errorf("self-test calls = %d, want 0 (persister missing aborts before the probe)", runner.calls)
	}
	if got := service.currentPolicy(); got != config.OffloadPolicyDetect {
		t.Errorf("policy = %q, want detect", got)
	}
	if len(backend.current) != 0 {
		t.Errorf("leaked rules without persister = %+v", backend.current)
	}
}

func TestAutoEnableRollbackOnSelfTestFailure(t *testing.T) {
	DefaultVisibilityGate().DisableRequirement("test reset")
	cfg := autoEnableConfig()
	runner := &verdictSelfTestRunner{verdict: VerdictFAIL}
	persistCalls := 0
	service, backend := newAutoEnableService(runner, cfg, func(c *config.Config) error {
		persistCalls++
		return nil
	})

	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if persistCalls != 0 {
		t.Errorf("persist calls = %d, want 0 after FAIL verdict", persistCalls)
	}
	if _, ok := service.transactions.Current(); ok {
		t.Error("no generation may remain after rollback")
	}
	if len(backend.current) != 0 {
		t.Errorf("leaked rules after self-test failure = %+v", backend.current)
	}
	if event := findAuditEvent(service, "auto-enable"); event == nil || event.Success {
		t.Errorf("expected rollback audit event, got %+v", event)
	}
}

func TestAutoEnableRollbackOnPersistFailure(t *testing.T) {
	DefaultVisibilityGate().DisableRequirement("test reset")
	cfg := autoEnableConfig()
	runner := &recordingSelfTestRunner{}
	persistErr := errors.New("durable commit failed")
	persistCalls := 0
	service, backend := newAutoEnableService(runner, cfg, func(c *config.Config) error {
		persistCalls++
		return persistErr
	})

	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if persistCalls == 0 {
		t.Fatal("persister must be reached before the failure path")
	}
	if _, ok := service.transactions.Current(); ok {
		t.Error("no generation may remain after persist failure")
	}
	if len(backend.current) != 0 {
		t.Errorf("leaked rules after persist failure = %+v", backend.current)
	}
	if event := findAuditEvent(service, "auto-enable"); event == nil || event.Success {
		t.Errorf("expected rollback audit event after persist failure, got %+v", event)
	}
}

func TestAutoEnableSkipsCapabilityFailure(t *testing.T) {
	cfg := autoEnableConfig()
	// Unsupported but NDM+MediaTek-looking platform: capability probe fails.
	cfg.System.Classifier.Runtime.Capture.PPE.TCPPorts = []uint16{443}
	runner := &recordingSelfTestRunner{}
	persistCalls := 0
	service, backend := newAutoEnableService(runner, cfg, func(c *config.Config) error {
		persistCalls++
		return nil
	})
	service.detector = NewDetector(&fakeRunner{
		ndm: true,
		files: map[string]string{
			"/proc/net/ip_tables_targets": "MARK\n",
			"/proc/sys/kernel/osrelease":  "5.10-test\n",
			"/proc/cpuinfo":               "Hardware: MediaTek MT7622\n",
		},
		paths: map[string]string{"iptables": "/sbin/iptables", "ip6tables": "/sbin/ip6tables", "ndmc": "/bin/ndmc"},
	})

	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if persistCalls != 0 {
		t.Errorf("persist calls = %d, want 0 when capability is unsupported", persistCalls)
	}
	if runner.callCount() != 0 {
		t.Errorf("self-test calls = %d, want 0", runner.callCount())
	}
	if got := service.currentPolicy(); got != config.OffloadPolicyDetect {
		t.Errorf("policy = %q, want detect", got)
	}
	if len(backend.current) != 0 {
		t.Errorf("leaked rules on capability failure = %+v", backend.current)
	}
}
