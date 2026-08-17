package ppe

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

type SelfTestController struct {
	mu         sync.Mutex
	capability func(context.Context) (CapabilityReport, error)
	policy     func() string
	health     HealthChecker
	probe      ProbeExecutor
	isolation  ABIsolation
	counters   RuleCounterSource
	bus        *ObservationBus
	store      SelfTestResultStore
	now        func() time.Time
}

func NewSelfTestController(capability func(context.Context) (CapabilityReport, error), policy func() string, health HealthChecker, probe ProbeExecutor, isolation ABIsolation, counters RuleCounterSource, bus *ObservationBus, store SelfTestResultStore) *SelfTestController {
	if bus == nil {
		bus = NewObservationBus()
	}
	if store == nil {
		store = NewMemorySelfTestStore(64)
	}
	return &SelfTestController{capability: capability, policy: policy, health: health, probe: probe, isolation: isolation, counters: counters, bus: bus, store: store, now: time.Now}
}

func (c *SelfTestController) Run(ctx context.Context, request SelfTestRequest) (result CaptureVisibilityResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	started := c.now().UTC()
	result = CaptureVisibilityResult{RunID: request.RunID, StartedAt: started, Verdict: VerdictINCONCLUSIVE}
	defer func() {
		result.CompletedAt = c.now().UTC()
		if c.store != nil {
			c.store.Put(result)
		}
	}()
	if err := request.Validate(); err != nil {
		return failResult(result, "validate", VerdictINCONCLUSIVE, err)
	}
	if c.capability == nil || c.health == nil || c.probe == nil || c.isolation == nil {
		return failResult(result, "dependencies", VerdictINCONCLUSIVE, errors.New("self-test dependencies are incomplete"))
	}
	capability, err := c.capability(ctx)
	if err != nil {
		return failResult(result, "capability", VerdictINCONCLUSIVE, err)
	}
	result.Capability = capability.State
	result.IPv4Active = request.Family == "ipv4" && capability.IPv4.State == CapabilitySupported
	result.IPv6Active = request.Family == "ipv6" && capability.IPv6.State == CapabilitySupported
	result.TCPActive = true
	result.QUICActive = request.RequireQUIC
	if c.policy != nil {
		result.Policy = c.policy()
	}
	if !capability.Supported || capability.State != CapabilitySupported {
		return failResult(result, "capability", VerdictUNSUPPORTED, errors.New("PPE capability is not fully supported"))
	}
	healthEndpoint := strings.TrimSpace(request.HealthEndpoint)
	if healthEndpoint == "" {
		healthEndpoint = request.ControlledEndpoint
	}
	if err := c.health.Check(ctx, healthEndpoint); err != nil {
		return failResult(result, "endpoint_health", VerdictINCONCLUSIVE, err)
	}
	if c.counters != nil {
		result.RuleCountersBefore, _ = c.counters.RuleCounters(ctx)
	}

	cleanup, err := c.isolation.BeginBypass(ctx, request.RunID, request.Family, request.TCPSourcePort, request.QUICSourcePort)
	if err != nil {
		return failResult(result, "phase_a_isolation", VerdictINCONCLUSIVE, err)
	}
	phaseA, phaseErr := c.runPhase(ctx, request, PhaseWithoutExclusion)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cleanupErr := cleanup(cleanupCtx)
	cancel()
	if phaseErr != nil {
		return failResult(result, "phase_a_probe", VerdictINCONCLUSIVE, phaseErr)
	}
	if cleanupErr != nil {
		return failResult(result, "phase_a_cleanup", VerdictINCONCLUSIVE, cleanupErr)
	}
	result.PhaseA = phaseA

	phaseB, err := c.runPhase(ctx, request, PhaseWithExclusion)
	if err != nil {
		return failResult(result, "phase_b_probe", VerdictINCONCLUSIVE, err)
	}
	result.PhaseB = phaseB
	if err := c.isolation.VerifyActive(ctx, request.Generation); err != nil {
		return failResult(result, "generation_verify", VerdictINCONCLUSIVE, err)
	}
	if c.counters != nil {
		result.RuleCountersAfter, _ = c.counters.RuleCounters(ctx)
	}
	return evaluateSelfTest(result, request.RequireQUIC, request.AllowLimitedApply)
}
