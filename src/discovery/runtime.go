package discovery

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/nfq"
)

var (
	ErrDiscoveryAlreadyRunning      = errors.New("discovery is already running")
	ErrAutomaticDiscoveryVisibility = errors.New("automatic Discovery requires complete capture visibility")
)

type poolStopper interface {
	Stop()
}

type runtimeState struct {
	pool              poolStopper
	sandbox           *SandboxHandle
	clearRules        func()
	discoveryStartNum int
	discoveryThreads  int
	discoveryFlowMark uint
	discoveryInjMark  uint
	activeSuiteID     string
	stopping          bool
	wg                sync.WaitGroup
}

type StartResult struct {
	Pool     *nfq.Pool
	FlowMark uint
}

type StartSuiteOptions struct {
	SkipDNS         bool
	SkipCache       bool
	PayloadFiles    []string
	ValidationTries int
	TLSVersion      string
	IPVersion       string
	Automatic       bool
}

type Runtime struct {
	mu    sync.Mutex
	state *runtimeState
}

func NewRuntime() *Runtime {
	return &Runtime{}
}

func (m *Runtime) IsActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state != nil
}

func (m *Runtime) Start(cfg *config.Config) (*StartResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cfg == nil {
		return nil, errors.New("discovery config is nil")
	}
	if m.state != nil {
		return nil, ErrDiscoveryAlreadyRunning
	}

	mainStart := cfg.Queue.StartNum
	mainThreads := cfg.Queue.Threads
	discoveryThreads := 1
	discoveryStart := mainStart + mainThreads
	discoveryEnd := discoveryStart + discoveryThreads - 1
	if discoveryStart < 0 || discoveryEnd > 65535 {
		return nil, fmt.Errorf("discovery queue range is out of bounds: %d-%d", discoveryStart, discoveryEnd)
	}

	flowMark := cfg.DiscoveryFlowMark()
	injectedMark := cfg.DiscoveryInjectedMark()

	log.Infof("Discovery queue range: main=%d-%d discovery=%d-%d", mainStart, mainStart+mainThreads-1, discoveryStart, discoveryEnd)
	log.Infof("Discovery marks: main_injected=0x%x discovery_flow=0x%x discovery_injected=0x%x", cfg.MainInjectedMark(), flowMark, injectedMark)

	runtimeCfg := cfg.Clone()
	backend := newRuntimeSandboxBackend(*runtimeCfg)
	leaseStore := SandboxLeaseStore(NewMemorySandboxLeaseStore(8))
	if cfg.ConfigPath != "" {
		leaseStore = &FileSandboxLeaseStore{Path: cfg.ConfigPath + ".discovery-sandboxes.json", Max: 8}
	}
	sandboxManager := NewSandboxManager(SandboxManagerConfig{Backend: backend, Leases: leaseStore, MaxActive: 1})
	if report, err := sandboxManager.Reconcile(context.Background()); err != nil {
		return nil, fmt.Errorf("reconcile discovery sandboxes: %w", err)
	} else if len(report.Errors) > 0 {
		return nil, fmt.Errorf("stale discovery sandbox cleanup incomplete: %s", report.Errors[0])
	}

	spec := SandboxSpec{
		ID:               "discovery-runtime",
		Mode:             SandboxBaselineProduction,
		QueueStart:       uint16(discoveryStart),
		QueueThreads:     uint16(discoveryThreads),
		FlowMark:         uint32(flowMark),
		ProcessedMark:    uint32(injectedMark),
		ConfigGeneration: cfg.RuntimeGeneration,
		ExcludeCandidate: true,
	}
	sandbox, err := sandboxManager.Acquire(context.Background(), spec)
	if err != nil {
		return nil, fmt.Errorf("start isolated discovery sandbox: %w", err)
	}
	pool := backend.Pool()
	if pool == nil {
		_ = sandbox.Close(context.Background())
		return nil, errors.New("discovery sandbox backend started without NFQUEUE pool")
	}
	m.state = &runtimeState{
		pool:              pool,
		sandbox:           sandbox,
		discoveryStartNum: discoveryStart,
		discoveryThreads:  discoveryThreads,
		discoveryFlowMark: flowMark,
		discoveryInjMark:  injectedMark,
	}

	return &StartResult{
		Pool:     pool,
		FlowMark: flowMark,
	}, nil
}

func (m *Runtime) SetActiveSuiteID(suiteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != nil {
		m.state.activeSuiteID = suiteID
	}
}

func (m *Runtime) StartSuite(cfg *config.Config, urls []string, opts StartSuiteOptions) (*DiscoverySuite, error) {
	if opts.Automatic {
		decision := ppe.DefaultVisibilityGate().Decision(ppe.VisibilityFeatureAutomaticDiscovery)
		if !decision.Allowed {
			return nil, fmt.Errorf("%w: %s", ErrAutomaticDiscoveryVisibility, decision.Reason)
		}
	}
	runtimeState, err := m.Start(cfg)
	if err != nil {
		return nil, err
	}

	suite := NewDiscoverySuite(
		urls,
		runtimeState.Pool,
		opts.SkipDNS,
		opts.SkipCache,
		opts.PayloadFiles,
		opts.ValidationTries,
		opts.TLSVersion,
		opts.IPVersion,
		runtimeState.FlowMark,
	)
	m.SetActiveSuiteID(suite.Id)
	RegisterSuite(suite.CheckSuite)

	log.GetDiscoveryHub().Reset()

	m.launchSuite(suite.Id, func() {
		suite.RunDiscovery()
		log.Infof("Discovery complete for %d domains", len(suite.Domains))
	})

	return suite, nil
}

func (m *Runtime) launchSuite(suiteID string, run func()) {
	m.mu.Lock()
	state := m.state
	if state == nil || state.stopping {
		m.mu.Unlock()
		return
	}
	state.wg.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.Stop(suiteID)
		defer state.wg.Done()
		run()
	}()
}

func (m *Runtime) Stop(suiteID string) {
	m.mu.Lock()
	state := m.state
	if state == nil || state.stopping {
		m.mu.Unlock()
		return
	}
	if suiteID != "" && state.activeSuiteID != "" && state.activeSuiteID != suiteID {
		m.mu.Unlock()
		return
	}
	state.stopping = true
	activeSuite := state.activeSuiteID
	m.mu.Unlock()

	if activeSuite != "" {
		CancelCheckSuite(activeSuite)
	}

	state.wg.Wait()

	if state.sandbox != nil {
		if err := state.sandbox.Close(context.Background()); err != nil {
			log.Errorf("Discovery sandbox cleanup failed: %v", err)
		}
	} else {
		state.pool.Stop()
		if state.clearRules != nil {
			state.clearRules()
		}
	}
	log.Infof("Discovery runtime stopped: queue=%d-%d", state.discoveryStartNum, state.discoveryStartNum+state.discoveryThreads-1)

	m.mu.Lock()
	m.state = nil
	m.mu.Unlock()
}
