package nfq

import (
	"context"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/dhcp"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/metrics"
	"github.com/daniellavrushin/b4/sni"
)

func NewWorkerWithQueue(cfg *config.Config, qnum uint16) *Worker {
	ctx, cancel := context.WithCancel(context.Background())

	w := &Worker{
		qnum:              qnum,
		ctx:               ctx,
		cancel:            cancel,
		dnsHints:          classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, nil),
		tcpReassembly:     classifier.NewTCPReassemblyStore(classifier.DefaultTCPReassemblyConfig()),
		tcpHold:           NewTCPHoldStore(DefaultTCPHoldConfig()),
		clientHelloClaims: newClientHelloDecisionClaimStore(),
		gsoPassTokens:     NewGSOPassTokenStore(DefaultGSOPassTokenStoreConfig()),
		actionTokens:      action.NewActionTokenStore(action.DefaultActionTokenStoreConfig()),
	}

	w.cfg.Store(cfg)
	w.gsoCapability.Store(defaultGSOCapabilityStatus())

	return w
}

func (p *Pool) EnableTUNSourceResolver(wanIP string) {
	if p.tunSrc == nil {
		if f, err := os.Open(conntrackPath); err != nil {
			log.Warnf("TUN: per-device source attribution unavailable (%s not readable: %v); device logging/filtering will show the uplink address in TUN mode", conntrackPath, err)
			return
		} else {
			f.Close()
		}
		p.tunSrc = newTunSrcResolver(wanIP)
	} else {
		p.tunSrc.setWAN(wanIP)
	}
	for _, w := range p.Workers {
		w.srcResolver = p.tunSrc
	}
	log.Infof("TUN: source attribution enabled (recovering LAN source from conntrack; uplink %s)", wanIP)
}

func (p *Pool) UpdateTUNSourceWAN(wanIP string) {
	if p.tunSrc == nil || wanIP == "" {
		return
	}
	p.tunSrc.setWAN(wanIP)
}

func NewPool(cfg *config.Config) *Pool {
	return newPoolWithState(cfg, false, nil, true, false, 0)
}

func NewCandidatePool(cfg *config.Config) *Pool {
	return newPoolWithState(cfg, true, nil, true, false, 0)
}

// NewGSOPrimaryPool builds a production-classifier pool wired to a dedicated
// secondary normalizer queue. It does not start listeners or install rules.
func NewGSOPrimaryPool(cfg *config.Config, normalizerQueue uint16) *Pool {
	return newPoolWithState(cfg, false, nil, false, false, normalizerQueue)
}

// NewGSONormalizerPool shares immutable flow/action/token state with its
// primary pool. A token miss accepts unchanged and never falls back to a second
// classification pass.
func NewGSONormalizerPool(cfg *config.Config, primary *Pool) *Pool {
	if primary == nil || primary.state == nil {
		return nil
	}
	return newPoolWithState(cfg, false, primary.state, false, true, 0)
}

func newPoolWithState(cfg *config.Config, candidate bool, shared *runtimeState, startDHCP, normalizer bool, normalizerQueue uint16) *Pool {
	threads := cfg.Queue.Threads
	start := uint16(cfg.Queue.StartNum)
	if threads < 1 {
		threads = 1
	}

	matcher := buildMatcher(cfg)
	hintStore := classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, nil)
	var canary *CanaryMonitor
	if candidate {
		canary = NewCanaryMonitor(0, 0)
	}

	state := shared
	ownsState := state == nil
	if state == nil {
		state = newRuntimeState(cfg)
	}
	if state.passiveRST != nil && ownsState {
		environment := PassiveRSTEnvironmentProduction
		if candidate {
			environment = PassiveRSTEnvironmentCandidate
		} else if cfg.Queue.IsDiscovery {
			environment = PassiveRSTEnvironmentDiscovery
		}
		state.passiveRST.SetEnvironment(environment)
	}
	var dhcpMgr *dhcp.Manager
	if startDHCP {
		dhcpMgr = dhcp.NewManager()
	}
	ws := make([]*Worker, 0, threads)
	for i := 0; i < threads; i++ {
		w := NewWorkerWithQueue(cfg, start+uint16(i))
		w.candidate = candidate
		w.matcher.Store(matcher)
		w.ipToMac.Store(make(map[string]string))
		w.tlsCache = state.tlsCache
		w.connTracker = state.connState
		w.destState = state.destState
		w.scopedFailures = state.scopedFailures
		w.routeBindings = state.routeBindings
		w.fallback = state.fallback
		w.gsoPassTokens = state.gsoPassTokens
		w.actionTokens = state.actionTokens
		w.passiveRST = state.passiveRST
		w.dnsHints = hintStore
		w.canary = canary
		w.candidateSet.Store("")
		w.configureGSONormalizer(normalizerQueue, normalizer)
		ws = append(ws, w)
	}

	pool := &Pool{Workers: ws, Dhcp: dhcpMgr, stopCleanup: make(chan struct{}), state: state, canary: canary, candidate: candidate, ownsState: ownsState}

	if dhcpMgr != nil {
		dhcpMgr.OnUpdate(func(ipToMAC map[string]string) {
			for _, w := range pool.Workers {
				w.ipToMac.Store(ipToMAC)
			}
			log.Infof("DHCP: updated %d IP->MAC mappings", len(ipToMAC))
		})

		dhcpMgr.SetManualDevices(cfg.Queue.Devices.ManualEntries())
		dhcpMgr.Start()

		initialMappings := dhcpMgr.GetAllMappings()
		for _, w := range pool.Workers {
			w.ipToMac.Store(initialMappings)
		}
		log.Infof("DHCP: initial load %d IP->MAC mappings", len(initialMappings))
	}

	if ownsState {
		go func() {
			cleanupTicker := time.NewTicker(30 * time.Second)
			defer cleanupTicker.Stop()
			escalationTicker := time.NewTicker(2 * time.Second)
			defer escalationTicker.Stop()
			for {
				select {
				case <-cleanupTicker.C:
					pool.state.connState.Cleanup()
					pool.state.tlsCache.Cleanup()
					pool.state.destState.Cleanup(300 * time.Second)
					pool.state.scopedFailures.GC(time.Now())
					pool.state.routeBindings.GC(time.Now())
					if pool.state.fallback != nil {
						pool.state.fallback.GC(time.Now())
					}
					if pool.state.passiveRST != nil {
						pool.state.passiveRST.GC(time.Now())
					}
					for _, worker := range pool.Workers {
						if worker.tcpReassembly != nil {
							worker.tcpReassembly.GC(time.Now())
						}
						if worker.tcpHold != nil {
							worker.tcpHold.GC(time.Now())
						}
						if worker.clientHelloClaims != nil {
							worker.clientHelloClaims.GC(time.Now())
						}
					}
				case <-escalationTicker.C:
					metrics.GetMetricsCollector().UpdateEscalations(pool.GetEscalations())
				case <-pool.stopCleanup:
					return
				}
			}
		}()
	}

	return pool
}

// StartDHCP attaches device identity ownership when a pre-built topology is
// about to start classifier workers. It is idempotent and intentionally kept
// separate from topology reservation.
func (p *Pool) StartDHCP(cfg *config.Config) {
	if p == nil || cfg == nil || p.Dhcp != nil {
		return
	}
	dhcpMgr := dhcp.NewManager()
	p.Dhcp = dhcpMgr
	dhcpMgr.OnUpdate(func(ipToMAC map[string]string) {
		for _, w := range p.Workers {
			w.ipToMac.Store(ipToMAC)
		}
		log.Infof("DHCP: updated %d IP->MAC mappings", len(ipToMAC))
	})
	dhcpMgr.SetManualDevices(cfg.Queue.Devices.ManualEntries())
	dhcpMgr.Start()
	initialMappings := dhcpMgr.GetAllMappings()
	for _, w := range p.Workers {
		w.ipToMac.Store(initialMappings)
	}
	log.Infof("DHCP: initial load %d IP->MAC mappings", len(initialMappings))
}

func (p *Pool) SetCanarySetID(setID string) {
	if p == nil || !p.candidate {
		return
	}
	for _, worker := range p.Workers {
		worker.candidateSet.Store(setID)
	}
}

func (p *Pool) ResetCanary() {
	if p != nil && p.canary != nil {
		p.canary.Reset()
	}
}

func (p *Pool) CanarySnapshot() CanarySnapshot {
	if p == nil || p.canary == nil {
		return CanarySnapshot{CapturedAt: time.Now()}
	}
	return p.canary.Snapshot(time.Now())
}

func (p *Pool) Start() error {
	for _, w := range p.Workers {
		var err error
		if p.candidate {
			err = w.StartCandidate()
		} else {
			err = w.Start()
		}
		if err != nil {
			for _, x := range p.Workers {
				x.Stop()
			}
			return err
		}
	}
	return nil
}

func (p *Pool) Stop() {
	if p.Dhcp != nil {
		p.Dhcp.Stop()
	}

	// Stop the connState cleanup goroutine
	select {
	case <-p.stopCleanup:
		// already closed
	default:
		close(p.stopCleanup)
	}

	var wg sync.WaitGroup
	for _, w := range p.Workers {
		wg.Add(1)
		worker := w
		go func() {
			defer wg.Done()
			worker.Stop()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	timeout := 5 * time.Second

	select {
	case <-done:
		if p.ownsState && p.state != nil && p.state.passiveRST != nil {
			p.state.passiveRST.Clear()
		}
		log.Infof("All NFQueue workers stopped")
	case <-time.After(timeout):
		log.Errorf("Timeout (%v) waiting for NFQueue workers to stop", timeout)
	}
}

func (w *Worker) getConfig() *config.Config {
	return w.cfg.Load().(*config.Config)
}

func (w *Worker) getMatcher() *sni.SuffixSet {
	return w.matcher.Load().(*sni.SuffixSet)
}

func (w *Worker) UpdateConfig(newCfg *config.Config) {
	oldCfg := w.getConfig()
	oldGeneration := dnsHintConfigGeneration(oldCfg)
	newGeneration := dnsHintConfigGeneration(newCfg)
	if oldGeneration != 0 && oldGeneration != newGeneration {
		if w.gsoPassTokens != nil {
			w.gsoPassTokens.InvalidateGeneration(oldGeneration)
		}
		if w.actionTokens != nil {
			w.actionTokens.InvalidateGeneration(oldGeneration)
		}
		if w.passiveRST != nil {
			w.passiveRST.InvalidateGeneration(oldGeneration)
		}
	}
	if w.passiveRST != nil && newCfg != nil {
		w.passiveRST.Reconfigure(newCfg.System.Classifier.Runtime.PassiveRST)
	}
	w.cfg.Store(newCfg)
}

func buildMatcher(cfg *config.Config) *sni.SuffixSet {
	if len(cfg.Sets) > 0 {
		m := sni.NewSuffixSet(cfg.Sets)
		totalDomains := 0
		totalIPs := 0
		for _, set := range cfg.Sets {
			totalDomains += len(set.Targets.DomainsToMatch)
			totalIPs += len(set.Targets.IpsToMatch)
		}
		log.Infof("Built matcher with %d domains and %d IPs across %d sets",
			totalDomains, totalIPs, len(cfg.Sets))
		return m
	}
	log.Tracef("Built empty matcher")
	return sni.NewSuffixSet([]*config.SetConfig{})
}

func (p *Pool) UpdateConfig(newCfg *config.Config) error {
	p.configMu.Lock()
	defer p.configMu.Unlock()

	var oldMatcher *sni.SuffixSet
	reuse := false
	var oldCfg *config.Config
	if len(p.Workers) > 0 {
		oldMatcher = p.Workers[0].getMatcher()
		oldCfg = p.Workers[0].getConfig()
		if oldCfg != nil {
			reuse = reflect.DeepEqual(oldCfg.Sets, newCfg.Sets)
		}
	}
	if len(p.Workers) > 0 {
		oldGeneration := dnsHintConfigGeneration(oldCfg)
		newGeneration := dnsHintConfigGeneration(newCfg)
		if oldGeneration != 0 && oldGeneration != newGeneration {
			if p.Workers[0].dnsHints != nil {
				p.Workers[0].dnsHints.InvalidateGeneration(oldGeneration)
			}
			if p.state != nil && p.state.gsoPassTokens != nil {
				p.state.gsoPassTokens.InvalidateGeneration(oldGeneration)
			}
			if p.state != nil && p.state.actionTokens != nil {
				p.state.actionTokens.InvalidateGeneration(oldGeneration)
			}
		}
	}

	matcher := oldMatcher
	if !reuse {
		matcher = buildMatcher(newCfg)
		if oldMatcher != nil {
			matcher.TransferLearnedIPs(oldMatcher)
		}
	}

	for _, w := range p.Workers {
		w.cfg.Store(newCfg)
		w.matcher.Store(matcher)
	}

	if !reuse && p.state != nil && p.state.destState != nil {
		p.state.destState.ResetEscalations()
	}

	if p.Dhcp != nil {
		p.Dhcp.SetManualDevices(newCfg.Queue.Devices.ManualEntries())
	}

	return nil
}

func (p *Pool) GetIPBlockCache() IPBlockCache {
	return p.state.destState
}

func (p *Pool) GetEscalations() []metrics.EscalationEntry {
	if p.state == nil || p.state.destState == nil {
		return nil
	}
	cfg := p.GetFirstWorkerConfig()
	snaps := p.state.destState.ListEscalations()
	out := make([]metrics.EscalationEntry, 0, len(snaps))
	for _, s := range snaps {
		toName := s.SetId
		if cfg != nil {
			if set := cfg.GetSetById(s.SetId); set != nil && set.Name != "" {
				toName = set.Name
			}
		}
		out = append(out, metrics.EscalationEntry{
			Host:      s.Host,
			ToSet:     toName,
			Hops:      s.Hops,
			SetAt:     s.SetAt,
			ExpiresAt: s.ExpiresAt,
		})
	}
	return out
}

func (p *Pool) ClearEscalations() {
	if p.state != nil && p.state.destState != nil {
		p.state.destState.ResetEscalations()
	}
}

func (p *Pool) ClearEscalation(host string) {
	if p.state != nil && p.state.destState != nil {
		p.state.destState.ClearEscalation(host)
	}
}

func (p *Pool) GetMatcher() *sni.SuffixSet {
	if len(p.Workers) == 0 {
		return nil
	}
	return p.Workers[0].getMatcher()
}

func (p *Pool) GetFirstWorkerConfig() *config.Config {
	if len(p.Workers) == 0 {
		return nil
	}
	return p.Workers[0].getConfig()
}

func (w *Worker) GetCacheStats() map[string]interface{} {
	matcher := w.getMatcher()
	return matcher.GetCacheStats()
}

// RecordPassiveRSTHealth feeds scoped canary/baseline regressions into the
// runtime rollback monitor. Production, candidate and discovery pools own
// separate stores, so their suppression state cannot mix.
func (p *Pool) RecordPassiveRSTHealth(sample PassiveRSTHealthSample) (PassiveRSTRollbackState, bool) {
	if p == nil || p.state == nil || p.state.passiveRST == nil || len(p.Workers) == 0 {
		return PassiveRSTRollbackState{}, false
	}
	cfg, _ := p.Workers[0].cfg.Load().(*config.Config)
	if cfg == nil {
		return PassiveRSTRollbackState{}, false
	}
	if sample.ConfigGeneration == 0 {
		sample.ConfigGeneration = dnsHintConfigGeneration(cfg)
	}
	if sample.Environment == "" {
		switch {
		case p.candidate:
			sample.Environment = PassiveRSTEnvironmentCandidate
		case cfg.Queue.IsDiscovery:
			sample.Environment = PassiveRSTEnvironmentDiscovery
		default:
			sample.Environment = PassiveRSTEnvironmentProduction
		}
	}
	return p.state.passiveRST.RecordHealth(cfg.System.Classifier.Runtime.PassiveRST, sample)
}

func (p *Pool) PassiveRSTRollbacks(limit int) []PassiveRSTRollbackState {
	if p == nil || p.state == nil || p.state.passiveRST == nil {
		return nil
	}
	return p.state.passiveRST.RecentRollbacks(limit)
}
