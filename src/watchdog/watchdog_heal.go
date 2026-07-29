package watchdog

import (
	"time"

	"github.com/daniellavrushin/b4/discovery"
	"github.com/daniellavrushin/b4/log"
)

func (w *Watchdog) healBatch(domains []string) {
	cfg := w.cfgPtr.Load()
	wdCfg := cfg.System.Checker.Watchdog

	if w.discoveryRT.IsActive() {
		log.Infof("[WATCHDOG] deferring healing — user discovery active")
		return
	}

	w.mu.Lock()
	for _, domain := range domains {
		if st, ok := w.domainStates[domain]; ok {
			st.Status = StatusEscalating
		}
	}
	w.mu.Unlock()

	log.Infof("[WATCHDOG] starting discovery for %d domains: %v", len(domains), domains)

	suite, err := w.discoveryRT.StartSuite(cfg, domains, discovery.StartSuiteOptions{
		SkipDNS:         true,
		ValidationTries: 1,
		Automatic:       true,
	})
	if err != nil {
		log.Warnf("[WATCHDOG] failed to start discovery: %v", err)
		w.mu.Lock()
		for _, domain := range domains {
			st, ok := w.domainStates[domain]
			if !ok {
				continue
			}
			st.Status = StatusDegraded
			st.ConsecutiveFailures = 0
			st.CooldownUntil = time.Now().Add(time.Duration(wdCfg.Cooldown) * time.Second)
		}
		w.mu.Unlock()
		return
	}

	pollTicker := time.NewTicker(2 * time.Second)
	defer pollTicker.Stop()
	for {
		select {
		case <-w.stop:
			log.Infof("[WATCHDOG] shutting down, canceling active discovery")
			discovery.CancelCheckSuite(suite.Id)
			w.discoveryRT.Stop(suite.Id)
			return
		case <-pollTicker.C:
		}

		currentCfg := w.cfgPtr.Load()
		if !currentCfg.System.Checker.Watchdog.Enabled {
			log.Infof("[WATCHDOG] disabled during healing, canceling discovery")
			discovery.CancelCheckSuite(suite.Id)
			w.discoveryRT.Stop(suite.Id)
			w.mu.Lock()
			for _, domain := range domains {
				if st, ok := w.domainStates[domain]; ok {
					st.Status = StatusDegraded
					st.ConsecutiveFailures = 0
				}
			}
			w.mu.Unlock()
			return
		}

		cs, ok := discovery.GetCheckSuite(suite.Id)
		if !ok {
			break
		}
		if cs.Status == discovery.CheckStatusComplete || cs.Status == discovery.CheckStatusFailed || cs.Status == discovery.CheckStatusCanceled {
			break
		}
		if cs.SuccessfulChecks >= len(domains) {
			log.Infof("[WATCHDOG] working strategies found for all domains, canceling discovery early")
			discovery.CancelCheckSuite(suite.Id)
			time.Sleep(1 * time.Second)
			break
		}
	}

	cs, ok := discovery.GetCheckSuite(suite.Id)
	if !ok {
		log.Warnf("[WATCHDOG] discovery suite disappeared")
		w.mu.Lock()
		for _, domain := range domains {
			st, ok := w.domainStates[domain]
			if !ok {
				continue
			}
			st.Status = StatusDegraded
			st.ConsecutiveFailures = 0
			st.CooldownUntil = time.Now().Add(time.Duration(wdCfg.Cooldown) * time.Second)
		}
		w.mu.Unlock()
		return
	}

	freshCfg := w.cfgPtr.Load().Clone()
	applyErrors := applyBatchResults(freshCfg, domains, cs, w.saveFunc)

	w.mu.Lock()
	defer w.mu.Unlock()

	for _, domain := range domains {
		st, ok := w.domainStates[domain]
		if !ok {
			continue
		}
		if err, failed := applyErrors[domain]; failed && err != nil {
			log.Warnf("[WATCHDOG] %s: %v, cooldown %ds", domain, err, wdCfg.Cooldown)
			st.Status = StatusDegraded
			st.ConsecutiveFailures = 0
			st.CooldownUntil = time.Now().Add(time.Duration(wdCfg.Cooldown) * time.Second)
			continue
		}

		dr := cs.DomainDiscoveryResults[ExtractDomain(domain)]
		if dr != nil && dr.BestSuccess {
			log.Infof("[WATCHDOG] %s: healed (%s, %.0f KB/s)", domain, dr.BestPreset, dr.BestSpeed/1024)
		}
		st.Status = StatusHealthy
		st.ConsecutiveFailures = 0
		st.Interval = wdCfg.IntervalSec
		st.LastHeal = time.Now()
		st.LastError = ""
		st.CooldownUntil = time.Now().Add(time.Duration(wdCfg.Cooldown) * time.Second)
	}
}
