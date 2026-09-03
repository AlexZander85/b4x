package watchdog

import (
	"time"

	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/netprobe"
)

func (w *Watchdog) run() {
	defer close(w.stopped)

	select {
	case <-w.stop:
		return
	case <-time.After(30 * time.Second):
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			w.tick()
		}
	}
}

func (w *Watchdog) tick() {
	cfg := w.cfgPtr.Load()
	wdCfg := cfg.System.Checker.Watchdog
	if !wdCfg.Enabled || len(wdCfg.Domains) == 0 {
		return
	}

	now := time.Now()
	mark := cfg.Queue.Mark
	timeout := time.Duration(wdCfg.TimeoutSec) * time.Second

	w.mu.Lock()
	w.syncDomainStates(wdCfg)

	var domainsToCheck []string
	for _, domain := range wdCfg.Domains {
		st := w.domainStates[domain]
		if st.Status == StatusEscalating {
			continue
		}
		if !st.LastCheck.IsZero() && now.Before(st.LastCheck.Add(time.Duration(st.Interval)*time.Second)) {
			continue
		}
		if !st.CooldownUntil.IsZero() && now.Before(st.CooldownUntil) {
			continue
		}
		domainsToCheck = append(domainsToCheck, domain)
	}
	w.mu.Unlock()

	if len(domainsToCheck) == 0 {
		return
	}

	results := checkAllConcurrently(domainsToCheck, mark, timeout)

	w.mu.Lock()
	var needsHealing []string
	for domain, result := range results {
		st, ok := w.domainStates[domain]
		if !ok {
			continue
		}
		st.LastCheck = now

		if result.OK {
			if st.Status == StatusDegraded {
				log.Infof("[WATCHDOG] %s: recovered (%.0f KB/s)", domain, result.Speed/1024)
			}
			st.ConsecutiveFailures = 0
			st.Status = StatusHealthy
			st.Interval = wdCfg.IntervalSec
			st.LastError = ""
			st.LastSpeed = result.Speed
			continue
		}

		st.LastFailure = now
		st.Status = StatusDegraded
		st.Interval = wdCfg.FailureInterval
		st.LastError = result.Error

		if result.Verdict == netprobe.DomainMTLS {
			st.CooldownUntil = now.Add(time.Duration(wdCfg.Cooldown) * time.Second)
			log.Warnf("[WATCHDOG] %s: server requires client certificate (mTLS), no DPI bypass applies — skipping heal, cooldown %ds", domain, wdCfg.Cooldown)
			continue
		}

		st.ConsecutiveFailures++
		log.Warnf("[WATCHDOG] %s: check FAILED [%s] (%s) [%d/%d]", domain, result.Verdict, result.Error, st.ConsecutiveFailures, wdCfg.MaxRetries)

		if st.ConsecutiveFailures >= wdCfg.MaxRetries {
			needsHealing = append(needsHealing, domain)
		}
	}
	w.mu.Unlock()

	if len(needsHealing) > 0 && w.healing.CompareAndSwap(false, true) {
		w.healWG.Add(1)
		go func(domains []string) {
			defer w.healWG.Done()
			defer w.healing.Store(false)
			log.Infof("[WATCHDOG] starting heal for %d domain(s): %v", len(domains), domains)
			w.healBatch(domains)
		}(needsHealing)
	}
}
