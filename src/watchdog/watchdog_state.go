package watchdog

import "github.com/daniellavrushin/b4/config"

func (w *Watchdog) syncDomainStates(wdCfg config.WatchdogConfig) {
	active := make(map[string]bool, len(wdCfg.Domains))
	for _, d := range wdCfg.Domains {
		active[d] = true
		if _, ok := w.domainStates[d]; !ok {
			w.domainStates[d] = &DomainStatus{
				Domain:   d,
				Status:   StatusHealthy,
				Interval: wdCfg.IntervalSec,
			}
		}
	}
	for d := range w.domainStates {
		if !active[d] {
			delete(w.domainStates, d)
		}
	}
}
