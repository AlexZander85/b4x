package watchdog

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/discovery"
	"github.com/daniellavrushin/b4/log"
)

// Watchdog passively observes domain health via discovery and updates
// in-memory status projection. After the FB-28 cutover it no longer mutates
// configuration: passive observation never persists config changes
// (authority separation, IV-18-MON-08). The operator-facing HTTP API is the
// only config mutation path (it uses its own saveAndPushConfig).
type Watchdog struct {
	cfgPtr       *atomic.Pointer[config.Config]
	discoveryRT  *discovery.Runtime
	mu           sync.Mutex
	domainStates map[string]*DomainStatus
	stop         chan struct{}
	stopped      chan struct{}
	healing      atomic.Bool
	healWG       sync.WaitGroup
}

func New(cfgPtr *atomic.Pointer[config.Config], discoveryRT *discovery.Runtime) *Watchdog {
	return &Watchdog{
		cfgPtr:       cfgPtr,
		discoveryRT:  discoveryRT,
		domainStates: make(map[string]*DomainStatus),
	}
}

func (w *Watchdog) Start() {
	w.stop = make(chan struct{})
	w.stopped = make(chan struct{})
	log.Infof("[WATCHDOG] starting watchdog service")
	go w.run()
}

func (w *Watchdog) Stop() {
	close(w.stop)
	<-w.stopped
	w.healWG.Wait()
	log.Infof("[WATCHDOG] watchdog service stopped")
}

func (w *Watchdog) GetState() WatchdogState {
	cfg := w.cfgPtr.Load()
	w.mu.Lock()
	defer w.mu.Unlock()

	domains := make([]*DomainStatus, 0)
	for _, d := range cfg.System.Checker.Watchdog.Domains {
		var copy DomainStatus
		if existing, ok := w.domainStates[d]; ok {
			copy = *existing
		} else {
			copy = DomainStatus{
				Domain:   d,
				Status:   StatusHealthy,
				Interval: cfg.System.Checker.Watchdog.IntervalSec,
			}
		}
		domain := ExtractDomain(d)
		copy.DisplayDomain = domain
		for _, set := range cfg.Sets {
			if !set.Enabled {
				continue
			}
			if setContainsAnyDomain(set, []string{domain}) {
				copy.MatchedSet = set.Name
				copy.MatchedSetId = set.Id
				break
			}
		}
		domains = append(domains, &copy)
	}
	return WatchdogState{
		Enabled: cfg.System.Checker.Watchdog.Enabled,
		Domains: domains,
	}
}

func (w *Watchdog) ForceCheck(domain string) {
	w.mu.Lock()
	st, ok := w.domainStates[domain]
	if !ok {
		st = &DomainStatus{
			Domain: domain,
			Status: StatusHealthy,
		}
		w.domainStates[domain] = st
	}
	st.LastCheck = time.Time{}
	st.CooldownUntil = time.Time{}
	w.mu.Unlock()
}
