package tproxy

import (
	"context"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/reserve"
	"github.com/daniellavrushin/b4/socks5"
)

type Manager struct {
	mu            sync.Mutex
	listeners     map[string]*Listener
	resolver      DomainResolver
	mtprotoBridge MTProtoBridge
	ctx           context.Context
	cancel        context.CancelFunc
}

func (m *Manager) SetMTProtoBridge(b MTProtoBridge) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mtprotoBridge = b
	for _, l := range m.listeners {
		l.Bridge = b
	}
}

func NewManager(resolver DomainResolver) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		listeners: make(map[string]*Listener),
		resolver:  resolver,
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (m *Manager) SetResolver(r DomainResolver) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resolver = r
	for _, l := range m.listeners {
		l.Resolver = r
	}
}

func (m *Manager) SyncConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	bypassMark := proxyBypassMark(cfg)

	desired := make(map[string]*config.SetConfig, len(cfg.Sets))
	for _, set := range cfg.Sets {
		if set == nil || !set.Enabled || !set.Routing.Enabled {
			continue
		}
		if !config.RoutingUsesTProxy(set.Routing.Mode) {
			continue
		}
		desired[set.Id] = set
	}

	for id, l := range m.listeners {
		set, keep := desired[id]
		if !keep {
			log.Infof("tproxy: stopping listener for removed set %q", l.SetName)
			_ = l.Stop()
			delete(m.listeners, id)
			continue
		}
		mark := effectiveMark(set)
		port := PortFor(mark)
		desiredHost := set.Routing.Upstream.Host
		if desiredHost == "" {
			desiredHost = "127.0.0.1"
		}
		isMTWS := set.Routing.Mode == config.RoutingModeMTProtoWS
		_, tunnelKindKey, tunnelUDP, _, _ := tunnelPlan(set)
		if l.Port != port ||
			l.MTProtoWS != isMTWS ||
			l.TunnelKind != tunnelKindKey ||
			l.UDP != tunnelUDP ||
			l.Upstream.Host != desiredHost ||
			l.Upstream.Port != set.Routing.Upstream.Port ||
			l.Upstream.Username != set.Routing.Upstream.Username ||
			l.Upstream.Password != set.Routing.Upstream.Password ||
			l.Upstream.BypassMark != bypassMark ||
			l.UseDomain != set.Routing.Upstream.UseDomain ||
			l.FailOpen != set.Routing.Upstream.FailOpen {
			log.Infof("tproxy: restarting listener for set %q (config changed)", set.Name)
			_ = l.Stop()
			delete(m.listeners, id)
		}
	}

	for id, set := range desired {
		if _, ok := m.listeners[id]; ok {
			continue
		}
		mark := effectiveMark(set)
		port := PortFor(mark)
		host := set.Routing.Upstream.Host
		if host == "" {
			host = "127.0.0.1"
		}

		// routing.mode=tunnel: resolve the reserve carrier by kind. An
		// unregistered kind (engine disabled / failed start / not wired
		// yet) gets NO listener — the tproxy port stays closed, the marked
		// traffic is refused. Fail-closed, never leaked around the tunnel.
		var tunnelCarrier reserve.Carrier
		_, tunnelKindKey, tunnelUDP, tunnelOK, entry := tunnelPlan(set)
		if set.Routing.Mode == config.RoutingModeTunnel {
			if !tunnelOK {
				log.Errorf("tproxy: tunnel carrier %q is not registered for set %q (engine disabled, failed to start, or not wired); the set stays fail-closed until it registers", set.Routing.Tunnel, set.Name)
				continue
			}
			tunnelCarrier = entry.Carrier
		}

		l := &Listener{
			SetID:   set.Id,
			SetName: set.Name,
			Port:    port,
			Upstream: socks5.ClientConfig{
				Host:       host,
				Port:       set.Routing.Upstream.Port,
				Username:   set.Routing.Upstream.Username,
				Password:   set.Routing.Upstream.Password,
				Timeout:    10 * time.Second,
				BypassMark: bypassMark,
			},
			UseDomain:  set.Routing.Upstream.UseDomain,
			UDP:        tunnelUDP,
			FailOpen:   set.Routing.Upstream.FailOpen,
			Resolver:   m.resolver,
			MTProtoWS:  set.Routing.Mode == config.RoutingModeMTProtoWS,
			Bridge:     m.mtprotoBridge,
			Tunnel:     tunnelCarrier,
			TunnelKind: tunnelKindKey,
		}
		if err := l.Start(m.ctx); err != nil {
			log.Errorf("tproxy: failed to start listener for set %q: %v", set.Name, err)
			continue
		}
		m.listeners[id] = l
	}
}

// tunnelPlan resolves the routing.mode=tunnel carrier parameters for one
// set: the configured kind, the registry kind key ("" when unregistered),
// the effective UDP flag (upstream.udp AND carrier support; plain
// upstream.udp for the non-tunnel modes), the registration verdict, and the
// registry entry (zero value when unregistered).
func tunnelPlan(set *config.SetConfig) (kind, kindKey string, udp, registered bool, entry reserve.Entry) {
	if set == nil {
		return "", "", false, false, reserve.Entry{}
	}
	if set.Routing.Mode != config.RoutingModeTunnel {
		return "", "", set.Routing.Upstream.UDP, true, reserve.Entry{}
	}
	e, ok := reserve.Lookup(reserve.Kind(set.Routing.Tunnel))
	if !ok {
		return set.Routing.Tunnel, "", false, false, reserve.Entry{}
	}
	return set.Routing.Tunnel, string(e.Kind), set.Routing.Upstream.UDP && e.Carrier.SupportsUDP(), true, e
}

func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, l := range m.listeners {
		_ = l.Stop()
		delete(m.listeners, id)
	}
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *Manager) PortForSet(set *config.SetConfig) int {
	if set == nil {
		return 0
	}
	return PortFor(effectiveMark(set))
}

func effectiveMark(set *config.SetConfig) uint32 {
	if set == nil {
		return 0
	}
	return MarkForSet(set.Id, set.Routing.FWMark)
}

// proxyBypassMark returns the SO_MARK value the listener uses on its outbound
// SOCKS5 dial so that those packets bypass b4's proxy-mode OUTPUT mark rule and
// don't loop back into TPROXY. It mirrors routeQueueBypassMark in the tables
// package, kept in sync via the cfg.Queue.Mark setting.
func proxyBypassMark(cfg *config.Config) uint32 {
	if cfg == nil || cfg.Queue.Mark == 0 {
		return 0x8000
	}
	return uint32(cfg.Queue.Mark)
}
