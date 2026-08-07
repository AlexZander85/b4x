package nfq

import (
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/routing"
)

// fallbackRouteConfig converts the persisted FallbackRuntimeConfig control
// plane into the routing package's immutable RouteConfig snapshot. The
// conversion lives in nfq (not routing): routing stays a pure library and the
// production wiring owns the mapping (FB-23 Stage 33).
func fallbackRouteConfig(fb config.FallbackRuntimeConfig, queueMark uint) routing.RouteConfig {
	return routing.RouteConfig{
		Enabled:           fb.Enabled,
		Policy:            fallbackPolicy(fb.Policy),
		NativeConfidence:  fb.NativeConfidence,
		ProcessedMark:     capture.ProcessedMarkFor(queueMark),
		ProcessedMarkMask: capture.ProcessedMarkMask,
		BypassMark:        fb.BypassMark,
		GenericMark:       fb.GenericMark,
		RuleTable:         fb.RuleTable,
		ProxyRouteID:      fb.ProxyRouteID,
		Cooldown:          time.Duration(fb.CooldownSeconds) * time.Second,
		LastGoodTTL:       time.Duration(fb.LastGoodTTLSeconds) * time.Second,
		HealthTTL:         time.Duration(fb.HealthTTLSeconds) * time.Second,
		MaxScopes:         fb.MaxScopes,
		MaxIdlePerScope:   fb.MaxIdlePerScope,
		MaxUDPSessions:    fb.MaxUDPSessions,
		UDPIdleTimeout:    time.Duration(fb.UDPIdleTimeoutSec) * time.Second,
		Capabilities:      fallbackCapabilities(fb.Capabilities),
		Clock:             clock.RealClock{},
	}
}

func fallbackPolicy(p string) routing.UnknownFlowPolicy {
	switch p {
	case config.FallbackGeneric:
		return routing.UnknownUseGeneric
	case config.FallbackProxy:
		return routing.UnknownRouteProxy
	default:
		return routing.UnknownAcceptDirect
	}
}

func fallbackCapabilities(c config.FallbackCapabilityConfig) routing.CapabilityMatrix {
	return routing.CapabilityMatrix{
		NativeTCP:  c.NativeTCP,
		NativeUDP:  c.NativeUDP,
		DirectTCP:  c.DirectTCP,
		DirectUDP:  c.DirectUDP,
		GenericTCP: c.GenericTCP,
		GenericUDP: c.GenericUDP,
		ProxyTCP:   c.ProxyTCP,
		ProxyUDP:   c.ProxyUDP,
		IPv4:       c.IPv4,
		IPv6:       c.IPv6,
	}
}

// newFallbackManager builds the routing fallback manager from the persisted
// classifier runtime configuration. It fails closed: an invalid fallback
// configuration (e.g. proxy policy without a proxy route id) returns an error
// and no manager, so the production packet path never runs a half-configured
// escape path. A disabled fallback returns (nil, nil).
func newFallbackManager(cfg *config.Config) (*routing.FallbackManager, error) {
	if cfg == nil {
		return nil, nil
	}
	fb := cfg.System.Classifier.Runtime.Fallback
	if !fb.Enabled {
		return nil, nil
	}
	m, err := routing.NewFallbackManager(fallbackRouteConfig(fb, cfg.Queue.Mark))
	if err != nil {
		return nil, err
	}
	return m, nil
}
