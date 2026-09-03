package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type ContextValidity string

const (
	ContextExact      ContextValidity = "exact"
	ContextCompatible ContextValidity = "compatible"
	ContextMismatch   ContextValidity = "mismatch"
	ContextExpired    ContextValidity = "expired"
)

type NetworkContext struct {
	ID               string
	WANFingerprint   string
	Interface        string
	IPFamily         string
	ConfigGeneration uint64
	ObservedAt       time.Time
	ExpiresAt        time.Time
}

func NewNetworkContext(wan, iface, family string, generation uint64, now time.Time) NetworkContext {
	h := sha256.Sum256([]byte(wan + "|" + iface + "|" + family))
	return NetworkContext{ID: "net-" + hex.EncodeToString(h[:8]), WANFingerprint: wan, Interface: iface, IPFamily: family, ConfigGeneration: generation, ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
}
func CompareContext(p NetworkDiagnosticProfile, c NetworkContext, now time.Time) ContextValidity {
	if p.ExpiresAt.Before(now) {
		return ContextExpired
	}
	if p.Scope.ConfigGeneration != c.ConfigGeneration || p.Scope.NetworkContextID != c.ID {
		return ContextMismatch
	}
	if !now.Before(c.ExpiresAt) {
		return ContextExpired
	}
	if p.Scope.IPFamily != "" && p.Scope.IPFamily != c.IPFamily {
		return ContextCompatible
	}
	return ContextExact
}

type ContextCollector interface{ Current() NetworkContext }
type StaticContextCollector struct{ Context NetworkContext }

func (c StaticContextCollector) Current() NetworkContext { return c.Context }
func InvalidateOnContextChange(p NetworkDiagnosticProfile, previous, current NetworkContext) bool {
	return previous.ID != current.ID || previous.ConfigGeneration != current.ConfigGeneration || p.Scope.NetworkContextID != current.ID
}
func ContextScope(c NetworkContext, client monitor.ClientScopeKey) monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{ClientScope: client, TargetRole: "target", NetworkContextID: c.ID, ConfigGeneration: c.ConfigGeneration, IPFamily: c.IPFamily}
}
