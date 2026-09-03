package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const CurrentVersion uint16 = 1

type DeliveryMode string

const (
	DirectStrategy   DeliveryMode = "direct-strategy"
	ExternalProxy    DeliveryMode = "external-proxy"
	RouterTunnel     DeliveryMode = "router-tunnel"
	ClientConfigured DeliveryMode = "client-configured"
	Hybrid           DeliveryMode = "hybrid"
)

type ExecutionPolicy string

const (
	ExecutionOff        ExecutionPolicy = "off"
	ExecutionObserve    ExecutionPolicy = "observe"
	ExecutionRecommend  ExecutionPolicy = "recommend"
	ExecutionAutoCanary ExecutionPolicy = "auto-canary"
)

type Provenance struct {
	Source, Signer, Version string
	Official                bool
}
type Target struct {
	Name, Role string
	Domains    []string
	Protocols  []string
}
type Component struct {
	ID         string          `json:"id"`
	Delivery   DeliveryMode    `json:"delivery"`
	Targets    []Target        `json:"targets,omitempty"`
	Execution  ExecutionPolicy `json:"execution"`
	GSO        string          `json:"gso,omitempty"`
	PassiveRST string          `json:"passive_rst,omitempty"`
}
type Manifest struct {
	SchemaVersion  uint16         `json:"schema_version"`
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Classification string         `json:"classification"`
	Provenance     Provenance     `json:"provenance"`
	Components     []Component    `json:"components"`
	Compatibility  []string       `json:"compatibility,omitempty"`
	Limits         map[string]int `json:"limits,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

func (m Manifest) CanonicalBytes() ([]byte, error) {
	// Sorting copies gives stable hashes without mutating caller-owned manifests.
	c := m
	c.Components = append([]Component(nil), m.Components...)
	for i := range c.Components {
		c.Components[i].Targets = append([]Target(nil), c.Components[i].Targets...)
		sort.Slice(c.Components[i].Targets, func(a, b int) bool { return c.Components[i].Targets[a].Name < c.Components[i].Targets[b].Name })
		for j := range c.Components[i].Targets {
			c.Components[i].Targets[j].Domains = append([]string(nil), c.Components[i].Targets[j].Domains...)
			sort.Strings(c.Components[i].Targets[j].Domains)
			c.Components[i].Targets[j].Protocols = append([]string(nil), c.Components[i].Targets[j].Protocols...)
			sort.Strings(c.Components[i].Targets[j].Protocols)
		}
	}
	sort.Slice(c.Components, func(a, b int) bool { return c.Components[a].ID < c.Components[b].ID })
	return json.Marshal(c)
}
func (m Manifest) SafetyHash() string {
	b, _ := m.CanonicalBytes()
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func normalizeDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
