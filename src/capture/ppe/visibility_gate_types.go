package ppe

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type CaptureVisibilityMode string

const (
	VisibilityComplete     CaptureVisibilityMode = "complete"
	VisibilityOutgoingOnly CaptureVisibilityMode = "outgoing-only"
	VisibilityUnknown      CaptureVisibilityMode = "unknown"
	VisibilityIncomplete   CaptureVisibilityMode = "incomplete"
)

type VisibilityFeature string

const (
	VisibilityFeatureObserve            VisibilityFeature = "observe"
	VisibilityFeatureStatelessMutation  VisibilityFeature = "stateless-mutation"
	VisibilityFeatureReassembly         VisibilityFeature = "reassembly"
	VisibilityFeatureHoldReplay         VisibilityFeature = "hold-replay"
	VisibilityFeatureACKReplay          VisibilityFeature = "ack-dependent-replay"
	VisibilityFeatureAutomaticDiscovery VisibilityFeature = "automatic-discovery"
	VisibilityFeatureCanary             VisibilityFeature = "canary"
	VisibilityFeaturePromotion          VisibilityFeature = "promotion"
)

type CaptureVisibilitySnapshot struct {
	Mode        CaptureVisibilityMode `json:"mode"`
	Enforced    bool                  `json:"enforced"`
	Generation  string                `json:"generation,omitempty"`
	LastVerdict SelfTestVerdict       `json:"last_verdict,omitempty"`
	Reason      string                `json:"reason,omitempty"`
	UpdatedAt   time.Time             `json:"updated_at"`
	Epoch       uint64                `json:"epoch"`
}

type VisibilityDecision struct {
	Allowed bool                      `json:"allowed"`
	Feature VisibilityFeature         `json:"feature"`
	State   CaptureVisibilitySnapshot `json:"state"`
	Reason  string                    `json:"reason,omitempty"`
}

type VisibilityGate struct {
	state atomic.Pointer[CaptureVisibilitySnapshot]

	mu        sync.Mutex
	nextID    uint64
	listeners map[uint64]func(CaptureVisibilitySnapshot)
}

var defaultVisibilityGate = NewVisibilityGate()

func NewVisibilityGate() *VisibilityGate {
	gate := &VisibilityGate{listeners: make(map[uint64]func(CaptureVisibilitySnapshot))}
	initial := CaptureVisibilitySnapshot{
		Mode:      VisibilityComplete,
		Enforced:  false,
		Reason:    "PPE visibility proof is not required",
		UpdatedAt: time.Now().UTC(),
		Epoch:     1,
	}
	gate.state.Store(&initial)
	return gate
}

func DefaultVisibilityGate() *VisibilityGate { return defaultVisibilityGate }

func (g *VisibilityGate) Snapshot() CaptureVisibilitySnapshot {
	if g == nil {
		return CaptureVisibilitySnapshot{Mode: VisibilityUnknown, Enforced: true, Reason: "visibility gate is unavailable"}
	}
	current := g.state.Load()
	if current == nil {
		return CaptureVisibilitySnapshot{Mode: VisibilityUnknown, Enforced: true, Reason: "visibility state is unavailable"}
	}
	return *current
}

func (g *VisibilityGate) Decision(feature VisibilityFeature) VisibilityDecision {
	state := g.Snapshot()
	allowed := !state.Enforced || state.Mode == VisibilityComplete || feature == VisibilityFeatureObserve || feature == VisibilityFeatureStatelessMutation
	reason := ""
	if !allowed {
		reason = state.Reason
		if strings.TrimSpace(reason) == "" {
			reason = "capture visibility is not complete"
		}
	}
	return VisibilityDecision{Allowed: allowed, Feature: feature, State: state, Reason: reason}
}
