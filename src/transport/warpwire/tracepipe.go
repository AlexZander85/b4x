// Package warpwire is the E7 integration layer between the dependency-free
// engine (src/transport/warp) and the contract/observability packages
// (src/warp): trace-pipeline adaptation of engine events and the §73
// hard-gate feed that keeps the contract producers live off runtime truth.
//
// Direction of imports: warpwire → {warp, transportwarp}. The engine never
// imports the contracts (design §13), so this package is the ONLY place
// allowed to know both sides.
package warpwire

import (
	"strconv"
	"sync/atomic"
	"time"

	engine "github.com/daniellavrushin/b4/transport/warp"
	warp "github.com/daniellavrushin/b4/warp"
)

// EventAdapter converts engine lifecycle events into sealed v2 envelopes.
// Sequence numbers are strictly monotonic across ALL events of one adapter
// (per-session monotonicity, §61.1). Payload keys are redacted-safe only:
// colo codes, structural classes/statuses/reasons, durations — never tokens
// or key material (§61.3; Runtime.PublishTrace enforces independently).
type EventAdapter struct {
	BootID    string
	ProcessID string
	SessionID string

	seq atomic.Uint64
}

func NewEventAdapter(bootID, processID, sessionID string) *EventAdapter {
	return &EventAdapter{BootID: bootID, ProcessID: processID, SessionID: sessionID}
}

// Contract event names referenced by the priority/state mapping (values are
// the §62 strings both sides already share).
const (
	evSessionGenerationStarted = "warp_session_generation_started"
	evMasqueConnected          = "warp_masque_connected"
	evMasqueRejected           = "warp_masque_rejected"
	evMasqueDisconnected       = "warp_masque_disconnected"
	evReconnectScheduled       = "warp_reconnect_scheduled"
	evKeepaliveFailed          = "warp_keepalive_failed"
	evIdentityBlocked          = "warp_identity_blocked"
	evRouteReleasedFailOpen    = "warp_route_released_failopen"

	evGeoPublicIPChanged = "warp_geo_public_ip_changed"
	evNonRUGateClosed    = "warp_nonru_gate_closed"
	evNonRURevoked       = "warp_nonru_route_revoked"
	evNonRUFailClosed    = "warp_nonru_fail_closed_activated"
	evCamouflageCutoff   = "warp_camouflage_cutoff"

	evDNSPathProven = "warp_dns_path_proven"
)

// priorityFor maps engine event names onto §61.2 priorities: P0 for
// state-critical transitions (never evicted from the retention ring), P1
// for required lifecycle evidence (the §62.5 promotion-completeness set).
// Engine sources carry no P2 samples.
func priorityFor(name string) warp.TracePriority {
	switch name {
	case evMasqueConnected,
		evMasqueRejected,
		evMasqueDisconnected,
		evRouteReleasedFailOpen,
		evNonRUGateClosed,
		evNonRURevoked,
		evNonRUFailClosed,
		evGeoPublicIPChanged:
		return warp.P0
	default:
		return warp.P1
	}
}

// stateFor is DELIBERATELY inert for now: asserting StateAfter engages the
// §63.2 runtime-vs-trace cross-check inside Runtime.PublishTrace, whose
// applied-route flag is owned by the FIELD layer's ApplyRoute lifecycle
// (not yet wired into composition). Populating states here before that
// lifecycle exists would manufacture TRACE_STATE_MISMATCH violations out of
// correct engine behavior. Revisit together with ApplyRoute wiring (E8/field).
func stateFor(string) string { return "" }

func (a *EventAdapter) envelope(event string, prio warp.TracePriority, at time.Time, payload map[string]string) warp.TransportTraceEnvelope {
	if payload == nil {
		payload = map[string]string{}
	}
	e := warp.TransportTraceEnvelope{
		SchemaVersion: 2,
		BootID:        a.BootID,
		ProcessID:     a.ProcessID,
		SessionID:     a.SessionID,
		Sequence:      a.seq.Add(1),
		Priority:      prio,
		Event:         event,
		StateAfter:    stateFor(event),
		Payload:       payload,
		ObservedAt:    at,
	}
	if e.ObservedAt.IsZero() {
		e.ObservedAt = time.Now()
	}
	return e.Seal()
}

// FromSupervisor converts one supervisor lifecycle event.
func (a *EventAdapter) FromSupervisor(ev engine.SupervisorEvent) warp.TransportTraceEnvelope {
	payload := map[string]string{}
	if ev.FailureClass != "" {
		payload["failure_class"] = ev.FailureClass
	}
	if ev.Colo != "" {
		payload["colo"] = ev.Colo
	}
	if ev.Status != 0 {
		payload["status"] = strconv.Itoa(ev.Status)
	}
	if ev.Attempt != 0 {
		payload["attempt"] = strconv.FormatUint(uint64(ev.Attempt), 10)
	}
	if ev.BackoffMS != 0 {
		payload["backoff_ms"] = strconv.FormatUint(ev.BackoffMS, 10)
	}
	if ev.DurationMS != 0 {
		payload["duration_ms"] = strconv.FormatUint(ev.DurationMS, 10)
	}
	if ev.Detail != "" {
		payload["detail"] = truncateDetail(ev.Detail)
	}
	return a.envelope(ev.Name, priorityFor(ev.Name), ev.ObservedAt, payload)
}

// FromGuard converts one control-flow-guard wiring event.
func (a *EventAdapter) FromGuard(ev engine.GuardEvent) warp.TransportTraceEnvelope {
	payload := map[string]string{}
	if ev.EndpointHash != "" {
		payload["endpoint_hash"] = ev.EndpointHash
	}
	if ev.Detail != "" {
		payload["detail"] = truncateDetail(ev.Detail)
	}
	return a.envelope(ev.Name, priorityFor(ev.Name), ev.ObservedAt, payload)
}

// FromNonRU converts one non-RU gate event.
func (a *EventAdapter) FromNonRU(ev engine.NonRUEvent) warp.TransportTraceEnvelope {
	payload := map[string]string{}
	for k, v := range map[string]string{
		"provider": ev.Provider,
		"reason":   ev.Reason,
		"verdict":  ev.Verdict,
		"detail":   truncateDetail(ev.Detail),
	} {
		if v != "" {
			payload[k] = v
		}
	}
	if ev.Gen != 0 {
		payload["session_gen"] = strconv.FormatUint(ev.Gen, 10)
	}
	if ev.DurationMS != 0 {
		payload["duration_ms"] = strconv.FormatUint(ev.DurationMS, 10)
	}
	return a.envelope(ev.Name, priorityFor(ev.Name), ev.ObservedAt, payload)
}

func truncateDetail(s string) string {
	if len(s) <= 120 {
		return s
	}
	return s[:120]
}

// SupervisorSink adapts to the supervisor Sink signature with publish-drop
// accounting (§63 warp_trace_dropped_required_event_total is counted inside
// PublishTrace; onDrop receives the same signal for local diagnostics).
func (a *EventAdapter) SupervisorSink(rt *warp.Runtime, onDrop func()) func(engine.SupervisorEvent) {
	return func(ev engine.SupervisorEvent) {
		if !rt.PublishTrace(a.SessionID, a.FromSupervisor(ev)) && onDrop != nil {
			onDrop()
		}
	}
}

// GuardSink is the GuardEvent counterpart.
func (a *EventAdapter) GuardSink(rt *warp.Runtime, onDrop func()) func(engine.GuardEvent) {
	return func(ev engine.GuardEvent) {
		if !rt.PublishTrace(a.SessionID, a.FromGuard(ev)) && onDrop != nil {
			onDrop()
		}
	}
}

// NonRUSink is the NonRUEvent counterpart.
func (a *EventAdapter) NonRUSink(rt *warp.Runtime, onDrop func()) func(engine.NonRUEvent) {
	return func(ev engine.NonRUEvent) {
		if !rt.PublishTrace(a.SessionID, a.FromNonRU(ev)) && onDrop != nil {
			onDrop()
		}
	}
}

// RequiredPromotionEvents lists the §62.5 names that MUST be present in the
// pipeline before a non-RU route may be promoted (§69-30: required-event
// loss blocks promotion). Verify with Runtime.VerifyTraceCompleteness.
var RequiredPromotionEvents = []string{
	evSessionGenerationStarted,
	evMasqueConnected,
	evDNSPathProven,
	"warp_geo_probe_started",
	"warp_geo_provider_result",
	"warp_geo_quorum_evaluated",
	"warp_geo_attestation_issued",
	"warp_nonru_gate_opened",
	"warp_nonru_route_promoted",
}
