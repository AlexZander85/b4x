package warp

// Hard-gate producer fixtures for the WARP base-transport runtime (FB-02
// section 3). Each test drives the real production function in
// src/warp/runtime.go that emits a registered hard-gate metric and asserts
// the counter moved. All ten gates are zero-tolerance violation counters
// (WARP addendum v1.2 §72), so every fixture is a negative fixture: it
// exercises the violation branch and asserts the counter incremented.
//
// These tests are referenced from specs/registries/hard_gates.yaml
// (test_producer / mutation_test / evidence_artifact) and from
// artifacts/remediation/FB02_WARP_BASE_TRANSPORT_PRODUCERS.json.

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

func warpHardGateCounterValue(t *testing.T, name string) uint64 {
	t.Helper()
	snap := observability.Default().Metrics.Snapshot(time.Now())
	var total uint64
	for _, counter := range snap.Counters {
		if counter.Name == name {
			total += counter.Value
		}
	}
	return total
}

// newProducerRuntime builds a runtime whose violation branches are exercised
// by the fixtures below.
func newProducerRuntime() *Runtime {
	return NewRuntime(DefaultConfig())
}

// TestHardGateProducer_WARPSecretLeak is the negative fixture for
// warp_secret_leak_total: a trace event whose payload carries a raw session
// secret must be rejected and counted.
func TestHardGateProducer_WARPSecretLeak(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := rt.PutSecret("sess-a", "tls-key", []byte("raw-secret-value")); err != nil {
		t.Fatal(err)
	}
	rt.ObserveHealth("sess-a", true, true)
	policy := DialPolicy{Mark: 0x5001, BindDevice: "wg0", EndpointPin: "pin", DirectControl: true, ProxyEnvDisabled: true, Generation: 1}
	lease := TunLease{SessionID: "sess-a", Interface: "b4tun0", Address: "10.0.0.2", MTU: 1500, State: TunOwned}
	auth := &TransportAuthorization{FlowID: "flow-1", ServiceProfile: "default", ClientKey: "ck", DestinationHash: "hash-1", RouteGeneration: 1, ConfigGeneration: 1, AllowForwarded: true}
	if err := rt.ApplyRoute("sess-a", policy, lease, []string{"1.1.1.1"}, auth); err != nil {
		t.Fatal(err)
	}

	event := TransportTraceEnvelope{SchemaVersion: 2, BootID: "b", ProcessID: "p", SessionID: "sess-a", Sequence: 1, Priority: P0, Event: "dial", ObservedAt: time.Now()}.Seal()
	event.Payload = map[string]string{"tls_key": "raw-secret-value"}
	if rt.PublishTrace("sess-a", event) {
		t.Fatal("trace with raw secret was accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpSecretLeak); got == 0 {
		t.Fatal("warp_secret_leak_total not incremented for raw-secret trace (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPForeignInterfaceModified is the negative fixture
// for warp_foreign_interface_modified_total: claiming a TUN interface owned
// by a different session must be counted.
func TestHardGateProducer_WARPForeignInterfaceModified(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Register("sess-b", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	rt.ObserveHealth("sess-a", true, true)
	rt.ObserveHealth("sess-b", true, true)
	policy := DialPolicy{Mark: 0x5002, BindDevice: "wg0", EndpointPin: "pin", DirectControl: true, ProxyEnvDisabled: true, Generation: 1}
	lease := TunLease{SessionID: "sess-a", Interface: "b4tun0", Address: "10.0.0.2", MTU: 1500, State: TunOwned}
	auth := &TransportAuthorization{FlowID: "flow-1", ServiceProfile: "default", ClientKey: "ck", DestinationHash: "hash-1", RouteGeneration: 1, ConfigGeneration: 1, AllowForwarded: true}
	if err := rt.ApplyRoute("sess-a", policy, lease, []string{"1.1.1.1"}, auth); err != nil {
		t.Fatal(err)
	}

	// sess-b tries to claim the same interface: foreign-interface modification.
	foreign := TunLease{SessionID: "sess-b", Interface: "b4tun0", Address: "10.0.0.9", MTU: 1500, State: TunOwned}
	if err := rt.ApplyRoute("sess-b", policy, foreign, []string{"2.2.2.2"}, auth); err == nil {
		t.Fatal("foreign interface claim accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpForeignInterfaceModified); got == 0 {
		t.Fatal("warp_foreign_interface_modified_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPRecursiveControlRoute is the negative fixture for
// warp_recursive_control_route_total: a control route targeting its own mark.
func TestHardGateProducer_WARPRecursiveControlRoute(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	rt.ObserveHealth("sess-a", true, true)
	// routeMark == policy.Mark => recursion.
	policy := DialPolicy{Mark: 0x6001, BindDevice: "wg0", EndpointPin: "pin", DirectControl: true, ProxyEnvDisabled: true, Generation: 1}
	lease := TunLease{SessionID: "sess-a", Interface: "b4tun0", Address: "10.0.0.2", MTU: 1500, State: TunOwned}
	auth := &TransportAuthorization{FlowID: "flow-1", ServiceProfile: "default", ClientKey: "ck", DestinationHash: "hash-1", RouteGeneration: 1, ConfigGeneration: 1, AllowForwarded: true}
	if err := rt.ApplyRoute("sess-a", policy, lease, []string{"1.1.1.1"}, auth); err == nil {
		t.Fatal("recursive control route accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpRecursiveControlRoute); got == 0 {
		t.Fatal("warp_recursive_control_route_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPMarkCollision is the negative fixture for
// warp_mark_collision_total: a policy-pinned mark already owned by another
// session.
func TestHardGateProducer_WARPMarkCollision(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Register("sess-b", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	rt.ObserveHealth("sess-a", true, true)
	rt.ObserveHealth("sess-b", true, true)
	policy := DialPolicy{Mark: 0x7001, BindDevice: "wg0", EndpointPin: "pin", DirectControl: true, ProxyEnvDisabled: true, Generation: 1}
	lease := TunLease{SessionID: "sess-a", Interface: "b4tun0", Address: "10.0.0.2", MTU: 1500, State: TunOwned}
	leaseB := TunLease{SessionID: "sess-b", Interface: "b4tun1", Address: "10.0.0.9", MTU: 1500, State: TunOwned}
	auth := &TransportAuthorization{FlowID: "flow-1", ServiceProfile: "default", ClientKey: "ck", DestinationHash: "hash-1", RouteGeneration: 1, ConfigGeneration: 1, AllowForwarded: true}
	if err := rt.ApplyRoute("sess-a", policy, lease, []string{"1.1.1.1"}, auth); err != nil {
		t.Fatal(err)
	}
	// sess-b pins the mark already owned by sess-a.
	if err := rt.ApplyRoute("sess-b", policy, leaseB, []string{"2.2.2.2"}, auth); err == nil {
		t.Fatal("mark collision accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpMarkCollision); got == 0 {
		t.Fatal("warp_mark_collision_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPRouteWithoutLiveness is the negative fixture for
// warp_route_without_liveness_total: route activation without any liveness
// proof.
func TestHardGateProducer_WARPRouteWithoutLiveness(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	policy := DialPolicy{Mark: 0x8001, BindDevice: "wg0", EndpointPin: "pin", DirectControl: true, ProxyEnvDisabled: true, Generation: 1}
	lease := TunLease{SessionID: "sess-a", Interface: "b4tun0", Address: "10.0.0.2", MTU: 1500, State: TunOwned}
	auth := &TransportAuthorization{FlowID: "flow-1", ServiceProfile: "default", ClientKey: "ck", DestinationHash: "hash-1", RouteGeneration: 1, ConfigGeneration: 1, AllowForwarded: true}
	// No ObserveHealth call: liveness is not proven.
	if err := rt.ApplyRoute("sess-a", policy, lease, []string{"1.1.1.1"}, auth); err == nil {
		t.Fatal("route activated without liveness proof")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpRouteWithoutLiveness); got == 0 {
		t.Fatal("warp_route_without_liveness_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPDestinationSetPartialApply is the negative fixture
// for warp_destination_set_partial_apply_total: the destination set applied
// partially (empty destination entries).
func TestHardGateProducer_WARPDestinationSetPartialApply(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	rt.ObserveHealth("sess-a", true, true)
	policy := DialPolicy{Mark: 0x9001, BindDevice: "wg0", EndpointPin: "pin", DirectControl: true, ProxyEnvDisabled: true, Generation: 1}
	lease := TunLease{SessionID: "sess-a", Interface: "b4tun0", Address: "10.0.0.2", MTU: 1500, State: TunOwned}
	auth := &TransportAuthorization{FlowID: "flow-1", ServiceProfile: "default", ClientKey: "ck", DestinationHash: "hash-1", RouteGeneration: 1, ConfigGeneration: 1, AllowForwarded: true}
	// One destination cannot be applied.
	partial := []string{"1.1.1.1", ""}
	if err := rt.ApplyRoute("sess-a", policy, lease, partial, auth); err == nil {
		t.Fatal("partial destination set accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpDestinationSetPartialApply); got == 0 {
		t.Fatal("warp_destination_set_partial_apply_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPUnboundedRestart is the negative fixture for
// warp_unbounded_restart_total: restarts beyond the configured limit.
func TestHardGateProducer_WARPUnboundedRestart(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < rt.cfg.MaxRestarts; i++ {
		if err := rt.Restart("sess-a"); err != nil {
			t.Fatalf("restart %d rejected: %v", i, err)
		}
	}
	if err := rt.Restart("sess-a"); err == nil {
		t.Fatal("restart beyond limit accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpUnboundedRestart); got == 0 {
		t.Fatal("warp_unbounded_restart_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPUnboundedRegistration is the negative fixture for
// warp_unbounded_registration_total: enrollment attempts beyond the policy
// MaxAttempts limit.
func TestHardGateProducer_WARPUnboundedRegistration(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	policy := DefaultEnrollmentPolicy()
	for i := 0; i < policy.MaxAttempts; i++ {
		if err := rt.Register("sess-a", policy); err != nil {
			t.Fatalf("registration %d rejected: %v", i, err)
		}
	}
	if err := rt.Register("sess-a", policy); err == nil {
		t.Fatal("registration beyond limit accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpUnboundedRegistration); got == 0 {
		t.Fatal("warp_unbounded_registration_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPUnrelatedControlAction is the negative fixture for
// warp_unrelated_control_action_total: a control action on a flow that is not
// part of the session authorization.
func TestHardGateProducer_WARPUnrelatedControlAction(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	rt.ObserveHealth("sess-a", true, true)
	policy := DialPolicy{Mark: 0xA001, BindDevice: "wg0", EndpointPin: "pin", DirectControl: true, ProxyEnvDisabled: true, Generation: 1}
	lease := TunLease{SessionID: "sess-a", Interface: "b4tun0", Address: "10.0.0.2", MTU: 1500, State: TunOwned}
	auth := &TransportAuthorization{FlowID: "flow-1", ServiceProfile: "default", ClientKey: "ck", DestinationHash: "hash-1", RouteGeneration: 1, ConfigGeneration: 1, AllowForwarded: true}
	if err := rt.ApplyRoute("sess-a", policy, lease, []string{"1.1.1.1"}, auth); err != nil {
		t.Fatal(err)
	}
	// Control action on flow-2, while the authorization covers flow-1 only.
	if err := rt.ControlAction("sess-a", "flow-2", true); err == nil {
		t.Fatal("unrelated control action accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpUnrelatedControlAction); got == 0 {
		t.Fatal("warp_unrelated_control_action_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPRollbackFailure is the negative fixture for
// warp_rollback_failure_total: rollback with no previous binding.
func TestHardGateProducer_WARPRollbackFailure(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	rt.ObserveHealth("sess-a", true, true)
	policy := DialPolicy{Mark: 0xB001, BindDevice: "wg0", EndpointPin: "pin", DirectControl: true, ProxyEnvDisabled: true, Generation: 1}
	lease := TunLease{SessionID: "sess-a", Interface: "b4tun0", Address: "10.0.0.2", MTU: 1500, State: TunOwned}
	auth := &TransportAuthorization{FlowID: "flow-1", ServiceProfile: "default", ClientKey: "ck", DestinationHash: "hash-1", RouteGeneration: 1, ConfigGeneration: 1, AllowForwarded: true}
	if err := rt.ApplyRoute("sess-a", policy, lease, []string{"1.1.1.1"}, auth); err != nil {
		t.Fatal(err)
	}
	// Only one binding exists: nothing to roll back to.
	if err := rt.Rollback("sess-a"); err == nil {
		t.Fatal("rollback with no previous state accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpRollbackFailure); got == 0 {
		t.Fatal("warp_rollback_failure_total not incremented (zero-tolerance gate)")
	}
}

// traceEvent builds a sealed P0 trace event for a session. Callers override
// RouteGeneration/StateAfter/Payload for the specific violation branch.
func traceEvent(session string, seq uint64, eventName string) TransportTraceEnvelope {
	return TransportTraceEnvelope{
		SchemaVersion: 2, BootID: "b", ProcessID: "p", SessionID: session,
		Sequence: seq, Priority: P0, Event: eventName, ObservedAt: time.Now(),
	}.Seal()
}

// appliedRoute registers a session, proves liveness and applies one route with
// generation 1 (the common §73B fixture preamble).
func appliedRoute(t *testing.T, rt *Runtime, session string, mark uint32) {
	t.Helper()
	if err := rt.Register(session, DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	rt.ObserveHealth(session, true, true)
	policy := DialPolicy{Mark: mark, BindDevice: "wg0", EndpointPin: "pin", DirectControl: true, ProxyEnvDisabled: true, Generation: 1}
	lease := TunLease{SessionID: session, Interface: "b4tun0", Address: "10.0.0.2", MTU: 1500, State: TunOwned}
	auth := &TransportAuthorization{FlowID: "flow-1", ServiceProfile: "default", ClientKey: "ck", DestinationHash: "hash-1", RouteGeneration: 1, ConfigGeneration: 1, AllowForwarded: true}
	if err := rt.ApplyRoute(session, policy, lease, []string{"1.1.1.1"}, auth); err != nil {
		t.Fatal(err)
	}
}

// TestHardGateProducer_WARPTraceSecretLeak is the negative fixture for
// warp_trace_secret_leak_total: a trace payload carrying a never-emit key
// class (§61.3) whose value is NOT a stored secret, so the §72 store-level
// raw-secret gate stays clean and only the trace-level gate fires.
func TestHardGateProducer_WARPTraceSecretLeak(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := rt.PutSecret("sess-a", "cert-key", []byte("cert-material")); err != nil {
		t.Fatal(err)
	}
	appliedRoute(t, rt, "sess-a", 0xC001)

	event := traceEvent("sess-a", 1, "dial")
	event.Payload = map[string]string{"private_key": "attacker-material"}
	if rt.PublishTrace("sess-a", event) {
		t.Fatal("trace with never-emit payload key accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpTraceSecretLeak); got == 0 {
		t.Fatal("warp_trace_secret_leak_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPTraceRequiredEventMissing is the negative fixture
// for warp_trace_required_event_missing_total: the trace-to-status cross-check
// (§63.2) finds a required event absent from the pipeline snapshot.
func TestHardGateProducer_WARPTraceRequiredEventMissing(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	appliedRoute(t, rt, "sess-a", 0xC101)
	if !rt.PublishTrace("sess-a", traceEvent("sess-a", 1, "warp_engine_provisioned")) {
		t.Fatal("required trace event rejected")
	}
	// "warp_route_applied" was never published: completeness check must fail.
	missing := rt.VerifyTraceCompleteness("sess-a", []string{"warp_engine_provisioned", "warp_route_applied"})
	if len(missing) != 1 || missing[0] != "warp_route_applied" {
		t.Fatalf("unexpected missing set: %v", missing)
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpTraceRequiredEventMissing); got == 0 {
		t.Fatal("warp_trace_required_event_missing_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPTraceDroppedRequiredEvent is the negative fixture
// for warp_trace_dropped_required_event_total: a P0 required event that cannot
// be stored because the ring holds only P0/P1 events (§61.2).
func TestHardGateProducer_WARPTraceDroppedRequiredEvent(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := NewRuntime(Config{TraceCapacity: 2})
	appliedRoute(t, rt, "sess-a", 0xC201)
	// Fill the whole ring with P0/P1 required events.
	for i := uint64(1); i <= 2; i++ {
		if !rt.PublishTrace("sess-a", traceEvent("sess-a", i, "phase")) {
			t.Fatalf("required event %d rejected before ring saturation", i)
		}
	}
	// Third required event cannot be stored: dropped required event.
	if rt.PublishTrace("sess-a", traceEvent("sess-a", 3, "phase")) {
		t.Fatal("dropped required event accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpTraceDroppedRequiredEvent); got == 0 {
		t.Fatal("warp_trace_dropped_required_event_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPTraceEventOrderViolation is the negative fixture
// for warp_trace_event_order_violation_total: a non-monotonic per-session
// sequence (§61.1).
func TestHardGateProducer_WARPTraceEventOrderViolation(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	appliedRoute(t, rt, "sess-a", 0xC301)
	if !rt.PublishTrace("sess-a", traceEvent("sess-a", 1, "phase")) {
		t.Fatal("first trace event rejected")
	}
	if rt.PublishTrace("sess-a", traceEvent("sess-a", 1, "phase")) {
		t.Fatal("non-monotonic event sequence accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpTraceEventOrderViolation); got == 0 {
		t.Fatal("warp_trace_event_order_violation_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPTraceGenerationMismatch is the negative fixture for
// warp_trace_generation_mismatch_total: a trace event claiming a route
// generation different from the applied route generation (§61.1).
func TestHardGateProducer_WARPTraceGenerationMismatch(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	appliedRoute(t, rt, "sess-a", 0xC401)
	// Applied route uses generation 1; announce generation 2.
	event := traceEvent("sess-a", 1, "masque_connected")
	event.RouteGeneration = "2"
	if rt.PublishTrace("sess-a", event) {
		t.Fatal("generation-mismatched trace accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpTraceGenerationMismatch); got == 0 {
		t.Fatal("warp_trace_generation_mismatch_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPTraceStateMismatch is the negative fixture for
// warp_trace_state_mismatch_total: trace-derived state contradicting the
// runtime state (§63.2) — the runtime reports the route active while the trace
// event announces the route closed.
func TestHardGateProducer_WARPTraceStateMismatch(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	appliedRoute(t, rt, "sess-a", 0xC501)
	event := traceEvent("sess-a", 1, "route-gate")
	event.StateAfter = "closed"
	if rt.PublishTrace("sess-a", event) {
		t.Fatal("state-mismatched trace accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpTraceStateMismatch); got == 0 {
		t.Fatal("warp_trace_state_mismatch_total not incremented (zero-tolerance gate)")
	}
	// second mismatch direction: active/established trace before any route apply
	// (runtime.go case "active","established" -> !st.hasApplied).
	observability.Default().Metrics.Reset()
	rt2 := newProducerRuntime()
	if err := rt2.Register("sess-b", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	rt2.ObserveHealth("sess-b", true, true)
	event2 := traceEvent("sess-b", 1, "route-active")
	event2.StateAfter = "active"
	if rt2.PublishTrace("sess-b", event2) {
		t.Fatal("state-mismatched active trace accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpTraceStateMismatch); got == 0 {
		t.Fatal("warp_trace_state_mismatch_total not incremented on active-before-apply (zero-tolerance gate)")
	}
}

// --- §73B nested dependency-graph producers (addendum §62.4) ---

// TestHardGateProducer_WARPNestedMissingParentLink is the negative fixture for
// warp_nested_missing_parent_link_total: child promotion without a current
// parent link.
func TestHardGateProducer_WARPNestedMissingParentLink(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	nb := &NestedBackend{} // no parent link at all
	if err := rt.NestedPromote(nb, 1); err == nil {
		t.Fatal("nested promotion without parent link accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpNestedMissingParentLink); got == 0 {
		t.Fatal("warp_nested_missing_parent_link_total not incremented (zero-tolerance gate)")
	}
	// second site: parent token use on a backend without a link
	// (nested_runtime.go NestedUseParentToken guard).
	observability.Default().Metrics.Reset()
	nb2 := &NestedBackend{}
	if err := rt.NestedUseParentToken(nb2, "token-x", 1); err == nil {
		t.Fatal("parent token use without parent link accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpNestedMissingParentLink); got == 0 {
		t.Fatal("warp_nested_missing_parent_link_total not incremented on token use (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPNestedRouteActiveWithoutParentHealth is the negative
// fixture for warp_nested_route_active_without_parent_health_total: promotion
// of a child route while the parent link is not healthy.
func TestHardGateProducer_WARPNestedRouteActiveWithoutParentHealth(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	nb := &NestedBackend{Link: TunnelDependencyLink{
		ParentSession: "parent", InnerSession: "child",
		ParentSessionGen: 3, ParentRouteGen: 2, Revalidated: true, Valid: true,
		ParentHealthy: false,
	}}
	nb.RevalidateParent(3, false)
	if err := rt.NestedPromote(nb, 3); err == nil {
		t.Fatal("nested promotion with unhealthy parent accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpNestedRouteActiveWithoutParentHealth); got == 0 {
		t.Fatal("warp_nested_route_active_without_parent_health_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPNestedParentGenerationMismatch is the negative
// fixture for warp_nested_parent_generation_mismatch_total: promotion claiming
// a parent SessionGen other than the revalidated one (parent reconnect case).
func TestHardGateProducer_WARPNestedParentGenerationMismatch(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	nb := &NestedBackend{Link: TunnelDependencyLink{
		ParentSession: "parent", InnerSession: "child",
		ParentSessionGen: 3, ParentRouteGen: 2, Revalidated: true, Valid: true,
		ParentHealthy: true,
	}}
	if err := rt.NestedPromote(nb, 2); err == nil { // claims stale gen 2, link revalidated against 3
		t.Fatal("nested promotion with mismatched parent generation accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpNestedParentGenerationMismatch); got == 0 {
		t.Fatal("warp_nested_parent_generation_mismatch_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPNestedControlDirectLeak is the negative fixture for
// warp_nested_control_direct_leak_total: inner control entering the base path
// without the inner-control mark.
func TestHardGateProducer_WARPNestedControlDirectLeak(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.NestedControl(false); err == nil {
		t.Fatal("inner control direct leak accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpNestedControlDirectLeak); got == 0 {
		t.Fatal("warp_nested_control_direct_leak_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPNestedStaleParentToken is the negative fixture for
// warp_nested_stale_parent_token_total: binding to a parent route token from a
// retired generation after link revalidation.
func TestHardGateProducer_WARPNestedStaleParentToken(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	nb := &NestedBackend{Link: TunnelDependencyLink{
		ParentSession: "parent", InnerSession: "child",
		ParentRouteID: "token-2", ParentRouteGen: 2, Valid: true,
	}}
	if err := rt.NestedUseParentToken(nb, "token-1", 1); err == nil {
		t.Fatal("stale parent route token accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpNestedStaleParentToken); got == 0 {
		t.Fatal("warp_nested_stale_parent_token_total not incremented (zero-tolerance gate)")
	}
}
