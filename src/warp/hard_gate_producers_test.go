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

// --- §73B WARP geo producers (addendum §62.5) ---

// TestHardGateProducer_WARPGeoAttestationWithoutRouteCounterDelta is the
// negative fixture for warp_geo_attestation_without_route_counter_delta_total:
// an attestation commit whose fresh provider result carries no route counter
// delta (§62.5: each provider result is an independent event with a route
// counter delta).
func TestHardGateProducer_WARPGeoAttestationWithoutRouteCounterDelta(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	now := time.Now()
	obs := []GeoObservation{
		{Provider: "geo-a", PublicIP: "1.2.3.4", PathID: "path-1", Class: GeoNonRU, DNSProof: true, CounterDelta: 7, ObservedAt: now, ExpiresAt: now.Add(time.Hour)},
		{Provider: "geo-b", PublicIP: "1.2.3.4", PathID: "path-1", Class: GeoNonRU, DNSProof: true, CounterDelta: 0, ObservedAt: now, ExpiresAt: now.Add(time.Hour)},
	}
	if _, err := rt.GeoAttestationCommit(obs, now); err == nil {
		t.Fatal("geo attestation without route counter delta accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpGeoAttestationWithoutRouteCounterDelta); got == 0 {
		t.Fatal("warp_geo_attestation_without_route_counter_delta_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPGeoQuorumWithoutProviderEvents is the negative
// fixture for warp_geo_quorum_without_provider_events_total: a quorum decision
// event with zero successful provider events (every result lacks DNS path
// proof; §62.5 "a single summary event without provider events and path proof
// is invalid").
func TestHardGateProducer_WARPGeoQuorumWithoutProviderEvents(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	now := time.Now()
	obs := []GeoObservation{
		{Provider: "geo-a", PublicIP: "1.2.3.4", PathID: "path-1", Class: GeoNonRU, DNSProof: false, CounterDelta: 1, ObservedAt: now, ExpiresAt: now.Add(time.Hour)},
		{Provider: "geo-b", PublicIP: "1.2.3.4", PathID: "path-1", Class: GeoNonRU, DNSProof: false, CounterDelta: 1, ObservedAt: now, ExpiresAt: now.Add(time.Hour)},
	}
	if _, err := rt.GeoQuorumDecision(obs, now); err == nil {
		t.Fatal("geo quorum decision without provider events accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpGeoQuorumWithoutProviderEvents); got == 0 {
		t.Fatal("warp_geo_quorum_without_provider_events_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPGeoRouteGateStateMismatch is the negative fixture
// for warp_geo_route_gate_state_mismatch_total (§62.5 GeoQuorumTrace
// RouteGateBefore/RouteGateAfter). Both Inc sites are covered: the gate
// closing under a valid attestation and the gate staying open after an
// invalid (revoked) attestation.
func TestHardGateProducer_WARPGeoRouteGateStateMismatch(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	now := time.Now()
	valid := GeoAttestation{Class: GeoNonRU, Providers: 2, Quorum: 2, PublicIP: "1.2.3.4", PathID: "path-1", FreshUntil: now.Add(time.Hour)}
	if err := rt.GeoRouteGateApply(valid, "open", "closed", now); err == nil {
		t.Fatal("geo route-gate state mismatch accepted (gate closed while attestation valid)")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpGeoRouteGateStateMismatch); got == 0 {
		t.Fatal("warp_geo_route_gate_state_mismatch_total not incremented (zero-tolerance gate)")
	}
	// second mismatch direction: revoked attestation, gate stayed open.
	observability.Default().Metrics.Reset()
	revoked := GeoAttestation{Class: GeoDisagreement, Providers: 2, Quorum: 2, Revoked: true}
	if err := rt.GeoRouteGateApply(revoked, "open", "open", now); err == nil {
		t.Fatal("geo route-gate state mismatch accepted (gate stayed open after invalid attestation)")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpGeoRouteGateStateMismatch); got == 0 {
		t.Fatal("warp_geo_route_gate_state_mismatch_total not incremented on open-gate-after-invalid (zero-tolerance gate)")
	}
}

// --- §73B WARP path-proof producers (addendum §62.2/§62.3/§62.6) ---

// TestHardGateProducer_WARPRoutePromotedWithoutPathProofEvent is the negative
// fixture for warp_route_promoted_without_path_proof_event_total: a route
// promotion whose path proof carries no counter delta ("route/rule existence
// is not path proof", §62.2).
func TestHardGateProducer_WARPRoutePromotedWithoutPathProofEvent(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	proof := TransportPathProof{ProofID: "proof-1", ProofKind: "router", ExpectedSessionGen: 1, ExpectedRouteGen: 1, Passed: true}
	if err := rt.PathProofPromote("sess-a", proof); err == nil {
		t.Fatal("route promotion without path-proof counter delta accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpRoutePromotedWithoutPathProofEvent); got == 0 {
		t.Fatal("warp_route_promoted_without_path_proof_event_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPForwardedSuccessWithoutBindingTrace is the negative
// fixture for warp_forwarded_success_without_binding_trace_total: a forwarded
// success whose correlation lacks the binding trace causal chain
// (BindingID -> RouteTokenID -> PathProofID, §62.3).
func TestHardGateProducer_WARPForwardedSuccessWithoutBindingTrace(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	corr := ForwardedFlowCorrelation{RouteTokenID: "token-1", PathProofID: "proof-1"} // BindingID missing
	if err := rt.ForwardedSuccess("sess-a", corr); err == nil {
		t.Fatal("forwarded success without binding trace accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpForwardedSuccessWithoutBindingTrace); got == 0 {
		t.Fatal("warp_forwarded_success_without_binding_trace_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPDirectFallbackWithoutTrace is the negative fixture
// for warp_direct_fallback_without_trace_total: a direct fallback with no
// path-probe event in the session trace pipeline.
func TestHardGateProducer_WARPDirectFallbackWithoutTrace(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.Register("sess-a", DefaultEnrollmentPolicy()); err != nil {
		t.Fatal(err)
	}
	// No path-probe trace is published before the fallback decision.
	if err := rt.DirectFallback("sess-a"); err == nil {
		t.Fatal("direct fallback without path-probe trace accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpDirectFallbackWithoutTrace); got == 0 {
		t.Fatal("warp_direct_fallback_without_trace_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPDNSPathUnproven is the negative fixture for
// warp_dns_path_unproven_total: a DNS path claim whose observed resolver path
// differs from the expected path (§62.6).
func TestHardGateProducer_WARPDNSPathUnproven(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	dns := DNSPathTrace{PathID: "dns-1", ExpectedPath: "resolver-a", ObservedPath: "resolver-b", Passed: true}
	if err := rt.DNSPathProof(dns); err == nil {
		t.Fatal("unproven dns path accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpDNSPathUnproven); got == 0 {
		t.Fatal("warp_dns_path_unproven_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPIPv6PathUnproven is the negative fixture for
// warp_ipv6_path_unproven_total: a stale IPv6 path claim (probe did not pass,
// §62.6).
func TestHardGateProducer_WARPIPv6PathUnproven(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	if err := rt.IPv6PathProof(IPFamilyPathTrace{PathID: "v6-1", Family: "ipv6", Passed: false}); err == nil {
		t.Fatal("unproven ipv6 path accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpIPv6PathUnproven); got == 0 {
		t.Fatal("warp_ipv6_path_unproven_total not incremented (zero-tolerance gate)")
	}
}

// --- §73B WARP resource-ownership / cleanup / cutoff / non-RU producers
// (addendum §62.5/§62.7/§62.8) ---

// TestHardGateProducer_WARPNonRURevocationExceededDeadline is the negative
// fixture for warp_nonru_revocation_exceeded_deadline_total: a strict non-RU
// revocation that starts after its revocation deadline.
func TestHardGateProducer_WARPNonRURevocationExceededDeadline(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	deadline := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	trace := NonRURevocationTrace{AttestationID: "att-1", RevocationStartedAt: deadline.Add(time.Hour), RevocationDeadline: deadline}
	if err := rt.NonRURevocationDeadline(trace); err == nil {
		t.Fatal("non-ru revocation after deadline accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpNonRURevocationExceededDeadline); got == 0 {
		t.Fatal("warp_nonru_revocation_exceeded_deadline_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPNonRUPublicIPChangeWithoutRefresh is the negative
// fixture for warp_nonru_public_ip_change_without_refresh_total: a public-IP
// change with no fresh attestation refresh issued.
func TestHardGateProducer_WARPNonRUPublicIPChangeWithoutRefresh(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	ev := PublicIPChangeEvent{AttestationID: "att-1", PreviousIPHash: "ip-1", ObservedIPHash: "ip-2"} // RefreshIssued missing
	if err := rt.NonRUPublicIPChange(ev); err == nil {
		t.Fatal("public ip change without attestation refresh accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpNonRUPublicIPChangeWithoutRefresh); got == 0 {
		t.Fatal("warp_nonru_public_ip_change_without_refresh_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPConnectIPEventWrongGeneration is the negative
// fixture for warp_connect_ip_event_wrong_generation_total: a CONNECT-IP
// event claiming a generation different from the expected one.
func TestHardGateProducer_WARPConnectIPEventWrongGeneration(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	ev := ConnectIPEventTrace{InstanceID: "inst-1", SessionID: "sess-a", EventProcessGeneration: 2, EventConfigGeneration: 3, ExpectedProcessGeneration: 1, ExpectedConfigGeneration: 3}
	if err := rt.ConnectIPEvent(ev); err == nil {
		t.Fatal("connect-ip event with wrong generation accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpConnectIPEventWrongGeneration); got == 0 {
		t.Fatal("warp_connect_ip_event_wrong_generation_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPPostCutoffMutation is the negative fixture for
// warp_post_cutoff_mutation_total: a payload mutation after the established
// bypass of a CONNECT-IP-confirmed camouflage cutoff (§62.7 hard invariant).
func TestHardGateProducer_WARPPostCutoffMutation(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	trace := CamouflageTrace{PolicyID: "pol-1", CandidateID: "cand-1", ConnectIPConfirmed: true, CutoffSource: "established", CutoffAtSequence: 10, BypassEstablished: true, PostCutoffMutations: 1}
	if err := rt.PostCutoffMutation(trace); err == nil {
		t.Fatal("post-cutoff payload mutation after established bypass accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpPostCutoffMutation); got == 0 {
		t.Fatal("warp_post_cutoff_mutation_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPCleanupIncomplete is the negative fixture for
// warp_cleanup_incomplete_total: a cleanup-completion claim over a
// generation-owned resource without a terminal removal record (§62.8).
func TestHardGateProducer_WARPCleanupIncomplete(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	report := CleanupReport{SessionGen: 1, Completed: true, Resources: []OwnedResourceTrace{
		{ResourceType: "route rule", ResourceHash: "r-1", OwnerSessionGen: 1, Foreign: false, RemoveResult: "remove-pending"},
	}}
	if err := rt.CleanupComplete(report); err == nil {
		t.Fatal("cleanup completion claim over resource without terminal record accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpCleanupIncomplete); got == 0 {
		t.Fatal("warp_cleanup_incomplete_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPOwnedResourceLeak is the negative fixture for
// warp_owned_resource_leak_total: a generation-owned resource with no
// terminal removal record at finalize (§62.8).
func TestHardGateProducer_WARPOwnedResourceLeak(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	res := OwnedResourceTrace{ResourceType: "TUN", ResourceHash: "t-1", OwnerSessionGen: 1, Foreign: false} // no RemoveResult
	if err := rt.OwnedResourceLeak(res); err == nil {
		t.Fatal("generation-owned resource leak accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpOwnedResourceLeak); got == 0 {
		t.Fatal("warp_owned_resource_leak_total not incremented (zero-tolerance gate)")
	}
}

// TestHardGateProducer_WARPForeignResourceRemoved is the negative fixture for
// warp_foreign_resource_removed_total: a foreign resource that received a
// successful removed-by-b4 event (§62.8: foreign resource MUST never receive
// one).
func TestHardGateProducer_WARPForeignResourceRemoved(t *testing.T) {
	observability.Default().Metrics.Reset()
	rt := newProducerRuntime()
	res := OwnedResourceTrace{ResourceType: "NAT rule", ResourceHash: "n-1", Foreign: true, RemoveResult: "removed-by-b4"}
	if err := rt.ForeignResourceRemoved(res); err == nil {
		t.Fatal("foreign resource removed-by-b4 accepted")
	}
	if got := warpHardGateCounterValue(t, observability.MetricWarpForeignResourceRemoved); got == 0 {
		t.Fatal("warp_foreign_resource_removed_total not incremented (zero-tolerance gate)")
	}
}
