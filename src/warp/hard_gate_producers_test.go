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
