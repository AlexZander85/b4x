package mtproto

// Hard-gate producer fixtures for the TGB Telegram bridge (FB-02 TGB
// section, §33 of the DDI/TGB addendum v1.0). Each test drives the real
// production guard in src/mtproto/hard_gate_producers.go that emits a
// registered hard-gate metric and asserts the counter moved. All ten gates
// are zero-tolerance violation counters, so every fixture is a negative
// fixture: it exercises the violating branch and asserts the counter
// incremented.
//
// These tests are referenced from specs/registries/hard_gates.yaml
// (test_producer / mutation_test / evidence_artifact) and from
// artifacts/remediation/FB02_DDI_TGB_PRODUCERS.json.

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

func tgbCounterValue(t *testing.T, name string) uint64 {
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

func assertTGBInc(t *testing.T, name string, trigger func()) {
	t.Helper()
	observability.Default().Metrics.Reset()
	before := tgbCounterValue(t, name)
	trigger()
	after := tgbCounterValue(t, name)
	if after <= before {
		t.Fatalf("%s: expected violating branch to increment counter, before=%d after=%d", name, before, after)
	}
}

func TestHardGateProducer_TGBZeroByteHandledDrop(t *testing.T) {
	assertTGBInc(t, observability.MetricMTProtoZeroByteHandledDrop, func() {
		ZeroByteHandledDrop(BridgeOutcome{Disposition: BridgeHandled, Reason: ReasonZeroByte})
	})
}

func TestHardGateProducer_TGBFixed5sDestructiveTimeout(t *testing.T) {
	assertTGBInc(t, observability.MetricMTProtoFixed5sDestructiveTimeout, func() {
		DestructiveTimeout(true)
	})
}

func TestHardGateProducer_TGBUnboundedPending(t *testing.T) {
	assertTGBInc(t, observability.MetricMTProtoUnboundedPending, func() {
		PendingBudgetBounded(0)
	})
}

func TestHardGateProducer_TGBPendingPerClientBypass(t *testing.T) {
	assertTGBInc(t, observability.MetricMTProtoPendingPerClientBypass, func() {
		PerClientPendingBounded(128, 0)
	})
}

func TestHardGateProducer_TGBPrefixLoss(t *testing.T) {
	assertTGBInc(t, observability.MetricMTProtoPrefixLoss, func() {
		PrefixHandoffComplete([]byte("prefix-data"), 3)
	})
}

func TestHardGateProducer_TGBPrefixDuplicate(t *testing.T) {
	assertTGBInc(t, observability.MetricMTProtoPrefixDuplicate, func() {
		PrefixHandoffNonDuplicate([]byte("prefix-data"), 20)
	})
}

func TestHardGateProducer_TGBRouteRecursion(t *testing.T) {
	assertTGBInc(t, observability.MetricMTProtoRouteRecursion, func() {
		RoutePlanNonRecursive(RoutePlan{Attempts: []BridgeRoute{RoutePrimary}, RecursionGuard: false})
	})
}

func TestHardGateProducer_TGBPrimaryFailureSilentDrop(t *testing.T) {
	assertTGBInc(t, observability.MetricMTProtoPrimaryFailureSilentDrop, func() {
		PrimaryFailureDisposition(BridgeOutcome{Disposition: BridgeDrop, Reason: ReasonDialFailed})
	})
}

func TestHardGateProducer_TGBOverflowWithoutReason(t *testing.T) {
	assertTGBInc(t, observability.MetricMTProtoOverflowWithoutReason, func() {
		OverflowWithReason(ErrPendingOverflow, "")
	})
}

func TestHardGateProducer_TGBShutdownLeak(t *testing.T) {
	assertTGBInc(t, observability.MetricMTProtoShutdownLeak, func() {
		m := NewPendingHandshakeManager(8, 2)
		tok, err := m.Acquire("client-a", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		m.closed = true
		_ = tok
		ShutdownPendingDrained(m)
	})
}
