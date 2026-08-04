package mtproto

// Hard-gate producers for the TGB Telegram bridge (FB-02 TGB section, §33 of
// the DDI/TGB addendum v1.0). Each guard is a production function that
// models one stage of the bridge lifecycle — pending-handshake budget,
// prefix handoff, route plan, failure disposition and shutdown — reusing
// the model in this package (PendingHandshakeManager, PrefixHandoff,
// RoutePlan, BridgeOutcome dispositions/reasons).
//
// Every violating branch increments exactly one zero-tolerance counter from
// src/observability/ddi.go; fixtures in hard_gate_producers_test.go drive
// each violating branch and assert the counter moved.

import (
	"github.com/daniellavrushin/b4/observability"
)

func tgbInc(name string) {
	observability.Default().Metrics.Inc(name, nil, 1)
}

// ZeroByteHandledDrop refuses to count a zero-byte connection as a handled
// bridge outcome (zero-byte must never be recorded as handled).
func ZeroByteHandledDrop(o BridgeOutcome) bool {
	if o.Reason == ReasonZeroByte && o.Disposition == BridgeHandled {
		tgbInc(observability.MetricMTProtoZeroByteHandledDrop)
		return false
	}
	return true
}

// DestructiveTimeoutRefuses a fixed 5-second destructive timeout: timeouts
// must be adaptive to path state, never a hardcoded destructive floor.
func DestructiveTimeout(fixed5s bool) bool {
	if fixed5s {
		tgbInc(observability.MetricMTProtoFixed5sDestructiveTimeout)
		return false
	}
	return true
}

// PendingBudgetBounded refuses an unbounded pending-handshake budget
// (maxGlobal <= 0 must never bypass the bound).
func PendingBudgetBounded(maxGlobal int) bool {
	if maxGlobal <= 0 {
		tgbInc(observability.MetricMTProtoUnboundedPending)
		return false
	}
	return true
}

// PerClientPendingBounded refuses a per-client pending limit that is
// disabled (maxClient <= 0) or larger than the global bound (which makes
// the per-client check meaningless).
func PerClientPendingBounded(maxGlobal, maxClient int) bool {
	if maxClient <= 0 || maxClient > maxGlobal {
		tgbInc(observability.MetricMTProtoPendingPerClientBypass)
		return false
	}
	return true
}

// PrefixHandoffComplete refuses a prefix handoff that delivered fewer bytes
// than the captured prefix (silent prefix loss).
func PrefixHandoffComplete(prefix []byte, delivered int) bool {
	if delivered < len(prefix) {
		tgbInc(observability.MetricMTProtoPrefixLoss)
		return false
	}
	return true
}

// PrefixHandoffNonDuplicate refuses a prefix handoff that replayed more
// bytes than the captured prefix (duplicate replay).
func PrefixHandoffNonDuplicate(prefix []byte, delivered int) bool {
	if delivered > len(prefix) {
		tgbInc(observability.MetricMTProtoPrefixDuplicate)
		return false
	}
	return true
}

// RoutePlanNonRecursive refuses a route plan executed without the recursion
// guard.
func RoutePlanNonRecursive(p RoutePlan) bool {
	if !p.RecursionGuard {
		tgbInc(observability.MetricMTProtoRouteRecursion)
		return false
	}
	return true
}

// PrimaryFailureDisposition refuses to drop a connection silently when the
// primary route failed: the outcome must fail open, never silently drop.
func PrimaryFailureDisposition(o BridgeOutcome) bool {
	if o.Reason == ReasonDialFailed && o.Disposition == BridgeDrop {
		tgbInc(observability.MetricMTProtoPrimaryFailureSilentDrop)
		return false
	}
	return true
}

// OverflowWithReason refuses a pending overflow that is reported without a
// reason (global-budget vs per-client-budget attribution must be explicit).
func OverflowWithReason(err error, reason string) bool {
	if err == ErrPendingOverflow && reason == "" {
		tgbInc(observability.MetricMTProtoOverflowWithoutReason)
		return false
	}
	return true
}

// ShutdownPendingDrained refuses a shutdown that leaves pending handshake
// tokens unreleased (shutdown leak).
func ShutdownPendingDrained(m *PendingHandshakeManager) bool {
	if m != nil {
		m.mu.Lock()
		leaked := len(m.pending) > 0
		m.mu.Unlock()
		if leaked {
			tgbInc(observability.MetricMTProtoShutdownLeak)
			return false
		}
	}
	return true
}
