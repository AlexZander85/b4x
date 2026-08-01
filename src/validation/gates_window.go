package validation

// Production validation window (FB-03 owner decision 2026-08-01, phase E2).
//
// Validation API, reports, canary and PromotePending share ONE evaluation of
// the current TestSession/ValidationRun: they all snapshot the internal
// metrics and evaluate the delta of the current window via
// BaselineForRun + EvaluateHardGatesWindow. The process-lifetime wrapper
// (EvaluateHardGates) is NOT used for session promotion.
//
// A new window baseline is allowed only for a new process/run/generation —
// never for a counter reset inside the same session (resets are reported as
// BLOCKED_COUNTER_RESET by the evaluator).

import (
	"sync"
	"time"
)

// ProductionWindow is the generation-keyed baseline store of the running
// process. It is concurrency-safe: consumers may evaluate concurrently.
type ProductionWindow struct {
	mu         sync.Mutex
	baseline   map[string]uint64
	generation string
	startedAt  time.Time
}

var productionWindow = &ProductionWindow{}

// BaselineForRun returns the stored window baseline for the generation, or
// captures the current counters as the baseline for a new process/run/
// generation. Subsequent evaluations of the same generation reuse the same
// baseline, so the delta accumulates across retries of the same session;
// a new generation (or a fresh process) starts a new window.
func BaselineForRun(generation string, current map[string]uint64) map[string]uint64 {
	productionWindow.mu.Lock()
	defer productionWindow.mu.Unlock()
	if productionWindow.baseline != nil && productionWindow.generation == generation {
		return productionWindow.baseline
	}
	baseline := make(map[string]uint64, len(current))
	for name, value := range current {
		baseline[name] = value
	}
	productionWindow.baseline = baseline
	productionWindow.generation = generation
	productionWindow.startedAt = time.Now().UTC()
	return baseline
}

// WindowInfo describes the active production validation window.
type WindowInfo struct {
	Generation string    `json:"generation,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	Active     bool      `json:"active"`
}

// ProductionWindowInfo reports the current window identity so consumers can
// attest that they evaluate the same session window (criterion 4: identical
// window baseline/delta/generation across consumers).
func ProductionWindowInfo() WindowInfo {
	productionWindow.mu.Lock()
	defer productionWindow.mu.Unlock()
	if productionWindow.baseline == nil {
		return WindowInfo{}
	}
	return WindowInfo{
		Generation: productionWindow.generation,
		StartedAt:  productionWindow.startedAt,
		Active:     true,
	}
}

// ResetProductionWindow clears the production window (test isolation and
// process-restart simulation). The next BaselineForRun captures a fresh
// baseline; this is the ONLY way a baseline may change without a new
// process/run/generation (test hook, never called by production code).
func ResetProductionWindow() {
	productionWindow.mu.Lock()
	defer productionWindow.mu.Unlock()
	productionWindow.baseline = nil
	productionWindow.generation = ""
	productionWindow.startedAt = time.Time{}
}
