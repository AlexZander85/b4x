// Per-address attempt-outcome memory (Nova 1.32.3 lineage, "stop Proton
// from retrying the same dead nodes forever"). The free-edge node list
// rotates ports on refresh and re-ranks by Load, so an endpoint:port keyed
// memory goes stale within one refresh cycle; an ADDRESS keyed memory
// survives it. The memory feeds the candidate ORDER, never the set: a
// recently failed address sinks to the tail instead of being excluded, and
// a proven address (last success newer than last failure) takes the head —
// a working node does not yield the front of the queue to unproven ones.
//
// Verdicts (Nova connectOrder, four steps collapsed into three address
// tiers — the pair-level steps are the same rule applied per port):
//
//      tier 1  proven:   last success newer than last failure, freshest first,
//                       ONE pair per address (its primary port);
//      tier 2  fresh:    addresses without a failure on record, breadth-first
//                       across their ports (first port of every address, then
//                       the second — a fallback port is never lost);
//      tier 3  failed:   oldest failure first — every new wave of retries
//                       starts from a DIFFERENT node, not the same dead one.
//
// The memory forgets an address after OutcomeMemoryTTL without updates
// (Nova FAILURE_MEMORY_MS = 6 h) and is bounded (Nova OUTCOME_MEMORY_LIMIT
// = 256; the bound drops the OLDEST entries). Router reality: the daemon
// is long-lived and the WAN is single-homed, so the store is in-memory
// (Nova splits per network-class wifi/cell — meaningless on a router).
package proton

import (
        "sync"
        "time"
)

// OutcomeMemory timing and size canon (Nova 1.32.3).
const (
        // OutcomeMemoryTTL is how long an address verdict survives without a
        // new attempt refreshing it.
        OutcomeMemoryTTL = 6 * time.Hour
        // OutcomeMemoryLimit bounds the store; the oldest entries drop first.
        OutcomeMemoryLimit = 256
)

// outcomeRecord is one address verdict.
type outcomeRecord struct {
        lastSuccess time.Time
        lastFailure time.Time
}

// OutcomeMemory remembers per-address attempt verdicts.
type OutcomeMemory struct {
        mu      sync.Mutex
        entries map[string]outcomeRecord
        order   []string // insertion order (bound eviction drops the head)
        now     func() time.Time
}

// NewOutcomeMemory arms the memory; now is injectable (tests).
func NewOutcomeMemory(now func() time.Time) *OutcomeMemory {
        if now == nil {
                now = time.Now
        }
        return &OutcomeMemory{entries: map[string]outcomeRecord{}, now: now}
}

// RecordSuccess notes a data-plane-confirmed success for the address.
func (m *OutcomeMemory) RecordSuccess(addr string) {
        if m == nil || addr == "" {
                return
        }
        m.mu.Lock()
        defer m.mu.Unlock()
        m.expireLocked()
        rec := m.entries[addr]
        rec.lastSuccess = m.now()
        m.putLocked(addr, rec)
}

// RecordFailure notes a failed attempt against the address (any failure
// class: handshake timeout, trust-gate loss, endpoint budget exhaustion).
func (m *OutcomeMemory) RecordFailure(addr string) {
        if m == nil || addr == "" {
                return
        }
        m.mu.Lock()
        defer m.mu.Unlock()
        m.expireLocked()
        rec := m.entries[addr]
        rec.lastFailure = m.now()
        m.putLocked(addr, rec)
}

// putLocked inserts/updates and maintains the insertion order + bound.
func (m *OutcomeMemory) putLocked(addr string, rec outcomeRecord) {
        if _, exists := m.entries[addr]; !exists {
                m.order = append(m.order, addr)
        }
        m.entries[addr] = rec
        // Bound: drop the oldest-inserted entries first.
        for len(m.order) > OutcomeMemoryLimit {
                oldest := m.order[0]
                m.order = m.order[1:]
                delete(m.entries, oldest)
        }
}

// expireLocked forgets addresses whose newest verdict predates the TTL.
func (m *OutcomeMemory) expireLocked() {
        cut := m.now().Add(-OutcomeMemoryTTL)
        kept := m.order[:0]
        for _, addr := range m.order {
                rec := m.entries[addr]
                if rec.lastSuccess.After(cut) || rec.lastFailure.After(cut) {
                        kept = append(kept, addr)
                } else {
                        delete(m.entries, addr)
                }
        }
        m.order = kept
}

// OutcomeSnapshot is a read-only view of one address verdict.
type OutcomeSnapshot struct {
        LastSuccess time.Time
        LastFailure time.Time
}

// Lookup returns the verdict of one address (ok=false when unknown or
// older than the TTL — a stale verdict must never order a seek).
func (m *OutcomeMemory) Lookup(addr string) (OutcomeSnapshot, bool) {
        if m == nil || addr == "" {
                return OutcomeSnapshot{}, false
        }
        m.mu.Lock()
        defer m.mu.Unlock()
        rec, ok := m.entries[addr]
        if !ok {
                return OutcomeSnapshot{}, false
        }
        cut := m.now().Add(-OutcomeMemoryTTL)
        if !rec.lastSuccess.After(cut) && !rec.lastFailure.After(cut) {
                return OutcomeSnapshot{}, false
        }
        return OutcomeSnapshot{LastSuccess: rec.lastSuccess, LastFailure: rec.lastFailure}, true
}

// Len reports the number of remembered addresses (test/diagnostics).
func (m *OutcomeMemory) Len() int {
        if m == nil {
                return 0
        }
        m.mu.Lock()
        defer m.mu.Unlock()
        return len(m.entries)
}

// outcomeTier classifies an address for ordering.
type outcomeTier int

const (
        tierProven outcomeTier = iota // last success newer than last failure
        tierFresh                     // no failure on record (unknown or success-only-stale)
        tierFailed                    // last failure newer than last success (or failure-only)
)

// tierOf is the ordering key; time is the reference "now".
func tierOf(s OutcomeSnapshot, ok bool, now time.Time) outcomeTier {
        if !ok || s.LastFailure.IsZero() {
                return tierFresh
        }
        if s.LastSuccess.After(s.LastFailure) {
                return tierProven
        }
        return tierFailed
}
