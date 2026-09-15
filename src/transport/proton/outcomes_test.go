package proton

import (
        "fmt"
        "testing"
        "time"
)

// Nova 1.32.3 contract tests: the outcome memory re-orders the seek queue so
// dead addresses stop consuming the head of every retry wave.

func memFixture(t *testing.T) (*OutcomeMemory, func(d time.Duration)) {
        t.Helper()
        now := time.Unix(1_700_000_000, 0)
        return NewOutcomeMemory(func() time.Time { return now }),
                func(d time.Duration) { now = now.Add(d) }
}

func TestOutcomeMemoryTiers(t *testing.T) {
        om, advance := memFixture(t)

        om.RecordFailure("1.1.1.1")
        if _, ok := om.Lookup("1.1.1.1"); !ok {
                t.Fatal("failure must be remembered")
        }
        sn, _ := om.Lookup("1.1.1.1")
        if got := tierOf(sn, true, om.now()); got != tierFailed {
                t.Fatalf("failure-only address tier = %d, want tierFailed", got)
        }

        om.RecordSuccess("2.2.2.2")
        advance(time.Minute)
        om.RecordFailure("2.2.2.2") // failure NEWER than success
        sn, _ = om.Lookup("2.2.2.2")
        if got := tierOf(sn, true, om.now()); got != tierFailed {
                t.Fatalf("failed-after-success tier = %d, want tierFailed", got)
        }

        advance(time.Minute)
        om.RecordSuccess("2.2.2.2") // success NEWER again
        sn, _ = om.Lookup("2.2.2.2")
        if got := tierOf(sn, true, om.now()); got != tierProven {
                t.Fatalf("recovered address tier = %d, want tierProven", got)
        }

        if got := tierOf(OutcomeSnapshot{}, false, om.now()); got != tierFresh {
                t.Fatalf("unknown address tier = %d, want tierFresh", got)
        }
}

func TestOutcomeMemoryForgetsAfterTTL(t *testing.T) {
        base := time.Unix(1_700_000_000, 0)
        now := base
        om := NewOutcomeMemory(func() time.Time { return now })
        om.RecordFailure("3.3.3.3")
        now = base.Add(OutcomeMemoryTTL + time.Minute)
        if _, ok := om.Lookup("3.3.3.3"); ok {
                t.Fatal("verdict older than TTL must be forgotten (Lookup view)")
        }
        // The store compacts on the next write; a fresh record sweeps the
        // stale entry out.
        om.RecordFailure("4.4.4.4")
        if _, ok := om.Lookup("3.3.3.3"); ok {
                t.Fatal("stale entry survived the post-write compaction")
        }
        if om.Len() != 1 {
                t.Fatalf("len after compaction = %d, want 1", om.Len())
        }
}

func TestOutcomeMemoryBound(t *testing.T) {
        om, _ := memFixture(t)
        for i := 0; i < OutcomeMemoryLimit+50; i++ {
                om.RecordFailure(fmt.Sprintf("10.0.%d.%d", i/250, i%250))
        }
        if om.Len() > OutcomeMemoryLimit {
                t.Fatalf("len = %d exceeds the bound %d", om.Len(), OutcomeMemoryLimit)
        }
}

func TestCandidatesOrderedTiers(t *testing.T) {
        om, advance := memFixture(t)
        nodes := []Node{
                {Name: "A", Country: "NL", EntryIP: "10.0.0.1", Load: 10},
                {Name: "B", Country: "US", EntryIP: "10.0.0.2", Load: 20},
                {Name: "C", Country: "NO", EntryIP: "10.0.0.3", Load: 30},
                {Name: "D", Country: "SE", EntryIP: "10.0.0.4", Load: 40},
        }

        // B: proven (success newer than failure). C: failed most recently.
        advance(time.Hour)
        om.RecordFailure("10.0.0.2")
        advance(time.Hour)
        om.RecordSuccess("10.0.0.2")
        advance(time.Hour)
        om.RecordFailure("10.0.0.3")

        q := NewQueue(nodes, 0)
        cands := q.CandidatesOrdered(Location{Mode: "auto"}, om)
        if len(cands) == 0 {
                t.Fatal("no candidates")
        }
        // Tier 1: the proven address leads with its primary pair.
        if cands[0].Node.EntryIP != "10.0.0.2" {
                t.Fatalf("head = %s, want the proven 10.0.0.2", cands[0].Node.EntryIP)
        }
        // Tier 3: the failed address must not appear before any fresh address'
        // primary pair. Collect the primary-pair order.
        primaryOrder := []string{}
        seen := map[string]bool{}
        for _, c := range cands {
                if !seen[c.Node.EntryIP] {
                        seen[c.Node.EntryIP] = true
                        primaryOrder = append(primaryOrder, c.Node.EntryIP)
                }
        }
        firstFailed, firstFresh := -1, -1
        for i, ip := range primaryOrder {
                if ip == "10.0.0.1" {
                        firstFresh = i
                }
                if ip == "10.0.0.3" {
                        firstFailed = i
                }
        }
        if firstFresh < 0 || firstFailed < 0 || firstFailed < firstFresh {
                t.Fatalf("failed node (%d) must follow fresh nodes (%d): %v", firstFailed, firstFresh, primaryOrder)
        }
}

func TestCandidatesOrderedPortFallback(t *testing.T) {
        nodes := []Node{
                {Name: "A", Country: "NL", EntryIP: "10.0.0.1", Load: 10},
                {Name: "B", Country: "NL", EntryIP: "10.0.0.2", Load: 20},
                {Name: "C", Country: "NL", EntryIP: "10.0.0.3", Load: 30}, // 3rd of NL: no fallbacks
        }
        q := NewQueue(nodes, 0)
        cands := q.CandidatesOrdered(Location{Mode: "auto"}, nil)
        counts := map[string]int{}
        for _, c := range cands {
                counts[c.Node.EntryIP]++
        }
        if counts["10.0.0.1"] != portFallbacksPerNode || counts["10.0.0.2"] != portFallbacksPerNode {
                t.Fatalf("top-2 country nodes must carry %d ports: %v", portFallbacksPerNode, counts)
        }
        if counts["10.0.0.3"] != 1 {
                t.Fatalf("third country node must carry 1 port: %v", counts)
        }
        // Breadth-first: the first three candidates are the three primaries.
        for i := 0; i < 3; i++ {
                if i > 0 && cands[i].Node.EntryIP == cands[i-1].Node.EntryIP {
                        t.Fatalf("fallback port must not precede another address' primary: %v", cands)
                }
        }
}
