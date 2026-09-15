package torscan

// Persistent probe budget. Relay scanning is useful against DPI, but repeated
// active handshakes to third-party ORPorts are unnecessary and can resemble
// abuse. Both the per-address cooldown and the aggregate rate budget survive
// b4 restarts.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	probeCooldown        = 6 * time.Hour
	probeBudgetWindow    = 6 * time.Hour
	probeBudgetPerWindow = 72
	maxLedgerEntries     = 4096
)

type probeLedger struct {
	Version  int              `json:"version"`
	Last     map[string]int64  `json:"last_probe_ms"`
	Attempts []int64          `json:"attempt_ms,omitempty"`
}

func loadProbeLedger(path string) probeLedger {
	l := probeLedger{Version: 1, Last: map[string]int64{}}
	if path == "" {
		return l
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return l
	}
	if json.Unmarshal(blob, &l) != nil || l.Version != 1 || l.Last == nil {
		return probeLedger{Version: 1, Last: map[string]int64{}}
	}
	return l
}

func (l *probeLedger) eligible(addr string, now time.Time) bool {
	ms, ok := l.Last[addr]
	if !ok || ms <= 0 {
		return true
	}
	return now.Sub(time.UnixMilli(ms)) >= probeCooldown
}

func (l *probeLedger) pruneAttempts(now time.Time) {
	cutoff := now.Add(-probeBudgetWindow).UnixMilli()
	kept := l.Attempts[:0]
	for _, ms := range l.Attempts {
		if ms > cutoff {
			kept = append(kept, ms)
		}
	}
	l.Attempts = kept
}

// reserve records scheduling, not success. A failed/dead ORPort should not be
// hammered every time the API is pressed, and a rotating set of new ORPorts
// must not bypass the aggregate safety budget.
func (l *probeLedger) reserve(addr string, now time.Time) bool {
	l.pruneAttempts(now)
	if len(l.Attempts) >= probeBudgetPerWindow {
		return false
	}
	if l.Last == nil {
		l.Last = map[string]int64{}
	}
	ms := now.UnixMilli()
	l.Last[addr] = ms
	l.Attempts = append(l.Attempts, ms)
	return true
}

func (l *probeLedger) save(path string) error {
	if path == "" {
		return nil
	}
	if len(l.Last) > maxLedgerEntries {
		type item struct {
			addr string
			ms   int64
		}
		items := make([]item, 0, len(l.Last))
		for addr, ms := range l.Last {
			items = append(items, item{addr: addr, ms: ms})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ms > items[j].ms })
		trimmed := make(map[string]int64, maxLedgerEntries)
		for _, it := range items[:maxLedgerEntries] {
			trimmed[it.addr] = it.ms
		}
		l.Last = trimmed
	}
	blob, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".torscan-ledger-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}
	if _, err := tmp.Write(blob); err != nil {
		cleanup()
		return err
	}
	_ = tmp.Chmod(0o600)
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

func ledgerPath(cachePath string) string {
	if cachePath == "" {
		return ""
	}
	return cachePath + ".probe-ledger.json"
}
