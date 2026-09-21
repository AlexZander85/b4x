package vless

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// StatTTL bounds how long a node's last verdict is trusted. Public free nodes
// rot fast: a node that worked yesterday is a coin toss today (Nova's rule,
// design §8), so anything older than this is ignored by the ordering.
const StatTTL = 24 * time.Hour

// NodeStat is the persisted per-node outcome memory. It is advisory — it only
// orders candidates, never gates one — so a write failure is never fatal.
type NodeStat struct {
	OK         int     `json:"ok"`
	Fail       int     `json:"fail"`
	LastOKAt   float64 `json:"last_ok_at,omitempty"`
	LastFailAt float64 `json:"last_fail_at,omitempty"`
	RTTMs      int     `json:"rtt_ms,omitempty"`
	RTTAt      float64 `json:"rtt_at,omitempty"`
	FailStreak int     `json:"fail_streak,omitempty"`
}

// StatsStore is the node-outcome memory, persisted 0600 next to the node cache
// so a restart does not re-walk a list of corpses (design §8 last-good).
type StatsStore struct {
	path    string
	mu      sync.Mutex
	entries map[string]NodeStat
}

// LoadStats reads the store; a missing or corrupt file yields an empty store
// (never an error that would block startup).
func LoadStats(path string) (*StatsStore, error) {
	s := &StatsStore{path: path, entries: map[string]NodeStat{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	var raw map[string]NodeStat
	if err := json.Unmarshal(b, &raw); err != nil {
		return &StatsStore{path: path, entries: map[string]NodeStat{}}, nil
	}
	if raw != nil {
		s.entries = raw
	}
	return s, nil
}

// Stat returns the stored memory for one node identity (zero when unknown).
func (s *StatsStore) Stat(identity string) NodeStat {
	if s == nil {
		return NodeStat{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries[identity]
}

// RecordResults folds one probe pass into the memory.
func (s *StatsStore) RecordResults(results []ProbeResult, now time.Time) {
	if s == nil || len(results) == 0 {
		return
	}
	stamp := float64(now.UnixNano()) / 1e9
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range results {
		id := r.Node.Identity()
		if id == "" {
			continue
		}
		e := s.entries[id]
		if r.OK {
			e.OK++
			e.LastOKAt = stamp
			e.FailStreak = 0
			if r.LatencyMs >= 0 {
				e.RTTMs = int(r.LatencyMs)
				e.RTTAt = stamp
			}
		} else {
			e.Fail++
			e.LastFailAt = stamp
			e.FailStreak++
		}
		s.entries[id] = e
	}
}

// Save writes the store atomically (0600).
func (s *StatsStore) Save() error {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	b, err := json.MarshalIndent(s.entries, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// statAge reports the age of a unix-seconds timestamp, or a negative value when
// it is unset (zero).
func statAge(stamp float64, now time.Time) time.Duration {
	if stamp <= 0 {
		return -1
	}
	return now.Sub(time.Unix(0, int64(stamp*1e9)))
}
