package vless

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatsStorePersistReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	st, err := LoadStats(path)
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	now := time.Now()
	n := nodeAt("a.example.org")
	st.RecordResults([]ProbeResult{{Node: n, OK: true, LatencyMs: 42, Loc: "DE"}}, now)
	if err := st.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm=%o want 600", perm)
	}
	re, err := LoadStats(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := re.Stat(n.Identity())
	if got.OK != 1 || got.RTTMs != 42 || got.LastOKAt <= 0 {
		t.Fatalf("reloaded stat = %+v", got)
	}
	// A failure keeps the record and marks the streak.
	re.RecordResults([]ProbeResult{{Node: n, OK: false, Err: "timeout"}}, now.Add(time.Second))
	got = re.Stat(n.Identity())
	if got.Fail != 1 || got.FailStreak != 1 || got.LastFailAt <= 0 {
		t.Fatalf("after fail = %+v", got)
	}
}

func TestStatsStoreCorruptIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadStats(path)
	if err != nil {
		t.Fatalf("corrupt must not error: %v", err)
	}
	if got := st.Stat("anything"); got != (NodeStat{}) {
		t.Fatalf("corrupt store not empty: %+v", got)
	}
}

func TestSelectorMemoryBeatsFasterNode(t *testing.T) {
	now := time.Now()
	fresh := float64(now.Add(-time.Minute).UnixNano()) / 1e9
	p := fakeProber{byHost: map[string]ProbeResult{
		"a.example.org": {OK: true, LatencyMs: 200, Loc: "DE"},
		"b.example.org": {OK: true, LatencyMs: 10, Loc: "NL"},
	}}
	st := &StatsStore{entries: map[string]NodeStat{
		nodeAt("a.example.org").Identity(): {OK: 3, LastOKAt: fresh, RTTAt: fresh, RTTMs: 180},
	}}
	s := NewSelector(SeekConfig{}, p)
	s.Stats = st
	s.SetNodes([]Node{nodeAt("a.example.org"), nodeAt("b.example.org")})
	got, ok := s.Select(context.Background())
	if !ok || got.Host != "a.example.org" {
		t.Fatalf("memory ordering: selected %q ok=%v want a.example.org", got.Host, ok)
	}
	// The pass itself is recorded (b now also has an OK entry).
	if st.Stat(nodeAt("b.example.org").Identity()).LastOKAt <= 0 {
		t.Fatal("current pass not recorded")
	}
}

func TestSelectorWithoutStatsIsLatencyOrdered(t *testing.T) {
	p := fakeProber{byHost: map[string]ProbeResult{
		"a.example.org": {OK: true, LatencyMs: 200, Loc: "DE"},
		"b.example.org": {OK: true, LatencyMs: 10, Loc: "NL"},
	}}
	s := NewSelector(SeekConfig{}, p)
	s.SetNodes([]Node{nodeAt("a.example.org"), nodeAt("b.example.org")})
	got, ok := s.Select(context.Background())
	if !ok || got.Host != "b.example.org" {
		t.Fatalf("latency ordering: selected %q ok=%v want b.example.org", got.Host, ok)
	}
}

func TestSelectorMemoryTTLExpires(t *testing.T) {
	now := time.Now()
	stale := float64(now.Add(-25*time.Hour).UnixNano()) / 1e9
	st := &StatsStore{entries: map[string]NodeStat{
		nodeAt("a.example.org").Identity(): {OK: 5, LastOKAt: stale, RTTAt: stale},
	}}
	s := NewSelector(SeekConfig{}, nil)
	s.Stats = st
	// Stale OK + no failure -> treated as untried (bucket 2), not trusted.
	a := ProbeResult{Node: nodeAt("a.example.org"), OK: true, LatencyMs: 5}
	if b := s.memoryBucket(a, now); b != 2 {
		t.Fatalf("stale evidence bucket=%d want 2", b)
	}
	// A fresh OK outranks it.
	st.entries[nodeAt("b.example.org").Identity()] = NodeStat{OK: 1, LastOKAt: float64(now.Add(-time.Minute).UnixNano()) / 1e9}
	b := ProbeResult{Node: nodeAt("b.example.org"), OK: true, LatencyMs: 300}
	if !s.orderLess(b, a, now) {
		t.Fatal("fresh OK must outrank stale/untried")
	}
}

func TestSelectorOnReadyFiresOnce(t *testing.T) {
	p := fakeProber{byHost: map[string]ProbeResult{
		"a.example.org": {OK: true, LatencyMs: 10, Loc: "DE"},
	}}
	s := NewSelector(SeekConfig{}, p)
	var ready, changes int
	s.OnReady = func(Node) { ready++ }
	s.OnChange = func(Node) { changes++ }
	s.SetNodes([]Node{nodeAt("a.example.org")})
	_, _ = s.Select(context.Background())
	_, _ = s.Select(context.Background())
	if ready != 1 || changes != 0 {
		t.Fatalf("ready=%d changes=%d want 1/0", ready, changes)
	}
}
