package vless

import (
	"context"
	"testing"
	"time"
)

// fakeProber scripts probe verdicts by node host.
type fakeProber struct {
	byHost map[string]ProbeResult
}

func (f fakeProber) Probe(_ context.Context, n Node) ProbeResult {
	r, ok := f.byHost[n.Host]
	if !ok {
		return ProbeResult{Node: n, Err: "no script"}
	}
	r.Node = n
	return r
}

func nodeAt(host string) Node {
	return Node{UUID: "u", Host: host, Port: 443, Security: SecurityTLS, SNI: "www.microsoft.com", Transport: TransportTCP}
}

func TestParseTraceSelectorPrefersNonRU(t *testing.T) {
	p := fakeProber{byHost: map[string]ProbeResult{
		"ru.example.org": {OK: true, LatencyMs: 10, Loc: "RU"},
		"de.example.org": {OK: true, LatencyMs: 40, Loc: "DE"},
	}}
	s := NewSelector(SeekConfig{PreferNonRU: true}, p)
	s.SetNodes([]Node{nodeAt("ru.example.org"), nodeAt("de.example.org")})
	got, ok := s.Select(context.Background())
	if !ok || got.Host != "de.example.org" {
		t.Fatalf("selected %q ok=%v want de.example.org", got.Host, ok)
	}
}

func TestSelectorToleranceKeepsActive(t *testing.T) {
	p := fakeProber{byHost: map[string]ProbeResult{
		"a.example.org": {OK: true, LatencyMs: 30, Loc: "DE"},
		"b.example.org": {OK: true, LatencyMs: 20, Loc: "NL"},
	}}
	// First pass sees only A.
	s := NewSelector(SeekConfig{Tolerance: 15 * time.Millisecond}, p)
	s.SetNodes([]Node{nodeAt("a.example.org")})
	if _, ok := s.Select(context.Background()); !ok {
		t.Fatal("first select failed")
	}
	// B is faster but within tolerance of A -> keep A.
	s.SetNodes([]Node{nodeAt("a.example.org"), nodeAt("b.example.org")})
	got, _ := s.Select(context.Background())
	if got.Host != "a.example.org" {
		t.Fatalf("tolerance: selected %q want a.example.org", got.Host)
	}
	// Zero tolerance -> switch to the faster B.
	s.cfg.Tolerance = 0
	got, _ = s.Select(context.Background())
	if got.Host != "b.example.org" {
		t.Fatalf("no tolerance: selected %q want b.example.org", got.Host)
	}
}

func TestSelectorDenyAndNoCandidates(t *testing.T) {
	p := fakeProber{byHost: map[string]ProbeResult{
		"ru.example.org":  {OK: true, LatencyMs: 5, Loc: "RU"},
		"de.example.org":  {OK: true, LatencyMs: 50, Loc: "DE"},
		"bad.example.org": {Err: "dial timeout"},
	}}
	s := NewSelector(SeekConfig{CountryDeny: []string{"RU"}}, p)
	s.SetNodes([]Node{nodeAt("ru.example.org"), nodeAt("de.example.org"), nodeAt("bad.example.org")})
	got, ok := s.Select(context.Background())
	if !ok || got.Host != "de.example.org" {
		t.Fatalf("deny: selected %q ok=%v want de.example.org", got.Host, ok)
	}
	// prefer_nonru with only RU candidates -> nothing acceptable.
	s2 := NewSelector(SeekConfig{PreferNonRU: true}, p)
	s2.SetNodes([]Node{nodeAt("ru.example.org")})
	if _, ok := s2.Select(context.Background()); ok {
		t.Fatal("expected no acceptable candidate")
	}
}

func TestSelectorPin(t *testing.T) {
	p := fakeProber{byHost: map[string]ProbeResult{
		"a.example.org": {OK: true, LatencyMs: 10, Loc: "DE"},
		"b.example.org": {OK: true, LatencyMs: 20, Loc: "NL"},
	}}
	s := NewSelector(SeekConfig{Pin: "b.example.org:443"}, p)
	s.SetNodes([]Node{nodeAt("a.example.org"), nodeAt("b.example.org")})
	got, ok := s.Select(context.Background())
	if !ok || got.Host != "b.example.org" {
		t.Fatalf("pin: selected %q ok=%v want b.example.org", got.Host, ok)
	}
	// A pin that matches nothing yields no candidate.
	s2 := NewSelector(SeekConfig{Pin: "missing.example.org:443"}, p)
	s2.SetNodes([]Node{nodeAt("a.example.org")})
	if _, ok := s2.Select(context.Background()); ok {
		t.Fatal("missing pin must yield no candidate")
	}
}

func TestSelectorOnChange(t *testing.T) {
	p := fakeProber{byHost: map[string]ProbeResult{
		"a.example.org": {OK: true, LatencyMs: 30, Loc: "DE"},
		"b.example.org": {OK: true, LatencyMs: 10, Loc: "NL"},
	}}
	s := NewSelector(SeekConfig{}, p)
	var changed []string
	s.OnChange = func(n Node) { changed = append(changed, n.Host) }
	s.SetNodes([]Node{nodeAt("a.example.org")})
	_, _ = s.Select(context.Background()) // first pick: no change callback
	s.SetNodes([]Node{nodeAt("a.example.org"), nodeAt("b.example.org")})
	_, _ = s.Select(context.Background())
	if len(changed) != 1 || changed[0] != "b.example.org" {
		t.Fatalf("OnChange = %v want [b.example.org]", changed)
	}
}
