package awgwarpservice

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// fakeSeeker stands in for *twg.Seeker so unit tests never drive a live
// session.
type fakeSeeker struct {
	winner *twg.Winner
	err    error
	calls  int
}

func (f *fakeSeeker) Seek(context.Context) (twg.SeekResult, error) {
	f.calls++
	if f.err != nil {
		return twg.SeekResult{}, f.err
	}
	return twg.SeekResult{Winner: f.winner}, nil
}

func seekTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	c := config.NewConfig()
	c.System.Warp.AWG = config.WarpAWGConfig{
		Enabled:      true,
		IdentityPath: filepath.Join(t.TempDir(), "slot.json"),
	}
	rt, err := Build(&c, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rt.mu.Lock()
	rt.identity = &twg.Identity{AssignedV4: "172.16.0.2"}
	rt.mu.Unlock()
	return rt
}

// TestSeekFallbackAdoptsWinner pins the bd b4x-wh6 pt.2 wiring: the fast path
// is tried first; only after seekAfterTicks failed ticks does ONE bounded
// discovery pass run, and its (endpoint, profile) pair overrides the next
// session build.
func TestSeekFallbackAdoptsWinner(t *testing.T) {
	orig := newSeeker
	defer func() { newSeeker = orig }()

	want := &twg.Winner{Endpoint: netip.MustParseAddrPort("8.39.214.9:500"), Profile: "quic-b"}
	fake := &fakeSeeker{winner: want}
	newSeeker = func(twg.SeekerConfig) (seekerRunner, error) { return fake, nil }

	rt := seekTestRuntime(t)
	for i := 0; i < seekAfterTicks-1; i++ {
		rt.maybeSeek(context.Background())
	}
	if fake.calls != 0 {
		t.Fatalf("seek ran before the failure threshold: %d calls", fake.calls)
	}
	rt.maybeSeek(context.Background())
	if fake.calls != 1 {
		t.Fatalf("seek calls = %d, want 1", fake.calls)
	}
	rt.winnerMu.Lock()
	ep, prof := rt.winnerEP, rt.winnerProfile
	rt.winnerMu.Unlock()
	if ep != want.Endpoint || prof != want.Profile {
		t.Fatalf("adopted (%s, %s), want (%s, %s)", ep, prof, want.Endpoint, want.Profile)
	}
}

// TestSeekFallbackFailSafe: a failed pass (no verified candidate) must adopt
// NOTHING — the fast path stays in place.
func TestSeekFallbackFailSafe(t *testing.T) {
	orig := newSeeker
	defer func() { newSeeker = orig }()
	newSeeker = func(twg.SeekerConfig) (seekerRunner, error) {
		return &fakeSeeker{err: errors.New("transportwg: discovery exhausted")}, nil
	}

	rt := seekTestRuntime(t)
	for i := 0; i < seekAfterTicks+1; i++ {
		rt.maybeSeek(context.Background())
	}
	rt.winnerMu.Lock()
	ep := rt.winnerEP
	rt.winnerMu.Unlock()
	if ep.IsValid() {
		t.Fatalf("failed seek adopted %s", ep)
	}
}
