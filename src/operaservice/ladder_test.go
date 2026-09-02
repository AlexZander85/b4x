package operaservice

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	opera "github.com/daniellavrushin/b4/transport/opera"
)

// The ladder uses ONLY confirmed data-plane block classes (review §7.5):
// TLS failures with a live dial. Everything else must not move it.
func tlsFail() error {
	return opera.NewFailure(opera.ClassDataPlaneTLS, "node handshake (uTLS): rst after clienthello", nil)
}

func newTestLadder(t *testing.T, head int, store *LadderStore) (*masqueradeLadder, *opera.MasqueradeBox, *eventRing, *time.Time) {
	t.Helper()
	box := &opera.MasqueradeBox{}
	ring := &eventRing{}
	base := time.Now()
	clk := base
	l := newMasqueradeLadder(box, ring, store, head, nil, false, func() time.Time { return clk })
	return l, box, ring, &clk
}

func TestLadderStartsAtHeadAndHolds(t *testing.T) {
	l, box, _, _ := newTestLadder(t, 0, nil)
	if got := box.Get().Fingerprint; got != opera.FingerprintChrome120 {
		t.Fatalf("head rung fingerprint = %q, want chrome120", got)
	}
	if got := box.Get().SNIMode; got != opera.SNIModeNode {
		t.Fatalf("head rung sni = %q, want node", got)
	}
	// Unrelated failures never move the ladder.
	for i := 0; i < 10; i++ {
		l.ObserveDial(false, errors.New("dial tcp: timeout"))
	}
	if box.Get().Fingerprint == opera.FingerprintNone {
		t.Fatal("unrelated failure moved the ladder")
	}
}

func TestLadderStepsDownOnConfirmedBlocks(t *testing.T) {
	l, box, _, _ := newTestLadder(t, 0, nil)
	// FailureLimit(3) consecutive TLS failures -> one rung down.
	for i := 0; i < 3; i++ {
		l.ObserveDial(false, tlsFail())
	}
	if got := box.Get().SNIMode; got != opera.SNIModePool {
		t.Fatalf("after 3 TLS fails sni = %q, want pool (rung 1)", got)
	}
	// Burn to the bottom rung.
	for i := 0; i < 3*(len(masqueradeLadderRungs)-1); i++ {
		l.ObserveDial(false, tlsFail())
	}
	if got := box.Get().Fingerprint; got != opera.FingerprintNone {
		t.Fatalf("bottom rung fingerprint = %q, want none", got)
	}
	if got := box.Get().SNIMode; got != opera.SNIModeNone {
		t.Fatalf("bottom rung sni = %q, want none", got)
	}
}

func TestLadderStepUpNeedsCooldownAndStreak(t *testing.T) {
	l, box, _, clk := newTestLadder(t, 0, nil)
	// Step down once.
	for i := 0; i < 3; i++ {
		l.ObserveDial(false, tlsFail())
	}
	if box.Get().SNIMode != opera.SNIModePool {
		t.Fatalf("expected rung 1, sni=%q", box.Get().SNIMode)
	}

	// Cooldown not elapsed: quiet streak alone must NOT step up.
	for i := 0; i < LadderQuietStreak+1; i++ {
		l.ObserveDial(true, nil)
	}
	if box.Get().SNIMode != opera.SNIModePool {
		t.Fatal("stepped up inside the cooldown (anti-oscillation broken)")
	}

	// Elapsed + streak: one rung up per episode.
	*clk = clk.Add(LadderCooldown + time.Second)
	l.ObserveDial(true, nil)
	if box.Get().SNIMode != opera.SNIModeNode {
		t.Fatalf("expected step up to node SNI, got %q", box.Get().SNIMode)
	}
}

func TestLadderRespectsConfigCeiling(t *testing.T) {
	// minimal profile: the ceiling is rung 3 — the ladder must never
	// re-enable the uTLS layer the owner turned off.
	l, box, _, clk := newTestLadder(t, 3, nil)
	if got := box.Get().Fingerprint; got != opera.FingerprintNone {
		t.Fatalf("minimal ceiling fingerprint = %q, want none", got)
	}
	for i := 0; i < 6; i++ {
		l.ObserveDial(false, tlsFail())
	}
	*clk = clk.Add(LadderCooldown + time.Second)
	for i := 0; i < LadderQuietStreak+1; i++ {
		l.ObserveDial(true, nil)
	}
	if got := box.Get().Fingerprint; got != opera.FingerprintNone {
		t.Fatal("stepped above the configured ceiling")
	}
}

func TestLadderLastGoodPersistsAndRestores(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ladder.json")
	store := &LadderStore{Path: path}
	l, _, _, _ := newTestLadder(t, 0, store)
	for i := 0; i < 3; i++ {
		l.ObserveDial(false, tlsFail())
	}
	name, ok := store.Get()
	if !ok || name != "browser+pool-sni" {
		t.Fatalf("last-good = %q (%v), want browser+pool-sni", name, ok)
	}

	// A fresh ladder (simulated reboot) resumes the field-proven rung.
	box2 := &opera.MasqueradeBox{}
	_ = newMasqueradeLadder(box2, nil, store, 0, nil, false, nil)
	if got := box2.Get().SNIMode; got != opera.SNIModePool {
		t.Fatalf("restored sni = %q, want pool", got)
	}
}

func TestLadderSwitchesAreObservable(t *testing.T) {
	l, _, ring, _ := newTestLadder(t, 0, nil)
	for i := 0; i < 3; i++ {
		l.ObserveDial(false, tlsFail())
	}
	events := ring.snapshot()
	found := false
	for _, ev := range events {
		if ev.Name == EventMasqueradeSwitched {
			found = true
		}
	}
	if !found {
		t.Fatal("switch event missing from the ring (silent fallback)")
	}
}

// Build-level: the ladder is wired for browser/minimal and absent for off.
func TestBuildLadderWiring(t *testing.T) {
	cfg := &config.Config{}
	rt, err := Build(cfg, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rt.ladder == nil {
		t.Fatal("ladder missing for the browser profile")
	}

	cfg2 := &config.Config{}
	cfg2.System.Opera.Masquerade.Profile = "off"
	rt2, err := Build(cfg2, Options{})
	if err != nil {
		t.Fatalf("Build off: %v", err)
	}
	if rt2.ladder != nil {
		t.Fatal("ladder must not run when the masquerade is off")
	}
	if rt2.client.CurrentMasquerade().Fingerprint != opera.FingerprintNone {
		t.Fatal("off profile kept the uTLS layer")
	}
}
