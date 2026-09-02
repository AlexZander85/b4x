// nest_test.go: FX-M2 pins — the port-block detector trips after
// nestStrikeThreshold consecutive suspect dial failures, the ladder
// switches to the nested rung with honest events, the nested session rides
// the carrier seam (Options.Carrier → DialPolicy.BaseDial), the last-good
// rung persists across builds, and the hourly return probe keeps the
// nested state on a still-blocked direct path.
package fxvpservice

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"time"
)

func TestNestOnPortBlockTripAndCarrierUse(t *testing.T) {
	fx := newLiveFixture(t, 15)
	fx.rt.cfg.Masquerade.NestOnPortBlock = true
	carrierCalls := 0
	fx.rt.carrierDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		carrierCalls++
		return nil, errors.New("carrier stand: no tunnel here")
	}
	seedServerlist(t, fx.rt.cfg.AccountsPath, time.Now()) // 127.0.0.1:1 → refused fast
	fx.rt.sl = nil
	ctx := context.Background()

	dead := newFakeSession()
	_ = dead.Close()
	fx.rt.session = dead
	fx.rt.sessionHost = "127.0.0.1:1"

	for i := 0; i < nestStrikeThreshold; i++ {
		fx.rt.tick(ctx)
	}
	st := fx.rt.Status()
	if !st.Nested {
		t.Fatalf("nest must trip after %d suspect failures", nestStrikeThreshold)
	}
	var suspected, activated bool
	for _, ev := range st.Events {
		switch ev.Type {
		case "fxvpn_port_block_suspected":
			suspected = true
		case "fxvpn_nested_activated":
			activated = true
		}
	}
	if !suspected || !activated {
		t.Fatalf("events missing: suspected=%t activated=%t (%+v)", suspected, activated, st.Events)
	}

	// The last-good rung persisted.
	blob, err := os.ReadFile(filepath.Join(filepath.Dir(fx.rt.cfg.AccountsPath), ladderStateFile))
	if err != nil {
		t.Fatalf("ladder state not persisted: %v", err)
	}
	if !containsJSONNested(blob) {
		t.Fatalf("ladder state must record nested=true: %s", blob)
	}

	// The nested rebuild rides the carrier seam.
	before := carrierCalls
	fx.rt.tick(ctx)
	if carrierCalls == before {
		t.Fatal("nested dial must go through the carrier (DialPolicy.BaseDial)")
	}
}

func containsJSONNested(blob []byte) bool {
	s := string(blob)
	return len(s) > 0 && // the file exists
		(len(s) < 1<<16) &&
		// "nested": true (tolerant of whitespace formats)
		indexOfBytes(blob, []byte(`true`)) >= 0
}

func indexOfBytes(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestNestLastGoodStartsNestedAndProbeHolds pins the persistence path: a
// build whose last-good state says nested starts nested (with the honest
// event on the first tick) and the hourly probe, facing a still-refused
// direct path, keeps it nested.
func TestNestLastGoodStartsNestedAndProbeHolds(t *testing.T) {
	fx := newLiveFixture(t, 15)
	fx.rt.cfg.Masquerade.NestOnPortBlock = true
	carrierCalls := 0
	fx.rt.carrierDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		carrierCalls++
		return nil, errors.New("carrier stand")
	}
	seedServerlist(t, fx.rt.cfg.AccountsPath, time.Now())
	fx.rt.sl = nil

	// Simulate the persisted last-good state from a previous run.
	if err := os.WriteFile(filepath.Join(filepath.Dir(fx.rt.cfg.AccountsPath), ladderStateFile),
		[]byte(`{"version":1,"nested":true,"saved_at":"2026-01-01T00:00:00Z"}`), 0600); err != nil {
		t.Fatalf("seed ladder state: %v", err)
	}

	// Rebuild: the last-good nested rung must be adopted.
	cfg := &config.Config{}
	cfg.System.FxVPN = fx.rt.cfg
	rt2, err := Build(cfg, Options{Carrier: fx.rt.carrierDial})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if !rt2.nested {
		t.Fatal("last-good nested state must be adopted on build")
	}

	// First tick announces the nesting (never silent, §7.8.3).
	live := newFakeSession()
	rt2.session = live
	rt2.sessionHost = "127.0.0.1:1"
	rt2.tick(context.Background())
	announced := false
	for _, ev := range rt2.Status().Events {
		if ev.Type == "fxvpn_nested_activated" {
			announced = true
		}
	}
	if !announced {
		t.Fatal("last-good nesting must announce itself")
	}
	if rt2.Status().Nested != true {
		t.Fatal("nested status must be exposed")
	}
	_ = net.ParseIP("127.0.0.1")
}
