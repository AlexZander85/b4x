// MasqueAwgRuntime construction and lifecycle smoke: validation paths and
// the waiting-parent posture without a live parent plane. Full cross-engine
// e2e (fake CONNECT-IP edge relaying to a fake AWG edge) is the follow-up
// sub-stage of E-NM; the engines' own suites cover their halves.
package nested

import (
	"context"
	"testing"
	"time"

	twg "github.com/daniellavrushin/b4/transport/wg"
)

func TestMasqueAwgRuntimeRejectsWrongKinds(t *testing.T) {
	cfg := MasqueAwgConfig{Pair: validPair()}
	cfg.Pair.Outer.Kind = KindAWG // W+W declared, runtime is M+W only
	if _, err := NewMasqueAwgRuntime(cfg); err == nil {
		t.Fatal("awg outer must be rejected by the masque+awg runtime")
	}
}

func TestMasqueAwgRuntimeRequiresPlaneAndIdentity(t *testing.T) {
	cfg := MasqueAwgConfig{Pair: validPair()}
	if _, err := NewMasqueAwgRuntime(cfg); err == nil {
		t.Fatal("missing capsule plane must be rejected")
	}
	cfg.Plane = newFakePlane()
	if _, err := NewMasqueAwgRuntime(cfg); err == nil {
		t.Fatal("missing inner identity must be rejected")
	}
}

func TestMasqueAwgRuntimeWaitingParentAndCleanStop(t *testing.T) {
	plane := newFakePlane()
	setPlaneHeld(plane, false) // the fixture default is held=true; this test pins the waiting-parent posture
	cfg := MasqueAwgConfig{
		Pair:       validPair(),
		Plane:      plane,
		LocalV4:    localV4(),
		InnerIdent: &twg.Identity{},
	}
	rt, err := NewMasqueAwgRuntime(cfg)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	if link, gen, child := rt.Status(); link != "waiting-parent" || gen != 0 || child {
		t.Fatalf("initial status = %s/%d/%v", link, gen, child)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // a few parent-link ticks

	link, _, child := rt.Status()
	if link != "waiting-parent" || child {
		t.Fatalf("no parent held: status drifted to %s/%v", link, child)
	}

	rt.Stop() // idempotent teardown (child-first order internally)
	rt.Stop() // second call must not panic or block
	// The plane fixture needs no teardown; a production Supervisor stays
	// owned by its creator.

	if _, _, child := rt.Status(); child {
		t.Fatal("child must not exist after Stop")
	}
}
