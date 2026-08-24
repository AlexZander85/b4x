// MasqueAwgRuntime construction and lifecycle smoke: validation paths and
// the waiting-parent posture without a live parent plane. Full cross-engine
// e2e (fake CONNECT-IP edge relaying to a fake AWG edge) is the follow-up
// sub-stage of E-NM; the engines' own suites cover their halves.
package nested

import (
	"context"
	"testing"
	"time"

	twarp "github.com/daniellavrushin/b4/transport/warp"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

func testSupervisor(t *testing.T) *twarp.Supervisor {
	t.Helper()
	sup, err := twarp.NewSupervisor(twarp.SupervisorConfig{
		Reconciler: &twarp.Reconciler{},
	})
	if err != nil {
		t.Fatalf("supervisor: %v", err)
	}
	return sup
}

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
		t.Fatal("missing supervisor must be rejected")
	}
	cfg.Supervisor = testSupervisor(t)
	if _, err := NewMasqueAwgRuntime(cfg); err == nil {
		t.Fatal("missing inner identity must be rejected")
	}
}

func TestMasqueAwgRuntimeWaitingParentAndCleanStop(t *testing.T) {
	sup := testSupervisor(t)
	cfg := MasqueAwgConfig{
		Pair:       validPair(),
		Supervisor: sup,
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
	// sup is intentionally never Stop()ed here: Supervisor.Stop blocks until
	// its loop exits, and this test never Start()ed it.

	if _, _, child := rt.Status(); child {
		t.Fatal("child must not exist after Stop")
	}
}
