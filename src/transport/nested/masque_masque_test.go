// MasqueMasqueRuntime construction and lifecycle tests: validation paths,
// the waiting-parent posture and the parent-link contract (child rebuild on
// rising edges, immediate invalidation on the falling edge, bounded retry
// ladder while the parent stays up). The child start is exercised through
// the startChildFn seam — no wire, no enrollment, the run-loop discipline
// is what is pinned here.
package nested

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	twarp "github.com/daniellavrushin/b4/transport/warp"
)

func validMMPair() PairConfig {
	return PairConfig{
		Outer: LayerSpec{
			Kind: KindMasqueH2, IdentitySlot: SlotPrimary,
			ProfileID: "cf-warp/vanilla-off", Endpoint: netip.MustParseAddrPort("162.159.192.1:443"),
		},
		Inner: LayerSpec{
			Kind: KindMasqueH2, IdentitySlot: SlotSecondary,
			ProfileID: "cf-warp/vanilla-off", Endpoint: netip.MustParseAddrPort("162.159.198.1:443"),
		},
	}
}

func mmConfig(t *testing.T) MasqueMasqueConfig {
	t.Helper()
	return MasqueMasqueConfig{
		Pair:          validMMPair(),
		Plane:         newFakePlane(),
		LocalV4:       localV4(),
		InnerEnroll:   &twarp.EnrollClient{},
		InnerSlotPath: t.TempDir() + "/secondary.json",
	}
}

func TestMasqueMasqueValidateTable(t *testing.T) {
	c0 := mmConfig(t)
	if err := c0.Validate(); err != nil {
		t.Fatalf("happy config rejected: %v", err)
	}

	awgOuter := mmConfig(t)
	awgOuter.Pair.Outer.Kind = KindAWG // the runtime is M+M only
	if err := awgOuter.Validate(); err == nil {
		t.Fatal("awg outer must be rejected by the masque+masque runtime")
	}

	awgInner := mmConfig(t)
	awgInner.Pair.Inner.Kind = KindAWG
	if err := awgInner.Validate(); err == nil {
		t.Fatal("awg inner must be rejected by the masque+masque runtime")
	}

	noPlane := mmConfig(t)
	noPlane.Plane = nil
	if err := noPlane.Validate(); err == nil {
		t.Fatal("missing capsule plane must be rejected")
	}

	noEnroll := mmConfig(t)
	noEnroll.InnerEnroll = nil
	if err := noEnroll.Validate(); err == nil {
		t.Fatal("missing secondary slot enrollment must be rejected (red line #3)")
	}

	noPath := mmConfig(t)
	noPath.InnerSlotPath = ""
	if err := noPath.Validate(); err == nil {
		t.Fatal("missing secondary store path must be rejected")
	}

	badFp := mmConfig(t)
	badFp.Fingerprint = "safari17"
	if err := badFp.Validate(); err == nil {
		t.Fatal("unknown fingerprint must be rejected")
	}

	edgeCollision := mmConfig(t)
	edgeCollision.Pair.Inner.Endpoint = edgeCollision.Pair.Outer.Endpoint
	if err := edgeCollision.Validate(); err == nil {
		t.Fatal("colliding layer edges must be rejected (gool hard rule)")
	}
}

func TestMasqueMasqueRuntimeConstruction(t *testing.T) {
	cfg := MasqueMasqueConfig{Pair: validMMPair()}
	if _, err := NewMasqueMasqueRuntime(cfg); err == nil {
		t.Fatal("missing plane/enrollment must be rejected at construction")
	}

	rt, err := NewMasqueMasqueRuntime(mmConfig(t))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if link, gen, child := rt.Status(); link != "waiting-parent" || gen != 0 || child {
		t.Fatalf("fresh runtime posture: link=%q gen=%d child=%v", link, gen, child)
	}
	if rt.InnerSupervisor() != nil {
		t.Fatal("no inner supervisor may exist before the parent holds")
	}
	st := rt.StatusDetailed()
	if st.Outer.HandshakeMS != neverEstablished || st.Inner.HandshakeMS != neverEstablished {
		t.Fatalf("unwitnessed handshakes must read neverEstablished, got %+v", st)
	}

	// Start-after-Stop is the structural refusal.
	rt.Stop()
	if err := rt.Start(context.Background()); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("start after stop must refuse with ErrRuntimeStopped, got %v", err)
	}
}

func TestMasqueMasqueParentLinkContract(t *testing.T) {
	plane := newFakePlane()
	setPlaneHeld(plane, false)

	var mu sync.Mutex
	var starts int
	startErr := errors.New("inner enrollment unreachable")

	var events []Event
	cfg := mmConfig(t)
	cfg.Plane = plane
	cfg.PollInterval = time.Millisecond
	cfg.OnEvent = func(ev Event) { mu.Lock(); events = append(events, ev); mu.Unlock() }

	rt, err := NewMasqueMasqueRuntime(cfg)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	// Test seams: fast retry ladder + an injectable child starter.
	rt.retryBase = time.Millisecond
	rt.retryCap = 2 * time.Millisecond
	rt.startChildFn = func(gen uint64) error {
		mu.Lock()
		starts++
		mu.Unlock()
		return startErr
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Waiting parent: nothing starts while the plane is down.
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	if starts != 0 {
		mu.Unlock()
		t.Fatalf("no child start may happen while the parent is down, got %d", starts)
	}
	mu.Unlock()

	// Parent rises: the retry ladder runs while the child keeps failing.
	setPlaneHeld(plane, true)
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		s := starts
		mu.Unlock()
		if s >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retry ladder never fired (starts=%d)", s)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if link, _, child := rt.Status(); link != "child-invalidated" || child {
		t.Fatalf("failed child must read child-invalidated, got link=%q child=%v", link, child)
	}

	// Parent falls: the child (already down) stays invalidated; the
	// controller keeps running (no goroutine leak into Start's done).
	setPlaneHeld(plane, false)
	time.Sleep(30 * time.Millisecond)

	// Parent rises again: the flap reset the ladder — at least one more start.
	setPlaneHeld(plane, true)
	deadline = time.Now().Add(2 * time.Second)
	mu.Lock()
	before := starts
	mu.Unlock()
	for {
		mu.Lock()
		s := starts
		mu.Unlock()
		if s > before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("post-flap restart never fired (%d -> %d)", before, s)
		}
		time.Sleep(2 * time.Millisecond)
	}

	rt.Stop()
	// Stop is idempotent; the runtime refuses a second Start afterwards.
	rt.Stop()
	if err := rt.Start(ctx); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("post-stop start must refuse, got %v", err)
	}

	// The failure taxonomy reached the event surface: a CHILD START failure
	// is a child-lifecycle outcome (M-14), while the parent's loss keeps the
	// warp_masque_disconnected class (the M+W canon — it is the parent
	// plane's route incident, not the child's).
	mu.Lock()
	defer mu.Unlock()
	sawChildStartFailed := false
	sawParentLost := false
	for _, ev := range events {
		if ev.Class == ClassChildStartFailed {
			sawChildStartFailed = true
		}
		if ev.Class == "warp_masque_disconnected" && ev.Reason == "parent lost: child invalidated" {
			sawParentLost = true
		}
	}
	if !sawChildStartFailed {
		t.Fatal("ClassChildStartFailed never reached the event sink")
	}
	if !sawParentLost {
		t.Fatal("parent loss must surface warp_masque_disconnected (the M+W canon)")
	}
}
