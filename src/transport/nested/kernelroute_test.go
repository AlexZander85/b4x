package nested

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRoutes simulates an iproute2 table for the ownership tests.
type fakeRoutes struct {
	mu          sync.Mutex
	lines       map[string]string // "fam|dst" -> effective line
	showPre     map[string]string // pre-existing foreign route per dst
	failAdd     map[string]bool   // PATCH-14: simulate add conflicts (EEXIST-like)
	failReplace map[string]bool
	failGet     map[string]bool
	failShow    map[string]bool // PATCH-06/E5: transient route-show failure
	calls       []string
}

func newFakeRoutes() *fakeRoutes {
	return &fakeRoutes{
		lines:       map[string]string{},
		showPre:     map[string]string{},
		failAdd:     map[string]bool{},
		failReplace: map[string]bool{},
		failGet:     map[string]bool{},
		failShow:    map[string]bool{},
	}
}

func key(fam, dst string) string { return fam + "|" + dst }

func (f *fakeRoutes) run(_ context.Context, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args, " "))
	if len(args) < 2 {
		return "", errors.New("bad args")
	}
	fam := args[0]
	rest := args[1:]
	switch {
	case rest[0] == "route" && rest[1] == "show":
		dst := rest[2]
		if f.failShow[dst] {
			return "", fmt.Errorf("ip route show %s: cache mispopulate (transient)", dst)
		}
		if line := f.lines[key(fam, dst)]; line != "" {
			return line + "\n", nil
		}
		return f.showPre[dst] + "\n", nil
	case rest[0] == "route" && rest[1] == "add":
		dst := strings.TrimSuffix(strings.TrimSuffix(rest[2], "/128"), "/32")
		if f.failAdd[dst] {
			return "", fmt.Errorf("ip route add %s: RTNETLINK answers: File exists", dst)
		}
		dev := "unknown"
		for i, a := range rest {
			if a == "dev" && i+1 < len(rest) {
				dev = rest[i+1]
			}
		}
		f.lines[key(fam, dst)] = fmt.Sprintf("%s dev %s", dst, dev)
		return "", nil
	case rest[0] == "route" && rest[1] == "replace":
		dst := strings.TrimSuffix(strings.TrimSuffix(rest[2], "/128"), "/32")
		if f.failReplace[dst] {
			return "", fmt.Errorf("ip route replace %s: RTNETLINK answers: Permission denied", dst)
		}
		dev := "unknown"
		for i, a := range rest {
			if a == "dev" && i+1 < len(rest) {
				dev = rest[i+1]
			}
		}
		f.lines[key(fam, dst)] = fmt.Sprintf("%s dev %s", dst, dev)
		return "", nil
	case rest[0] == "route" && rest[1] == "get":
		dst := rest[2]
		if f.failGet[dst] {
			return "", fmt.Errorf("ip route get %s: lookup failed", dst)
		}
		if line := f.lines[key(fam, dst)]; line != "" {
			return fmt.Sprintf("%s via 10.9.9.1 dev %s src 10.9.9.9\n", dst, deviceOf(line)), nil
		}
		return fmt.Sprintf("%s via 10.8.8.1 dev wan0\n", dst), nil
	case rest[0] == "route" && rest[1] == "del":
		dst := strings.TrimSuffix(strings.TrimSuffix(rest[2], "/128"), "/32")
		delete(f.lines, key(fam, dst))
		return "", nil
	default:
		return "", fmt.Errorf("fake: unsupported command %v", rest)
	}
}

func deviceOf(line string) string {
	for i, tok := range strings.Fields(line) {
		if tok == "dev" && i+1 < len(strings.Fields(line)) {
			return strings.Fields(line)[i+1]
		}
	}
	return "?"
}

func (f *fakeRoutes) has(fam, dst, dev string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := f.lines[key(fam, dst)]
	return strings.Contains(line, "dev "+dev)
}

// count counts recorded runner calls containing substr (PATCH-07).
func (f *fakeRoutes) count(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, cl := range f.calls {
		if strings.Contains(cl, substr) {
			n++
		}
	}
	return n
}

func ep4() netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{9, 9, 9, 9}), 51820)
}

func testCarrier(t *testing.T, fr *fakeRoutes, mutate func(*KernelRouteCarrierConfig)) *KernelRouteCarrier {
	t.Helper()
	cfg := KernelRouteCarrierConfig{
		Endpoint: ep4(),
		Device:   "wgout",
		Runner:   fr.run,
		Policy:   FamilyPolicy{RequireV4: true},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewKernelRouteCarrier(cfg)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	return c
}

func TestKernelSetupPinsAndProves(t *testing.T) {
	fr := newFakeRoutes()
	c := testCarrier(t, fr, nil)
	defer c.Close()

	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	proof, ok := c.ProofSnapshot()
	if !ok || !strings.Contains(proof, "9.9.9.9@wgout") {
		t.Fatalf("proof = %q ok=%v, want pinned evidence", proof, ok)
	}
	if !fr.has("-4", "9.9.9.9", "wgout") {
		t.Fatal("table lacks the owned pin")
	}
}

func TestKernelSetupIdempotentNoDoublePin(t *testing.T) {
	fr := newFakeRoutes()
	c := testCarrier(t, fr, nil)
	defer c.Close()

	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("setup1: %v", err)
	}
	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("setup2: %v", err)
	}
	// PATCH-14: a fresh pin is one `route add`; no replace, no del.
	fr.mu.Lock()
	adds, replaces, dels := 0, 0, 0
	for _, cl := range fr.calls {
		switch {
		case strings.Contains(cl, "route add"):
			adds++
		case strings.Contains(cl, "route replace"):
			replaces++
		case strings.Contains(cl, "route del"):
			dels++
		}
	}
	fr.mu.Unlock()
	if adds != 1 || replaces != 0 || dels != 0 {
		t.Fatalf("pin calls = add:%d replace:%d del:%d, want 1/0/0 (B-N1)", adds, replaces, dels)
	}
	if n := len(c.ownedList()); n != 1 {
		t.Fatalf("owned entries = %d, want 1", n)
	}
}

func TestKernelSetupRollbackOnVerifyFailure(t *testing.T) {
	fr := newFakeRoutes()
	fr.showPre["9.9.9.9"] = "9.9.9.9 via 10.1.1.1 dev wan0"
	fr.failGet["9.9.9.9"] = true
	c := testCarrier(t, fr, nil)
	defer c.Close()

	err := c.Setup(context.Background())
	if err == nil {
		t.Fatal("setup unexpectedly succeeded despite failing verification")
	}
	// Rollback must restore the FOREIGN previous route verbatim.
	fr.mu.Lock()
	found := false
	for _, cl := range fr.calls {
		if strings.Contains(cl, "route replace 9.9.9.9 via 10.1.1.1 dev wan0") {
			found = true
		}
	}
	fr.mu.Unlock()
	if !found {
		t.Fatal("previous foreign route was not restored verbatim")
	}
}

func TestKernelAssertRepairsWipedPinAndEmitsRestored(t *testing.T) {
	fr := newFakeRoutes()
	var evs []Event
	c := testCarrier(t, fr, func(cc *KernelRouteCarrierConfig) {
		cc.OnEvent = func(ev Event) { evs = append(evs, ev) }
	})
	defer c.Close()

	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Outer recreate wipes the pin (the documented zapret-gui gap).
	fr.mu.Lock()
	delete(fr.lines, key("-4", "9.9.9.9"))
	fr.mu.Unlock()

	if err := c.Assert(context.Background()); err != nil {
		t.Fatalf("assert after wipe: %v", err)
	}
	if !fr.has("-4", "9.9.9.9", "wgout") {
		t.Fatal("pin was not repaired by Assert")
	}
	restored := false
	for _, ev := range evs {
		if ev.Class == ClassPinRestored {
			restored = true
		}
	}
	if !restored {
		t.Fatal("missing nested/pin-restored event")
	}
}

func TestKernelAssertionLoopRepairsAutomatically(t *testing.T) {
	fr := newFakeRoutes()
	evc := make(chan Event, 16)
	c := testCarrier(t, fr, func(cc *KernelRouteCarrierConfig) {
		cc.OnEvent = func(ev Event) { evc <- ev }
	})
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Setup(ctx); err != nil {
		t.Fatalf("setup: %v", err)
	}
	c.RunAssertionLoop(ctx, 15*time.Millisecond)

	fr.mu.Lock()
	delete(fr.lines, key("-4", "9.9.9.9"))
	fr.mu.Unlock()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-evc:
			if ev.Class == ClassPinRestored {
				return // the tick fixed what zapret-gui left broken
			}
		case <-deadline:
			t.Fatal("no pin-restored event within deadline")
		}
	}
}

func TestKernelDialTCPFailClosedThenAllowed(t *testing.T) {
	fr := newFakeRoutes()
	c := testCarrier(t, fr, nil)
	defer c.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listen unavailable: %v", err)
	}
	defer func() { _ = ln.Close() }()
	dst := netip.MustParseAddrPort(ln.Addr().String())

	if _, err := c.DialTCPThrough(context.Background(), dst); !errors.Is(err, ErrCarrierUnproven) {
		t.Fatalf("unproven dial err = %v, want ErrCarrierUnproven", err)
	}
	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	conn, err := c.DialTCPThrough(context.Background(), dst)
	if err != nil {
		t.Fatalf("proven dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	acceptC := make(chan net.Conn, 1)
	go func() {
		ac, aerr := ln.Accept()
		if aerr == nil {
			acceptC <- ac
		}
	}()
	select {
	case ac := <-acceptC:
		_ = ac.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("carrier dial did not reach the listener")
	}
}

func TestKernelV6WarnOnlyPolicy(t *testing.T) {
	fr := newFakeRoutes()
	v6ep := netip.AddrPortFrom(
		netip.AddrFrom16([16]byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), 51820)
	c := testCarrier(t, fr, func(cc *KernelRouteCarrierConfig) {
		cc.Endpoint = v6ep
		cc.Policy = FamilyPolicy{RequireV4: false}
	})
	defer c.Close()

	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("v6-only setup with RequireV4=false: %v", err)
	}
	if _, ok := c.ProofSnapshot(); !ok {
		t.Fatal("expected proven state for warn-only family posture")
	}
}

func TestKernelRestoreDeletesOwnedPinOnly(t *testing.T) {
	fr := newFakeRoutes()
	c := testCarrier(t, fr, nil)

	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	c.Restore(context.Background())
	if fr.has("-4", "9.9.9.9", "wgout") {
		t.Fatal("owned pin survived Restore")
	}
	if _, ok := c.ProofSnapshot(); ok {
		t.Fatal("proof must be false after Restore")
	}
}

// ---- PATCH-14 (M-1): B-N1 pin discipline — add first, replace fallback ----

func TestPinFamilyAddFirstDiscipline(t *testing.T) {
	t.Run("clean-pin-is-single-add", func(t *testing.T) {
		fr := newFakeRoutes()
		c := testCarrier(t, fr, nil)
		defer c.Close()
		if err := c.Setup(context.Background()); err != nil {
			t.Fatalf("setup: %v", err)
		}
		fr.mu.Lock()
		var adds, replaces, dels int
		for _, cl := range fr.calls {
			switch {
			case strings.Contains(cl, "route add"):
				adds++
			case strings.Contains(cl, "route replace"):
				replaces++
			case strings.Contains(cl, "route del"):
				dels++
			}
		}
		fr.mu.Unlock()
		if adds != 1 || replaces != 0 || dels != 0 {
			t.Fatalf("clean pin = add:%d replace:%d del:%d, want 1/0/0", adds, replaces, dels)
		}
	})

	t.Run("conflict-falls-back-to-single-replace", func(t *testing.T) {
		fr := newFakeRoutes()
		ep := ep4()
		fr.failAdd[ep.Addr().String()] = true
		c := testCarrier(t, fr, nil)
		defer c.Close()
		if err := c.Setup(context.Background()); err != nil {
			t.Fatalf("setup with add conflict: %v", err)
		}
		fr.mu.Lock()
		var adds, replaces, dels int
		for _, cl := range fr.calls {
			switch {
			case strings.Contains(cl, "route add"):
				adds++
			case strings.Contains(cl, "route replace"):
				replaces++
			case strings.Contains(cl, "route del"):
				dels++
			}
		}
		fr.mu.Unlock()
		if adds != 1 || replaces != 1 || dels != 0 {
			t.Fatalf("conflict pin = add:%d replace:%d del:%d, want 1/1/0", adds, replaces, dels)
		}
		if !fr.has("-4", ep.Addr().String(), "wgout") {
			t.Fatal("conflict fallback did not land the pin")
		}
	})

	t.Run("both-fail-pin-errors", func(t *testing.T) {
		fr := newFakeRoutes()
		ep := ep4()
		dst := ep.Addr().String()
		fr.failAdd[dst] = true
		fr.failReplace[dst] = true
		c := testCarrier(t, fr, nil)
		defer c.Close()
		if err := c.Setup(context.Background()); err == nil {
			t.Fatal("setup must fail when add and replace both fail")
		}
		fr.mu.Lock()
		for _, cl := range fr.calls {
			if strings.Contains(cl, "route del") {
				fr.mu.Unlock()
				t.Fatalf("pinFamily must never del (del only in Restore/self-clean): %q", cl)
			}
		}
		fr.mu.Unlock()
	})
}

// ---- PATCH-06: kernel-route teardown package (E1/E5/E6/E7/E8) ----

func TestKernelRestoreWithCoveringPrevDeletesPin(t *testing.T) {
	fr := newFakeRoutes()
	// The MOST COMMON field case: the snapshotted prev is a COVERING route
	// (default), not the exact /32. Old behavior: replace("default ...")
	// succeeded and `continue` skipped our-pin deletion — the /32 pin leaked
	// past full teardown (red before, green after PATCH-06/E1).
	fr.showPre["9.9.9.9"] = "default via 10.1.1.1 dev wan0"
	c := testCarrier(t, fr, nil)

	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if !fr.has("-4", "9.9.9.9", "wgout") {
		t.Fatal("precondition: pin not set")
	}
	c.Restore(context.Background())

	if fr.has("-4", "9.9.9.9", "wgout") {
		t.Fatal("E1: owned /32 pin survived Restore with a covering prev")
	}
	fr.mu.Lock()
	defaultTouched := false
	for _, cl := range fr.calls {
		if strings.Contains(cl, "route replace default") {
			defaultTouched = true
		}
	}
	fr.mu.Unlock()
	if defaultTouched {
		t.Fatal("covering default route must never be re-issued by Restore")
	}
}

func TestKernelRestoreWithExactForeignPrefixRestoresVerbatim(t *testing.T) {
	fr := newFakeRoutes()
	fr.showPre["9.9.9.9"] = "9.9.9.9 via 10.1.1.1 dev wan0"
	c := testCarrier(t, fr, nil)

	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	c.Restore(context.Background())

	// Our pin is gone AND the displaced foreign /32 is back verbatim.
	if fr.has("-4", "9.9.9.9", "wgout") {
		t.Fatal("owned pin survived Restore")
	}
	if !fr.has("-4", "9.9.9.9", "wan0") {
		t.Fatal("exact-prefix foreign route was not restored verbatim")
	}
}

func TestKernelRestoreMultiLinePrevIsSafe(t *testing.T) {
	fr := newFakeRoutes()
	fr.showPre["9.9.9.9"] = "9.9.9.9 via 10.1.1.1 dev wan0\ndefault via 10.1.1.1 dev wan0\nblob  garbage line"
	c := testCarrier(t, fr, nil)

	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	c.Restore(context.Background()) // must not panic; pin must be gone
	if fr.has("-4", "9.9.9.9", "wgout") {
		t.Fatal("owned pin survived Restore with multi-line prev")
	}
}

func TestKernelSetupFailsClosedWhenShowFails(t *testing.T) {
	fr := newFakeRoutes()
	fr.failShow["9.9.9.9"] = true
	c := testCarrier(t, fr, nil)
	defer c.Close()

	err := c.Setup(context.Background())
	if err == nil {
		t.Fatal("E5: setup must fail closed when route show fails (no prev snapshot => no pin)")
	}
	fr.mu.Lock()
	defer fr.mu.Unlock()
	for _, cl := range fr.calls {
		if strings.Contains(cl, "route add") || strings.Contains(cl, "route replace") {
			t.Fatalf("no mutation may follow a failed show snapshot: %q", cl)
		}
	}
}

// TestKernelFallbackBothFailForeignRouteIntact pins the E6 invariant under
// the B-N1 add-first ladder: when BOTH add and replace fail, no del was ever
// issued, so the foreign route must remain untouched (nothing lost, nothing
// to restore). This is the structural replacement for the plan's
// del->replace fallback restore, which no longer exists in this ladder.
func TestKernelFallbackBothFailForeignRouteIntact(t *testing.T) {
	fr := newFakeRoutes()
	dst := ep4().Addr().String()
	fr.showPre[dst] = dst + " via 10.7.7.1 dev wan0"
	fr.failAdd[dst] = true
	fr.failReplace[dst] = true
	c := testCarrier(t, fr, nil)
	defer c.Close()

	if err := c.Setup(context.Background()); err == nil {
		t.Fatal("setup must fail when both add and replace fail")
	}
	fr.mu.Lock()
	defer fr.mu.Unlock()
	for _, cl := range fr.calls {
		if strings.Contains(cl, "route del") {
			t.Fatalf("both-fail path must never del (foreign route could be orphaned): %q", cl)
		}
	}
	if len(fr.lines) != 0 {
		t.Fatalf("foreign table polluted by failed pin: %v", fr.lines)
	}
}

// TestKernelFallbackLandsThenRollbackRestoresForeign covers the mixed path:
// add conflicts, replace lands, verify fails => self-clean del + verbatim
// restore of the displaced foreign /32.
func TestKernelFallbackLandsThenRollbackRestoresForeign(t *testing.T) {
	fr := newFakeRoutes()
	dst := ep4().Addr().String()
	fr.showPre[dst] = dst + " via 10.7.7.1 dev wan0"
	fr.failAdd[dst] = true
	fr.failGet[dst] = true
	c := testCarrier(t, fr, nil)
	defer c.Close()

	if err := c.Setup(context.Background()); err == nil {
		t.Fatal("setup must fail when verification fails")
	}
	if fr.has("-4", dst, "wgout") {
		t.Fatal("rollback did not delete the landed pin")
	}
	if !fr.has("-4", dst, "wan0") {
		t.Fatal("displaced foreign /32 not restored after fallback rollback")
	}
}

func TestKernelDeviceTokenNoPrefixCollision(t *testing.T) {
	// E7: a `dev wg01` line must NOT satisfy a wg0 carrier — neither the
	// idempotency check nor verifyRoute may substring-match devices.
	fr := newFakeRoutes()
	dst := ep4().Addr().String()
	c := testCarrier(t, fr, func(cc *KernelRouteCarrierConfig) {
		cc.Device = "wg0"
	})
	defer c.Close()

	if err := c.Setup(context.Background()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// A foreign device with a colliding name takes the route over; both
	// re-pin mutations are blocked.
	fr.mu.Lock()
	fr.lines[key("-4", dst)] = dst + " dev wg01"
	fr.failAdd[dst] = true
	fr.failReplace[dst] = true
	fr.mu.Unlock()

	// Old code: show line contains "dev wg0" (substring of "dev wg01") and
	// the route is owned => idempotent no-op SUCCESS. Fixed code: the token
	// match fails => a re-pin is attempted => both mutations fail => the
	// structural error surfaces instead of a false "already ours".
	if err := c.Setup(context.Background()); err == nil {
		t.Fatal("E7: collision line accepted as already-ours by the idempotency check")
	}
	// verifyRoute must likewise reject a wg01 effective route for wg0.
	if err := c.verifyRoute(context.Background(), "-4", ep4().Addr()); err == nil {
		t.Fatal("E7: verify accepted a dev wg01 line for carrier wg0")
	}
}

func TestDevTokenIsExactMatching(t *testing.T) {
	if !devTokenIs(strings.Fields("9.9.9.9 via 10.0.0.1 dev wg0"), "wg0") {
		t.Fatal("devTokenIs must match the exact token")
	}
	if devTokenIs(strings.Fields("9.9.9.9 via 10.0.0.1 dev wg01"), "wg0") {
		t.Fatal("devTokenIs must not substring-match prefix-colliding devices")
	}
	if devTokenIs(strings.Fields("9.9.9.9 dev"), "wg0") {
		t.Fatal("dangling dev token must not match")
	}
}

func TestKernelCloseWaitsAssertionLoop(t *testing.T) {
	fr := newFakeRoutes()
	c := testCarrier(t, fr, nil)

	ctx := context.Background()
	if err := c.Setup(ctx); err != nil {
		t.Fatalf("setup: %v", err)
	}
	c.RunAssertionLoop(ctx, 15*time.Millisecond)

	// Wipe the pin, then Close IMMEDIATELY: an in-flight Assert must not
	// re-pin after Close returns (E8 teardown race).
	fr.mu.Lock()
	delete(fr.lines, key("-4", "9.9.9.9"))
	fr.mu.Unlock()

	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("Close blocked beyond the Assert tick budget")
	}

	// Give any leaked (post-fix impossible) repair several tick windows.
	for i := 0; i < 30; i++ {
		if fr.has("-4", "9.9.9.9", "wgout") {
			t.Fatal("E8: pin re-appeared after Close (assertion loop raced teardown)")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
