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
	calls       []string
}

func newFakeRoutes() *fakeRoutes {
	return &fakeRoutes{
		lines:       map[string]string{},
		showPre:     map[string]string{},
		failAdd:     map[string]bool{},
		failReplace: map[string]bool{},
		failGet:     map[string]bool{},
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
