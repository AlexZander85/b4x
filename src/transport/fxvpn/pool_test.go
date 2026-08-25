package fxvpn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// ---- deterministic test environment -------------------------------------------

type envClock struct {
	mu sync.Mutex
	t  time.Time
}

func newEnvClock() *envClock { return &envClock{t: time.Unix(1_800_000_000, 0)} }

func (c *envClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *envClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type eventLog struct {
	mu  sync.Mutex
	evs []PoolEvent
}

func (l *eventLog) sink(ev PoolEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evs = append(l.evs, ev)
}

func (l *eventLog) count(evType string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.evs {
		if e.Type == evType {
			n++
		}
	}
	return n
}

type poolFixture struct {
	pool     *Pool
	guardian *poolGuardian
	fxa      *FXA
	clock    *envClock
	events   *eventLog
}

func newPoolFixture(t *testing.T, accounts []Account, mutate func(*PoolConfig)) *poolFixture {
	t.Helper()
	fx := &poolFixture{clock: newEnvClock(), events: &eventLog{}}

	g := newPoolGuardian(t)
	cp := newTestCP(t, "")
	cp.EP.Guardian = g.srv.URL
	fx.guardian = g
	fx.fxa = newFxAStand(t).fxa

	cfg := PoolConfig{
		Now:    fx.clock.Now,
		Jitter: func() time.Duration { return 0 },
		Events: fx.events.sink,
	}
	if mutate != nil {
		mutate(&cfg)
	}

	store := NewAccountStore(storeSeedPath(t))
	if err := store.Save(&AccountsFile{Accounts: accounts}); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	pool, err := NewPool(store, fx.fxa, &Guardian{CP: cp}, cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	fx.pool = pool
	return fx
}

func rtAccount(label string) Account {
	return Account{Email: label + "@example.com", Label: label, RefreshToken: "rt-" + label}
}

// ---- scenarios ------------------------------------------------------------------

func TestPoolBootstrapHappyActivatesFirst(t *testing.T) {
	fx := newPoolFixture(t, []Account{rtAccount("a"), rtAccount("b")}, nil)
	fx.guardian.setQuota("500", "1000", "")

	if err := fx.pool.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	st := fx.pool.Status()
	if st.Blocked || len(st.Views) != 2 {
		t.Fatalf("status = %+v", st)
	}
	if !st.Views[0].Active || st.Views[0].State != StateActive {
		t.Fatalf("first must be active: %+v", st.Views[0])
	}
	if st.Views[1].State != StateStandby {
		t.Fatalf("second must be standby: %+v", st.Views[1])
	}
	if fx.events.count(EvAccountActivated) != 1 {
		t.Fatalf("activated events = %d, want 1", fx.events.count(EvAccountActivated))
	}
	bearer, ok := fx.pool.ActiveBearer()
	if !ok || bearer[:7] != "Bearer " {
		t.Fatalf("bearer = %q ok=%v", bearer, ok)
	}
	if st.Views[0].QuotaLeft != 500 || st.Views[0].QuotaMax != 1000 {
		t.Fatalf("quota not parsed: %+v", st.Views[0])
	}
}

func TestPoolThresholdWarningAndPreemptiveRotation(t *testing.T) {
	fx := newPoolFixture(t, []Account{rtAccount("a"), rtAccount("b")}, nil)
	fx.guardian.setQuota("900", "1000", "")
	if err := fx.pool.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Cross the threshold through the reporting path.
	fx.pool.ReportQuota(90, 1000, time.Time{})
	if fx.events.count(EvQuotaWarning) != 1 {
		t.Fatalf("warning events = %d, want exactly 1", fx.events.count(EvQuotaWarning))
	}
	fx.pool.ReportQuota(80, 1000, time.Time{}) // already warned this cycle: silent
	if fx.events.count(EvQuotaWarning) != 1 {
		t.Fatal("warning must fire once per cycle")
	}

	switched, err := fx.pool.RotateIfDue(context.Background())
	if err != nil || !switched {
		t.Fatalf("rotate = %v/%v, want true/nil", switched, err)
	}
	st := fx.pool.Status()
	if !st.Views[1].Active || st.Views[1].Label != "b" {
		t.Fatalf("b must serve now: %+v", st.Views)
	}
	if st.Views[0].State != StateCoolingDown {
		t.Fatalf("retired state = %s, want cooling_down", st.Views[0].State)
	}
	if fx.events.count(EvAccountActivated) != 2 {
		t.Fatalf("activated events = %d, want 2", fx.events.count(EvAccountActivated))
	}

	// Anti-flap: immediate re-rotation finds no eligible candidate and stays.
	switched, err = fx.pool.RotateIfDue(context.Background())
	if err != nil || switched {
		t.Fatalf("immediate re-rotate = %v/%v, want false/nil", switched, err)
	}
}

func TestPoolResetLeadTriggerRotatesEvenAtHighQuota(t *testing.T) {
	fx := newPoolFixture(t, []Account{rtAccount("a"), rtAccount("b")},
		func(c *PoolConfig) { c.ResetLeadWindow = time.Hour })
	fx.guardian.setQuota("950", "1000", "2038-01-01T00:00:00Z")
	if err := fx.pool.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Reset far away: no rotation.
	fx.pool.ReportQuota(950, 1000, fx.clock.Now().Add(72*time.Hour))
	if switched, _ := fx.pool.RotateIfDue(context.Background()); switched {
		t.Fatal("far reset must not rotate at 95 percent quota")
	}

	// Reset inside the lead window: trigger B fires.
	fx.pool.ReportQuota(950, 1000, fx.clock.Now().Add(30*time.Minute))
	switched, err := fx.pool.RotateIfDue(context.Background())
	if err != nil || !switched {
		t.Fatalf("reset-lead rotate = %v/%v", switched, err)
	}
}

func TestPoolExhaustedVacatesSeatAndRecyclesAfterReset(t *testing.T) {
	fx := newPoolFixture(t, []Account{rtAccount("a"), rtAccount("b")}, nil)
	fx.guardian.setQuota("500", "1000", "")
	if err := fx.pool.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	resetAt := fx.clock.Now().Add(time.Hour)
	fx.pool.MarkExhausted(resetAt)

	st := fx.pool.Status()
	if st.Views[0].State != StateExhausted || st.Views[0].Active {
		t.Fatalf("exhausted view wrong: %+v", st.Views[0])
	}
	if st.Views[1].State != StateStandby {
		t.Fatalf("standby expected: %+v", st.Views[1])
	}

	// Seat refills from the standby pool.
	switched, err := fx.pool.RotateIfDue(context.Background())
	if err != nil || !switched {
		t.Fatalf("fill after exhaustion = %v/%v", switched, err)
	}

	// Recycling honors the calendar.
	if got := fx.pool.RecycleDue(); len(got) != 0 {
		t.Fatalf("premature recycle: %v", got)
	}
	fx.clock.Add(2 * time.Hour)
	got := fx.pool.RecycleDue()
	if len(got) != 1 || got[0] != "a" {
		t.Fatalf("recycle = %v, want [a]", got)
	}
	st = fx.pool.Status()
	if st.Views[0].State != StateStandby {
		t.Fatalf("recycled state = %s", st.Views[0].State)
	}

}

func TestPoolCascadeAllExhaustedBlockedOnceNoLoop(t *testing.T) {
	fx := newPoolFixture(t, []Account{rtAccount("solo")}, nil)
	fx.guardian.setQuota("10", "1000", "")
	if err := fx.pool.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	fx.pool.MarkExhausted(fx.clock.Now().Add(time.Hour))

	for i := 0; i < 4; i++ {
		_, err := fx.pool.RotateIfDue(context.Background())
		if !errors.Is(err, ErrPoolBlocked) {
			t.Fatalf("iter %d: want ErrPoolBlocked, got %v", i, err)
		}
	}
	if n := fx.events.count(EvPoolBlocked); n != 1 {
		t.Fatalf("blocked announced %d times, want exactly 1 (no loops)", n)
	}
	st := fx.pool.Status()
	if !st.Blocked {
		t.Fatal("status must be structurally blocked")
	}

	// Time passes the reset calendar: recycle unlocks the pool.
	fx.clock.Add(2 * time.Hour)
	if got := fx.pool.RecycleDue(); len(got) != 1 {
		t.Fatalf("recycle after reset = %v", got)
	}
	switched, err := fx.pool.RotateIfDue(context.Background())
	if err != nil || !switched {
		t.Fatalf("post-recycle activation = %v/%v", switched, err)
	}
	if fx.pool.Status().Blocked {
		t.Fatal("blocked flag must clear after recycle+activation")
	}
}

func TestPoolBanLadderOnPersistentRefreshFailures(t *testing.T) {
	fx := newPoolFixture(t, []Account{rtAccount("doomed")}, nil)
	// Swap in the always-failing FxA client.
	fx.pool.mu.Lock()
	fx.pool.fxa = refreshAlwaysFailFxA(t)
	fx.pool.mu.Unlock()

	if err := fx.pool.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap must swallow account-level auth failures: %v", err)
	}
	st := fx.pool.Status()
	if !st.Blocked || st.Views[0].State != StateVerifying {
		t.Fatalf("after first failure: %+v", st.Views[0])
	}

	// Two more strikes (gates respected) => banned.
	for i := 0; i < 2; i++ {
		fx.clock.Add(time.Hour) // clear backoff gate
		if _, err := fx.pool.RotateIfDue(context.Background()); !errors.Is(err, ErrPoolBlocked) {
			t.Fatalf("strike %d: %v", i, err)
		}
	}
	st = fx.pool.Status()
	if st.Views[0].State != StateBanned {
		t.Fatalf("state = %s, want banned after %d failures", st.Views[0].State, 3)
	}
	if !st.Blocked {
		t.Fatal("single banned account = blocked pool")
	}
}

func TestPoolPasswordOnlyStaysVerifyingAndBlocks(t *testing.T) {
	pwOnly := Account{Email: "manual@example.com", Password: "pw"}
	fx := newPoolFixture(t, []Account{pwOnly}, nil)

	if err := fx.pool.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := fx.pool.Status()
	if st.Views[0].State != StateVerifying {
		t.Fatalf("password-only must wait interactive: %+v", st.Views[0])
	}
	if !st.Blocked {
		t.Fatal("verifying-only pool is structurally blocked (honest status)")
	}
}

func TestPoolRenewActivePassInsideLead(t *testing.T) {
	fx := newPoolFixture(t, []Account{rtAccount("a")}, nil)
	fx.guardian.setQuota("500", "1000", "")
	if err := fx.pool.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	if pass, err := fx.pool.RenewActivePassIfNeeded(context.Background()); err != nil || pass != nil {
		t.Fatalf("fresh pass must not renew: %v/%v", pass, err)
	}

	fx.clock.Add(3550 * time.Second) // exp-50s < 2min lead
	pass, err := fx.pool.RenewActivePassIfNeeded(context.Background())
	if err != nil || pass == nil {
		t.Fatalf("renew inside lead = %v/%v", pass, err)
	}
	tokens, _ := fx.guardian.counts()
	if tokens < 2 {
		t.Fatalf("guardian token mints = %d, want >=2", tokens)
	}
}

func TestPoolMarkAuthRejectedRotatesToFreshCredentials(t *testing.T) {
	fx := newPoolFixture(t, []Account{rtAccount("a"), rtAccount("b")}, nil)
	fx.guardian.setQuota("500", "1000", "")
	if err := fx.pool.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	fx.pool.MarkAuthRejected()
	switched, err := fx.pool.RotateIfDue(context.Background())
	if err != nil || !switched {
		t.Fatalf("rotation after auth rejection = %v/%v", switched, err)
	}
	st := fx.pool.Status()
	var bView, aView AccountView
	for _, v := range st.Views {
		switch v.Label {
		case "a":
			aView = v
		case "b":
			bView = v
		}
	}
	if !bView.Active || bView.State != StateActive {
		t.Fatalf("b must take over: %+v", st.Views)
	}
	if aView.State != StateVerifying {
		t.Fatalf("rejected account must wait in verifying: %+v", aView)
	}
}
