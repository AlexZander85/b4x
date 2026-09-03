package fxvpservice

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	fxvpn "github.com/daniellavrushin/b4/transport/fxvpn"
)

func TestIsBypassDomainTable(t *testing.T) {
	yes := []string{
		"vpn.mozilla.org", "api.accounts.firefox.com",
		"firefox.settings.services.mozilla.com",
		"fra1.m1.fastly-masque.net", "FASTLY-MASQUE.NET.",
	}
	no := []string{"", "example.com", "notmozilla.org", "evil-fastly-masque.net.example"}
	for _, h := range yes {
		if !IsBypassDomain(h) {
			t.Fatalf("%q must be bypass", h)
		}
	}
	for _, h := range no {
		if IsBypassDomain(h) {
			t.Fatalf("%q must NOT be bypass", h)
		}
	}
}

func newGuard(now func() time.Time) *restartGuard { return &restartGuard{now: now} }

func TestRestartGuardCapsSixPerHour(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	g := newGuard(clock)

	for i := 0; i < MaxRestartsPerHour; i++ {
		if !g.allowed() {
			t.Fatalf("restart %d must be allowed", i+1)
		}
		g.stamp()
	}
	if g.allowed() {
		t.Fatal("7th restart within the hour must be capped")
	}

	// Cooldown stamps in after the cap: still blocked later inside window.
	now = now.Add(RestartCooldown / 2)
	if g.allowed() {
		t.Fatal("cooldown must hold")
	}

	// An hour later the window drains.
	now = now.Add(time.Hour)
	if !g.allowed() {
		t.Fatal("cap must expire after an hour")
	}
}

func TestRestartGuardCooldownAndSlidingWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	g := newGuard(clock)
	for i := 0; i < MaxRestartsPerHour; i++ {
		g.stamp()
	}

	// Cooldown window: blocked even though an hour has NOT passed.
	now = now.Add(RestartCooldown / 2)
	if g.allowed() {
		t.Fatal("cooldown must hold right after the cap")
	}

	// Sliding window: all six stamps still inside the hour => still capped
	// even past the cooldown stamp.
	now = now.Add(time.Hour - RestartCooldown - time.Minute)
	if g.allowed() {
		t.Fatal("sliding hour must keep the cap while stamps are alive")
	}

	// Past the last stamp's birthday the window drains.
	now = now.Add(4 * time.Minute)
	if !g.allowed() {
		t.Fatal("cap must expire once stamps age out of the sliding hour")
	}
}

func TestPathHelpers(t *testing.T) {
	if got := pinPathFor("/opt/etc/b4/fxvpn/accounts.json"); got != "/opt/etc/b4/fxvpn/pins.json" {
		t.Fatalf("pinPathFor = %q", got)
	}
	if got := siblingPath("/opt/etc/b4/fxvpn/accounts.json", "serverlist.json"); got != "/opt/etc/b4/fxvpn/serverlist.json" {
		t.Fatalf("siblingPath = %q", got)
	}
	if got := pinPathFor("accounts.json"); got != "pins.json" {
		t.Fatalf("bare pinPathFor = %q", got)
	}
}

func TestClassifyServiceErrMapping(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fxvpn.ErrPoolBlocked, fxvpn.ClassQuotaExhausted},
		{fxvpn.ErrNoServers, fxvpn.ClassNoServerForLocation},
		{fxvpn.ErrPinMismatch, fxvpn.ClassAPIPinMismatch},
		{errors.New("misc"), ""},
	}
	for _, tc := range cases {
		if got := classifyServiceErr(tc.err); got != tc.want && tc.want != "" {
			t.Fatalf("classify(%v)=%q want %q", tc.err, got, tc.want)
		}
	}
	if got := classifyServiceErr(fxvpn.ErrPoolBlocked); got != fxvpn.ClassQuotaExhausted {
		t.Fatalf("pool blocked class = %q", got)
	}
}

// Build smoke: disabled config assembles WITHOUT any I/O; status is honest
// (running=false, pool empty+blocked); Start/Stop idempotent; SupportsUDP
// constant false.
func TestBuildDisabledSmokeAndLifecycle(t *testing.T) {
	cfg := &config.Config{}
	rt, err := Build(cfg, Options{})
	if err != nil {
		t.Fatalf("build disabled: %v", err)
	}
	if rt.SupportsUDP() {
		t.Fatal("fxvpn must be TCP-only")
	}

	st := rt.Status()
	if st.Enabled || st.Running || st.Listening || st.Transport != "tcp-only" {
		t.Fatalf("status = %+v", st)
	}
	if !st.Pool.Blocked || !st.Pool.Empty {
		t.Fatalf("empty pool must be structurally blocked: %+v", st.Pool)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := rt.Start(ctx); err != nil {
		t.Fatal("double start must be idempotent")
	}
	// Give the first tick a moment; disabled pool stays blocked either way.
	time.Sleep(50 * time.Millisecond)
	rt.Stop()
	rt.Stop() // idempotent
	cancel()
}

// TestWiringSmokeEnabledRuntimeStarts pins review F4 at the service layer:
// an enabled config builds and starts the supervisor loop, Status reports
// running, and the StreamDialer seam is the runtime itself (the scoped
// router contract). The daemon-side wiring itself lives in main.go (proton
// canon block).
func TestWiringSmokeEnabledRuntimeStarts(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.FxVPN.Enabled = true
	cfg.System.FxVPN.AccountsPath = filepath.Join(t.TempDir(), "accounts.json")
	rt, err := Build(cfg, Options{})
	if err != nil {
		t.Fatalf("build enabled: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	time.Sleep(80 * time.Millisecond) // let the first tick run (empty pool -> no-op)
	st := rt.Status()
	if !st.Enabled || !st.Running {
		t.Fatalf("enabled runtime must run: %+v", st)
	}
	if rt.StreamDialer() == nil {
		t.Fatal("StreamDialer seam must be exposed")
	}
	rt.Stop()
}
