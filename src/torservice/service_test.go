package torservice

// TT7 DoD (patch-plan §8): the fake-tor stand drives the state machine —
// success ladder, binary-missing, no-bridges wait, stall ladder advance,
// liveness NEWNYM/teardown/restart-with-winner, restart cap backoff,
// mixed-set winner attribution, exit mismatch. All seams in-package.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/transport/tor"

	"go.uber.org/goleak"
)

const fp1 = "0123456789ABCDEF0123456789ABCDEF01234567"
const obfs4Line = "obfs4 45.66.35.35:443 " + fp1 + " cert=x"
const webtunnelLine = "webtunnel 2001:db8::1:443 " + fp1 + " url=https://x/"

// initIgnore captures the package-init goroutines (kcp-go schedulers via
// the snowflake import chain).
var initIgnore = goleak.IgnoreCurrent()

// cleanupLeaksAfterStop registers the leak check as a t.Cleanup BEFORE
// the bed registers its Stop cleanup — cleanups run LIFO, so Stop runs
// first and the check sees only real leaks.
func cleanupLeaksAfterStop(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t, initIgnore) })
}

// --- fakes ---

// fakeProcess is a controllable ProcessController.
type fakeProcess struct {
	pid   int
	death chan tor.ProcessDeath
	dead  bool
	mu    sync.Mutex
}

func (f *fakeProcess) PID() int                       { return f.pid }
func (f *fakeProcess) Death() <-chan tor.ProcessDeath { return f.death }
func (f *fakeProcess) Stop(ctx context.Context, ctl tor.ControlClient) {
	f.mu.Lock()
	if !f.dead {
		f.dead = true
		close(f.death)
	}
	f.mu.Unlock()
}
func (f *fakeProcess) kill(reason error) {
	f.mu.Lock()
	if !f.dead {
		f.dead = true
		f.death <- tor.ProcessDeath{Err: reason}
	}
	f.mu.Unlock()
}

// fakeControl scripts GETINFO answers and records SIGNAL/SETCONF.
type fakeControl struct {
	mu        sync.Mutex
	bootstrap []string // ladder per poll (last repeats)
	orconn    string
	signals   []string
	setconfs  []string
	authOK    bool
	socks     string
}

func (f *fakeControl) Authenticate(cookie []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authOK = true
	return nil
}

func (f *fakeControl) GetInfo(keys ...string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for _, k := range keys {
		switch k {
		case "status/bootstrap-phase":
			if len(f.bootstrap) == 0 {
				return nil, errors.New("no bootstrap scripted")
			}
			out[k] = f.bootstrap[0]
			if len(f.bootstrap) > 1 {
				f.bootstrap = f.bootstrap[1:]
			}
		case "net/listeners/socks":
			out[k] = f.socks
		case "orconn-status", "entry-guards":
			out[k] = f.orconn
		case "circuit-status":
			out[k] = "LAUNCHED LAUNCHED"
		case "traffic/read":
			out[k] = "1000"
		case "traffic/written":
			out[k] = "2000"
		default:
			out[k] = ""
		}
	}
	return out, nil
}

func (f *fakeControl) Signal(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signals = append(f.signals, s)
	return nil
}

func (f *fakeControl) SetConf(kv ...[2]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, pair := range kv {
		f.setconfs = append(f.setconfs, pair[0]+"="+pair[1])
	}
	return nil
}

func (f *fakeControl) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func ph(progress int, tag string) string {
	return fmt.Sprintf("NOTICE BOOTSTRAP PROGRESS=%d TAG=%s SUMMARY=\"x\"", progress, tag)
}

// runtimeTestBed wires a Runtime with all seams faked.
type runtimeTestBed struct {
	t       *testing.T
	rt      *Runtime
	proc    *fakeProcess
	ctl     *fakeControl
	died    chan error
	dataDir string
}

func newRuntimeTestBed(t *testing.T, tc config.TorConfig) *runtimeTestBed {
	t.Helper()
	dataDir := t.TempDir()
	tc.DataPath = dataDir
	tc.Enabled = true
	if tc.Entry.Mode == "" {
		tc.Entry.Mode = "auto"
	}
	cfg := config.NewConfig()
	cfg.System.Tor = tc

	bed := &runtimeTestBed{t: t, dataDir: dataDir}
	// the fake tor "writes" its control cookie where the runtime reads it
	if err := os.MkdirAll(filepath.Join(dataDir, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "data", "control.cookie"), []byte("fake-cookie-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	bed.proc = &fakeProcess{pid: 4242, death: make(chan tor.ProcessDeath, 4)}
	bed.ctl = &fakeControl{
		bootstrap: []string{ph(10, "conn_done"), ph(45, "handshake"), ph(100, "done")},
		socks:     "127.0.0.1:9050",
	}

	fastBoot := tor.DefaultBootstrapConfig()
	fastBoot.PollInterval = 5 * time.Millisecond
	fastBoot.StallWindow = 300 * time.Millisecond
	fastBoot.HardCap = 2 * time.Second
	fastBoot.SnowflakeCap = 2 * time.Second

	rt, err := Build(&cfg, Options{
		Now:           time.Now,
		SuperviseTick: time.Hour, // tests drive ensure() manually
		Bootstrap:     fastBoot,
		// consent rule: the test collector has NO default mirrors and a
		// silent HTTP client — nothing leaves the process.
		CollectorFactory: func(store *tor.BridgesStore, dial tor.ProbeDial, now func() time.Time) *tor.Collector {
			return tor.NewCollector(tor.CollectorOptions{
				Store:            store,
				Dial:             dial,
				Now:              now,
				NoDefaultMirrors: true,
				MoatURL:          "https://moat.invalid.test",
				MirrorURLs:       []string{"https://mirror.invalid.test/{file}"},
				Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					return nil, errors.New("consent rule: no live collection from tests")
				})},
			})
		},
		Spawn: func(ctx context.Context, binaryPath, torrcPath, dataPath string) (ProcessController, error) {
			return bed.proc, nil
		},
		DialControl: func(ctx context.Context, network, addr string) (tor.ControlClient, error) {
			return bed.ctl, nil
		},
		LivenessProbe: func(ctx context.Context, socksAddr string) error { return nil },
		ExitProbe: func(ctx context.Context, socksAddr string) (ExitInfo, error) {
			return ExitInfo{IP: "199.9.14.1", Country: "US", IsTor: true}, nil
		},
		Resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return nil, errors.New("no resolve in tests")
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	bed.rt = rt
	// deterministic tests: wire the listeners WITHOUT the supervisor loop
	// goroutine — the bed drives ensure() itself
	if err := rt.startListeners(context.Background()); err != nil {
		t.Fatalf("startListeners: %v", err)
	}
	t.Cleanup(rt.Stop)
	return bed
}

func (bed *runtimeTestBed) ensure() { bed.rt.ensure(context.Background()) }

func (bed *runtimeTestBed) state() string {
	bed.rt.mu.Lock()
	defer bed.rt.mu.Unlock()
	return bed.rt.state
}

func (bed *runtimeTestBed) lastEvents(n int) []tor.TorEvent {
	bed.rt.mu.Lock()
	defer bed.rt.mu.Unlock()
	ev := bed.rt.events
	if len(ev) > n {
		ev = ev[len(ev)-n:]
	}
	return append([]tor.TorEvent(nil), ev...)
}

func (bed *runtimeTestBed) hasEvent(name string) bool {
	for _, ev := range bed.lastEvents(64) {
		if ev.Name == name {
			return true
		}
	}
	return false
}

func (bed *runtimeTestBed) storeBridges(lines ...string) {
	f := tor.BridgesFile{Schema: 1, UpdatedAt: time.Now().UnixMilli(), Source: "test"}
	for _, l := range lines {
		if b, err := tor.ParseBridgeLine(l); err == nil {
			f.Bridges = append(f.Bridges, tor.StoredBridge{Transport: b.Transport, Line: b.Line, Endpoint: b.AddrPort, Fingerprint: b.Fingerprint})
		}
	}
	if err := bed.rt.store.Save(f); err != nil {
		bed.t.Fatal(err)
	}
}

// --- scenarios ---

func TestTorScenarioBootstrapSuccess(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "obfs4"}})
	bed.storeBridges(obfs4Line)

	bed.ensure() // bridges + process
	bed.ensure() // bootstrap
	if got := bed.state(); got != StateEstablished {
		t.Fatalf("state = %q, want established (events: %+v)", got, bed.lastEvents(8))
	}
	if !bed.hasEvent(tor.EventTorEstablished) {
		t.Fatal("tor_established event missing")
	}
	if !bed.hasEvent(tor.EventTorEntryWon) {
		t.Fatal("tor_entry_won event missing")
	}
	st := bed.rt.Status()
	if !st.Listening || st.Bootstrap.Progress != 100 {
		t.Fatalf("status = %+v", st)
	}
	if st.Entry.Winner != "obfs4" {
		t.Fatalf("winner = %q", st.Entry.Winner)
	}
	// entry memory recorded the winner
	mem := bed.rt.entryMem.Load(time.Now)
	if mem.Winner != "obfs4" {
		t.Fatalf("memory winner = %+v", mem)
	}
}

func TestTorScenarioBinaryMissing(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{})
	bed.storeBridges(obfs4Line)
	// make spawn fail: binary path points nowhere and the default spawn runs
	bed.rt.opts.Spawn = func(ctx context.Context, binaryPath, torrcPath, dataPath string) (ProcessController, error) {
		return nil, os.ErrNotExist
	}
	bed.ensure()
	if got := bed.state(); got != StateBinaryMissing {
		t.Fatalf("state = %q, want binary-missing", got)
	}
	if !bed.hasEvent(tor.EventTorBinaryMissing) {
		t.Fatal("tor_binary_missing event missing")
	}
	st := bed.rt.Status()
	if st.Hint == "" || !strings.Contains(st.Hint, "opkg install tor") {
		t.Fatalf("hint = %q", st.Hint)
	}
}

func TestTorScenarioNoBridgesWait(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "obfs4"}})
	// empty store + failing collector (all mirrors dead via the seam is
	// heavy; the collector itself fails honestly on an empty world)
	bed.ensure()
	if got := bed.state(); got != StateBridgesWait {
		t.Fatalf("state = %q, want bridges-wait (no process spawn without bridges)", got)
	}
}

func TestTorScenarioStallAdvancesLadder(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{})
	bed.storeBridges(obfs4Line) // mixed-set: obfs4 only from store
	// freeze bootstrap at 25% → stall window (300ms) fires
	bed.ctl.bootstrap = []string{ph(25, "handshake")}

	bed.ensure()
	bed.ensure()
	// bootstrap stalls synchronously (fast windows)
	if got := bed.state(); got == StateEstablished {
		t.Fatal("frozen bootstrap must not establish")
	}
	bed.rt.mu.Lock()
	entry := bed.rt.entry
	bed.rt.mu.Unlock()
	if entry == "auto-mixed" {
		t.Fatalf("stalled mixed-set must advance the ladder, entry = %q", entry)
	}
	if !bed.hasEvent(tor.EventTorEntryFailed) {
		t.Fatal("tor_entry_failed event missing")
	}
}

func TestTorScenarioLivenessNEWNYMAndRestart(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	bed.ensure()
	if bed.state() != StateEstablished {
		t.Fatalf("state = %q", bed.state())
	}

	// liveness starts failing
	fail := true
	bed.rt.opts.LivenessProbe = func(ctx context.Context, socksAddr string) error {
		if fail {
			return errors.New("dead")
		}
		return nil
	}
	// accelerate: no liveness-interval gating between test steps
	for i := 0; i < 4; i++ {
		bed.rt.mu.Lock()
		bed.rt.lastLiveness = time.Now().Add(-2 * livenessInterval)
		bed.rt.mu.Unlock()
		bed.ensure()
	}
	bed.ctl.mu.Lock()
	signals := append([]string(nil), bed.ctl.signals...)
	bed.ctl.mu.Unlock()
	sawNewnym := false
	sawActive := false
	for _, s := range signals {
		if s == "NEWNYM" {
			sawNewnym = true
		}
		if s == "ACTIVE" {
			sawActive = true
		}
	}
	if !sawNewnym || !sawActive {
		t.Fatalf("2 liveness failures must trigger ACTIVE+NEWNYM, signals = %v", signals)
	}
	if !bed.hasEvent(tor.EventTorRotated) {
		t.Fatal("tor_rotated event missing")
	}
	// 4+ failures: teardown + restart scheduled from the winner
	bed.rt.mu.Lock()
	entry := bed.rt.entry
	bed.rt.mu.Unlock()
	if entry != "obfs4" {
		t.Fatalf("restart must return to the winner entry, entry = %q", entry)
	}
}

func TestTorScenarioRestartCapBackoff(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{})
	bed.rt.cfg.MaxRestartsPerHour = 1
	bed.storeBridges(obfs4Line)
	bed.ensure()
	bed.ensure()

	// exhaust the restart budget through repeated teardowns
	fail := true
	bed.rt.opts.LivenessProbe = func(ctx context.Context, socksAddr string) error {
		if fail {
			return errors.New("dead")
		}
		return nil
	}
	// enough iterations for TWO full teardown cycles: the first restart
	// consumes the budget (max=1), the second hits the cap → backoff
	for i := 0; i < 14; i++ {
		bed.rt.mu.Lock()
		bed.rt.lastLiveness = time.Now().Add(-2 * livenessInterval)
		bed.rt.mu.Unlock()
		bed.ensure()
		if bed.state() == StateBackoff {
			break
		}
	}
	if got := bed.state(); got != StateBackoff {
		t.Fatalf("state = %q, want backoff after restart cap", got)
	}
}

func TestTorScenarioMixedSetWinnerAttribution(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{})
	bed.storeBridges(webtunnelLine, obfs4Line)
	// orconn-status reports the obfs4 bridge as the connected one
	bed.ctl.mu.Lock()
	bed.ctl.orconn = "45.66.35.35:443 CONNECTED"
	bed.ctl.mu.Unlock()

	bed.ensure()
	bed.ensure()
	if bed.state() != StateEstablished {
		t.Fatalf("state = %q (events %+v)", bed.state(), bed.lastEvents(6))
	}
	bed.rt.mu.Lock()
	winner := bed.rt.winner
	bed.rt.mu.Unlock()
	if winner != "obfs4" {
		t.Fatalf("mixed-set winner = %q, want obfs4 (orconn attribution)", winner)
	}
	mem := bed.rt.entryMem.Load(time.Now)
	if mem.Winner != "obfs4" {
		t.Fatalf("memory winner = %+v", mem)
	}
}

func TestTorScenarioExitMismatch(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	bed.ensure()

	bed.rt.opts.ExitProbe = func(ctx context.Context, socksAddr string) (ExitInfo, error) {
		return ExitInfo{IP: "1.2.3.4", Country: "XX", IsTor: false}, nil
	}
	bed.rt.mu.Lock()
	bed.rt.lastExitProbe = time.Now().Add(-2 * exitProbeInterval)
	bed.rt.mu.Unlock()
	bed.ensure()
	if !bed.hasEvent(tor.EventTorExitMismatch) {
		t.Fatal("tor_exit_mismatch event missing")
	}
	// informational: no strike/rotation on mismatch
	if bed.state() != StateEstablished {
		t.Fatalf("mismatch must not tear the tunnel down, state = %q", bed.state())
	}
}

func TestTorScenarioConfluxHonestDegradation(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Speed: config.TorSpeedConfig{Conflux: "throughput"}})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	bed.ensure()

	// after establishment ensureConflux ran; the fake accepts SETCONF
	bed.ctl.mu.Lock()
	confs := append([]string(nil), bed.ctl.setconfs...)
	bed.ctl.mu.Unlock()
	joined := strings.Join(confs, ",")
	if !strings.Contains(joined, "ConfluxEnabled=1") || !strings.Contains(joined, "ConfluxClientUX=throughput") {
		t.Fatalf("conflux SETCONF missing: %v", confs)
	}
	if !bed.hasEvent(tor.EventTorConfluxEnabled) {
		t.Fatal("tor_conflux_enabled event missing")
	}
}

func TestTorScenarioDisabledBuildRefused(t *testing.T) {
	// the honest no-op canon: the CALLER never builds a disabled runtime;
	// Build refuses loudly if it happens anyway.
	cfg := config.NewConfig()
	cfg.System.Tor.Enabled = false
	if _, err := Build(&cfg, Options{}); err == nil {
		t.Fatal("Build with disabled config must refuse")
	}
}

func TestTorScenarioDirectEntryNoBridges(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "direct"}})
	bed.ensure()
	bed.ensure()
	if bed.state() != StateEstablished {
		t.Fatalf("direct entry needs no bridges, state = %q", bed.state())
	}
	// the rendered torrc carries UseBridges 0
	bed.rt.mu.Lock()
	set := bed.rt.activeSet
	bed.rt.mu.Unlock()
	if len(set) != 0 {
		t.Fatalf("direct entry set = %v", set)
	}
}

func TestTorProcessDeathTriggersRestart(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	bed.ensure()
	if bed.state() != StateEstablished {
		t.Fatalf("state = %q", bed.state())
	}
	// tor dies: the death channel delivers (the loop would call
	// handleDeath; the test calls it directly for determinism)
	bed.proc.kill(errors.New("segfault"))
	select {
	case <-bed.proc.Death():
	default:
		t.Fatal("death must be delivered")
	}
	bed.rt.handleDeath(context.Background())
	bed.rt.mu.Lock()
	entry := bed.rt.entry
	bed.rt.mu.Unlock()
	if entry != "obfs4" {
		t.Fatalf("restart-from-winner expected obfs4, entry = %q", entry)
	}
	if !bed.hasEvent(tor.EventTorProcessDied) {
		t.Fatal("tor_process_died event missing")
	}
}

// torrc rendering sanity through the runtime path: the file lands in the
// data slot with the owning pid.
func TestTorTorrcFileWritten(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	bed.ensure()
	raw, err := os.ReadFile(filepath.Join(bed.dataDir, "torrc"))
	if err != nil {
		t.Fatalf("torrc: %v", err)
	}
	doc := string(raw)
	if !strings.Contains(doc, "ClientOnly 1") {
		t.Fatalf("torrc content wrong:\n%s", doc)
	}
	if !strings.Contains(doc, fmt.Sprintf("__OwningControllerProcess %d", os.Getpid())) {
		t.Fatalf("owning controller pid missing:\n%s", doc)
	}
}
