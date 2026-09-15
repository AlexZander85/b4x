package torservice

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
const webtunnelLine = "webtunnel 198.51.100.2:443 " + fp1 + " url=https://example.com/secret"
const snowflakeLine = "snowflake 192.0.2.3:1 " + fp1 + " url=https://broker.example/ fronts=front.example"
const meekLine = "meek_lite 198.51.100.4:443 " + fp1 + " url=https://example.com/"

var initIgnore = goleak.IgnoreCurrent()

func cleanupLeaksAfterStop(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t, initIgnore) })
}

type fakeProcess struct {
	pid       int
	death     chan tor.ProcessDeath
	mu        sync.Mutex
	dead      bool
	stopCount int
}

func newFakeProcess(pid int) *fakeProcess {
	return &fakeProcess{pid: pid, death: make(chan tor.ProcessDeath, 2)}
}
func (f *fakeProcess) PID() int { return f.pid }
func (f *fakeProcess) Death() <-chan tor.ProcessDeath { return f.death }
func (f *fakeProcess) Alive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.dead
}
func (f *fakeProcess) Stop(ctx context.Context, ctl tor.ControlClient) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCount++
	f.dead = true
	_ = ctx
	_ = ctl
}
func (f *fakeProcess) stopped() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopCount
}
func (f *fakeProcess) kill(reason error) {
	f.mu.Lock()
	if !f.dead {
		f.dead = true
		f.death <- tor.ProcessDeath{Err: reason}
	}
	f.mu.Unlock()
}

type fakeControl struct {
	mu        sync.Mutex
	bootstrap []string
	orconn    string
	signals   []string
	setconfs  []string
	socks     string
}

func (f *fakeControl) Authenticate(cookie []byte) error { return nil }
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
		case "orconn-status":
			out[k] = f.orconn
		case "entry-guards":
			out[k] = ""
		case "circuit-status":
			out[k] = "1 BUILT"
		case "traffic/read":
			out[k] = "1000"
		case "traffic/written":
			out[k] = "2000"
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
	for _, p := range kv {
		f.setconfs = append(f.setconfs, p[0]+"="+p[1])
	}
	return nil
}
func (f *fakeControl) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func ph(progress int, tag string) string {
	return fmt.Sprintf("NOTICE BOOTSTRAP PROGRESS=%d TAG=%s SUMMARY=\"x\"", progress, tag)
}

type runtimeTestBed struct {
	t       *testing.T
	rt      *Runtime
	ctl     *fakeControl
	dataDir string
	mu      sync.Mutex
	procs   []*fakeProcess
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
	if err := os.MkdirAll(filepath.Join(dataDir, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "data", "control.cookie"), []byte("fake-cookie"), 0o600); err != nil {
		t.Fatal(err)
	}
	bed := &runtimeTestBed{t: t, dataDir: dataDir}
	bed.ctl = &fakeControl{
		bootstrap: []string{ph(10, "conn_done"), ph(45, "handshake"), ph(100, "done")},
		socks: "127.0.0.1:9050",
	}
	fastBoot := tor.DefaultBootstrapConfig()
	fastBoot.PollInterval = 5 * time.Millisecond
	fastBoot.StallWindow = 120 * time.Millisecond
	fastBoot.HardCap = 2 * time.Second
	fastBoot.SnowflakeCap = 2 * time.Second

	rt, err := Build(&cfg, Options{
		Now: time.Now, SuperviseTick: time.Hour, Bootstrap: fastBoot,
		CollectorFactory: func(store *tor.BridgesStore, dial tor.ProbeDial, now func() time.Time) *tor.Collector {
			return tor.NewCollector(tor.CollectorOptions{
				Store: store, Dial: dial, Now: now, NoDefaultMirrors: true,
				MoatURL: "https://moat.invalid.test", MirrorURLs: []string{"https://mirror.invalid.test/{file}"},
				Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					return nil, errors.New("consent rule: no live collection from tests")
				})},
			})
		},
		Spawn: func(ctx context.Context, binaryPath, torrcPath, dataPath string) (ProcessController, error) {
			bed.mu.Lock()
			defer bed.mu.Unlock()
			p := newFakeProcess(4242 + len(bed.procs))
			bed.procs = append(bed.procs, p)
			return p, nil
		},
		DialControl: func(ctx context.Context, network, addr string) (tor.ControlClient, error) { return bed.ctl, nil },
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
	if err := rt.startListeners(context.Background()); err != nil {
		t.Fatalf("startListeners: %v", err)
	}
	t.Cleanup(rt.Stop)
	return bed
}

func (b *runtimeTestBed) ensure() { b.rt.ensure(context.Background()) }
func (b *runtimeTestBed) state() string {
	b.rt.mu.Lock(); defer b.rt.mu.Unlock(); return b.rt.state
}
func (b *runtimeTestBed) currentProc() *fakeProcess {
	b.mu.Lock(); defer b.mu.Unlock()
	if len(b.procs) == 0 { return nil }
	return b.procs[len(b.procs)-1]
}
func (b *runtimeTestBed) spawnCount() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.procs) }
func (b *runtimeTestBed) hasEvent(name string) bool {
	b.rt.mu.Lock(); defer b.rt.mu.Unlock()
	for _, ev := range b.rt.events { if ev.Name == name { return true } }
	return false
}
func (b *runtimeTestBed) storeBridges(lines ...string) {
	f := tor.BridgesFile{Schema: 1, UpdatedAt: time.Now().UnixMilli(), Source: "test"}
	for _, line := range lines {
		br, err := tor.ParseBridgeLine(line)
		if err != nil { b.t.Fatalf("parse %q: %v", line, err) }
		f.Bridges = append(f.Bridges, tor.StoredBridge{Transport: br.Transport, Line: br.Line, Endpoint: br.AddrPort, Fingerprint: br.Fingerprint})
	}
	if err := b.rt.store.Save(f); err != nil { b.t.Fatal(err) }
}

func TestTorPinnedBootstrapSuccess(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "obfs4"}})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	if bed.state() != StateEstablished { t.Fatalf("state=%s", bed.state()) }
	st := bed.rt.Status()
	if !st.Listening || st.Entry.Winner != "obfs4" || st.Entry.WinnerBridge == "" {
		t.Fatalf("status=%+v", st)
	}
}

func TestTorAutoMixedWinnerPersistsBridgeIdentity(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "auto", RaceWindow: 2}})
	bed.storeBridges(webtunnelLine, obfs4Line)
	bed.ctl.orconn = "45.66.35.35:443 CONNECTED"
	bed.ensure()
	if bed.state() != StateEstablished { t.Fatalf("state=%s", bed.state()) }
	st := bed.rt.Status()
	if st.Entry.Winner != "obfs4" || !strings.Contains(st.Entry.WinnerBridge, "obfs4|") {
		t.Fatalf("winner=%+v", st.Entry)
	}
	mem := bed.rt.entryMem.Load(time.Now)
	if mem.Winner != "obfs4" || mem.WinnerBridge == "" {
		t.Fatalf("memory=%+v", mem)
	}
}

func TestTorAutoMixedUnknownWinnerDoesNotLearn(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "auto", RaceWindow: 2}})
	bed.storeBridges(webtunnelLine, obfs4Line)
	bed.ctl.orconn = "$FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF CONNECTED"
	bed.ensure()
	if bed.state() != StateEstablished { t.Fatalf("state=%s", bed.state()) }
	st := bed.rt.Status()
	if st.Entry.Winner != "" || st.Entry.WinnerBridge != "" {
		t.Fatalf("unknown attribution must not fabricate winner: %+v", st.Entry)
	}
	if !bed.hasEvent(tor.EventTorEntryAttributionUnknown) {
		t.Fatal("attribution-unknown event missing")
	}
	if mem := bed.rt.entryMem.Load(time.Now); mem.Winner != "" {
		t.Fatalf("unknown winner must not train memory: %+v", mem)
	}
}

func TestTorAutoMixedFailureSelectsSequentialEntry(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "auto", RaceWindow: 2}})
	bed.storeBridges(obfs4Line)
	bed.ctl.bootstrap = []string{ph(25, "handshake")}
	bed.ensure()
	bed.rt.mu.Lock()
	entry := bed.rt.entry
	mixed := bed.rt.mixedTried
	bed.rt.mu.Unlock()
	if !mixed || entry == "" || entry == "auto-mixed" {
		t.Fatalf("mixed failure must choose explicit sequential entry: mixed=%t entry=%q", mixed, entry)
	}
}

func TestTorMixedRaceWindowGlobalAndMeekManualOnly(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "auto", RaceWindow: 2}, Bridges: config.TorBridgesConfig{BuiltinSnowflake: false}})
	bed.storeBridges(webtunnelLine, obfs4Line, snowflakeLine, meekLine)
	set, ok := bed.rt.assembleSet("auto-mixed")
	if !ok || len(set) != 2 { t.Fatalf("set=%+v ok=%t", set, ok) }
	for _, br := range set {
		if br.Transport == "meek_lite" { t.Fatal("meek_lite must remain manual-only") }
	}
}

func TestTorPinnedSnowflakeFailsClosed(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{
		Entry: config.TorEntryConfig{Mode: "snowflake"},
		Egress: config.TorEgressConfig{Through: "proton"},
		Bridges: config.TorBridgesConfig{BuiltinSnowflake: true},
	})
	bed.ensure()
	if bed.state() != StateBackoff || bed.spawnCount() != 0 {
		t.Fatalf("pinned Snowflake must fail closed: state=%s spawns=%d", bed.state(), bed.spawnCount())
	}
	if !bed.hasEvent(tor.EventTorCarrierUnsupported) { t.Fatal("carrier-unsupported event missing") }
}

func TestTorLivenessUsesRealGraceAndRetiresBeforeRestart(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "obfs4"}})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	old := bed.currentProc()
	bed.rt.opts.LivenessProbe = func(ctx context.Context, socksAddr string) error { return errors.New("dead") }
	for i := 0; i < 4; i++ {
		bed.rt.mu.Lock()
		bed.rt.lastLiveness = time.Now().Add(-2 * livenessInterval)
		bed.rt.mu.Unlock()
		bed.ensure()
	}
	if old.stopped() != 0 { t.Fatal("4th failure must start grace, not teardown immediately") }
	bed.rt.mu.Lock()
	bed.rt.livenessDeadSince = time.Now().Add(-livenessGrace - time.Second)
	bed.rt.mu.Unlock()
	bed.ensure()
	if old.stopped() != 1 { t.Fatalf("old process stopCount=%d", old.stopped()) }
	if bed.spawnCount() != 1 { t.Fatalf("replacement must not spawn in same retirement pass: %d", bed.spawnCount()) }
	bed.rt.opts.LivenessProbe = func(ctx context.Context, socksAddr string) error { return nil }
	bed.ctl.bootstrap = []string{ph(100, "done")}
	bed.ensure()
	if bed.spawnCount() != 2 { t.Fatalf("replacement spawn count=%d", bed.spawnCount()) }
	if bed.currentProc() == old { t.Fatal("replacement process must differ from retired process") }
}

func TestTorManualRestartRetiresOldProcessFirst(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "obfs4"}})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	old := bed.currentProc()
	bed.rt.RestartNow(context.Background())
	if old.stopped() != 1 { t.Fatalf("old process was not retired: %d", old.stopped()) }
	bed.ensure()
	if bed.spawnCount() != 2 { t.Fatalf("spawn count=%d", bed.spawnCount()) }
}

func TestTorProcessDeathTriggersRestart(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "obfs4"}})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	p := bed.currentProc()
	p.kill(errors.New("segfault"))
	bed.rt.handleDeath(context.Background())
	if p.stopped() != 0 { t.Fatal("already-dead process must not be stopped again") }
	if !bed.hasEvent(tor.EventTorProcessDied) { t.Fatal("process-died event missing") }
}

func TestTorConfluxAndResourceStatus(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "obfs4"}, Speed: config.TorSpeedConfig{Conflux: "throughput"}})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	bed.ctl.mu.Lock()
	joined := strings.Join(bed.ctl.setconfs, ",")
	bed.ctl.mu.Unlock()
	if !strings.Contains(joined, "ConfluxEnabled=1") || !strings.Contains(joined, "ConfluxClientUX=throughput") {
		t.Fatalf("conflux=%s", joined)
	}
	st := bed.rt.Status()
	if st.Resources.ConfluxUX != "throughput" { t.Fatalf("resources=%+v", st.Resources) }
}

func TestTorDirectEntryNoBridges(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "direct"}})
	bed.ensure()
	if bed.state() != StateEstablished { t.Fatalf("state=%s", bed.state()) }
}

func TestTorDisabledBuildRefused(t *testing.T) {
	cfg := config.NewConfig()
	cfg.System.Tor.Enabled = false
	if _, err := Build(&cfg, Options{}); err == nil { t.Fatal("disabled Build must refuse") }
}

func TestTorTorrcFileWritten(t *testing.T) {
	cleanupLeaksAfterStop(t)
	bed := newRuntimeTestBed(t, config.TorConfig{Entry: config.TorEntryConfig{Mode: "obfs4"}})
	bed.storeBridges(obfs4Line)
	bed.ensure()
	raw, err := os.ReadFile(filepath.Join(bed.dataDir, "torrc"))
	if err != nil { t.Fatal(err) }
	doc := string(raw)
	if !strings.Contains(doc, "ClientOnly 1") || !strings.Contains(doc, fmt.Sprintf("__OwningControllerProcess %d", os.Getpid())) {
		t.Fatalf("torrc content wrong:\n%s", doc)
	}
}
