// BLK-7 verification: hot-path enqueue semantics, guards, aging, capping,
// unlearn lifecycle and persistence discipline of the IP-learn sublayer
// (addendum §BLK-8). All kernel interaction goes through a recording fake;
// time is injected, so every aging scenario is deterministic.
package adblock

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

// recordingApplier captures every kernel-side operation.
type recordingApplier struct {
	mu      sync.Mutex
	added   map[string]int // ip -> last ttl seen
	removed map[string]bool
	flushes int
	ensures int
	failAdd bool
}

func newRecordingApplier() *recordingApplier {
	return &recordingApplier{added: map[string]int{}, removed: map[string]bool{}}
}

func (r *recordingApplier) EnsureRules() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensures++
	return nil
}

func (r *recordingApplier) AddIPs(ips []net.IP, ttlSec int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failAdd {
		return errFakeApply
	}
	for _, ip := range ips {
		r.added[ip.String()] = ttlSec
	}
	return nil
}

var errFakeApply = errors.New("fake apply failure")

func (r *recordingApplier) RemoveIPs(ips []net.IP) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ip := range ips {
		r.removed[ip.String()] = true
		delete(r.added, ip.String())
	}
	return nil
}

func (r *recordingApplier) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushes++
	r.added = map[string]int{}
	return nil
}

func (r *recordingApplier) addedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.added)
}

func (r *recordingApplier) ttlOf(ip string) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.added[ip]
	return v, ok
}

// newTestRuntime wires an isolated runtime against a fake clock without
// starting its goroutine (deterministic direct-drive testing).
func newTestRuntime(t *testing.T, ttl, max int, now func() time.Time) (*learnRuntime, *recordingApplier) {
	t.Helper()
	cfg := config.AdBlockConfig{
		Enabled:           true,
		IPLearn:           true,
		IPLearnTTLSec:     ttl,
		IPLearnMaxEntries: max,
	}
	rt := newLearnRuntime(cfg, filepath.Join(t.TempDir(), "iplearn.json"))
	rt.now = now
	ap := newRecordingApplier()
	SetLearnApplier(ap)
	t.Cleanup(func() {
		SetLearnApplier(nil)
		learnRT.Store(nil)
		learnFP.Store(nil)
	})
	learnRT.Store(rt)
	return rt, ap
}

func drainQueue(rt *learnRuntime) {
	for {
		select {
		case req := <-rt.queue:
			rt.handle(req)
		default:
			return
		}
	}
}

func fixedClock(start time.Time) func() time.Time {
	cur := start
	var mu sync.Mutex
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return cur
	}
}

func advanceClock(fn func() time.Time, d time.Duration) func() time.Time {
	// The fixedClock closure keeps internal state; wrap to shift reads.
	base := fn()
	return func() time.Time { return base.Add(d) }
}

func resetLearnCounters() {
	learnTotal.Store(0)
	learnCDNSkip.Store(0)
	learnPrivateSkip.Store(0)
	learnDropped.Store(0)
	learnApplyFails.Store(0)
}

func TestLearnBasicEnqueueAppliesWithTTL(t *testing.T) {
	resetLearnCounters()
	now := time.Unix(1_000_000, 0)
	rt, ap := newTestRuntime(t, 600, 100, fixedClock(now))

	ip := net.ParseIP("93.184.216.34")
	EnqueueLearn("ads.example.com", ip, "AA:BB:CC:DD:EE:FF", "block")
	drainQueue(rt)

	if got := learnTotal.Load(); got != 1 {
		t.Fatalf("ip_learn_total=%d want 1", got)
	}
	ttl, ok := ap.ttlOf("93.184.216.34")
	if !ok || ttl != 600 {
		t.Fatalf("kernel add missing or wrong ttl: %v %d", ok, ttl)
	}
	if st := GetStats(); st.IPLearnActive != 1 {
		t.Fatalf("active gauge=%d want 1", st.IPLearnActive)
	}
}

func TestLearnHotPathClonesIPItNeverAliasesPacketBuffer(t *testing.T) {
	resetLearnCounters()
	rt, _ := newTestRuntime(t, 600, 100, fixedClock(time.Unix(1_000_000, 0)))

	buf := make([]byte, 4)
	copy(buf, net.ParseIP("1.2.3.4").To4())
	EnqueueLearn("ads.example.com", net.IP(buf), "", "block")
	copy(buf, net.ParseIP("9.9.9.9").To4()) // mutate the "packet buffer"

	drainQueue(rt)
	if _, ok := rt.entries["1.2.3.4"]; !ok {
		t.Fatalf("entry must record the IP value at enqueue time, got %v", rt.entries)
	}
}

func TestLearnRepeatBlockExtendsExpiry(t *testing.T) {
	resetLearnCounters()
	now := time.Unix(1_000_000, 0)
	clock := fixedClock(now)
	rt, ap := newTestRuntime(t, 600, 100, func() time.Time { return clock() })

	ip := net.ParseIP("93.184.216.34")
	EnqueueLearn("ads.example.com", ip, "", "block")
	drainQueue(rt)

	clock = advanceClock(clock, 300*time.Second)
	rt.now = func() time.Time { return clock() }
	EnqueueLearn("ads.example.com", ip, "", "block")
	drainQueue(rt)

	rt.mu.Lock()
	e := rt.entries["93.184.216.34"]
	rt.mu.Unlock()
	want := clock().Unix() + 600
	if e == nil || e.ExpiresAt != want {
		t.Fatalf("expiry=%v want %d", e, want)
	}
	if got := learnTotal.Load(); got != 1 {
		t.Fatalf("repeat block must not double-count learn total: %d", got)
	}
	if _, ok := ap.ttlOf("93.184.216.34"); !ok {
		t.Fatal("kernel timeout must be refreshed on repeat block")
	}
}

func TestLearnRejectsReservedRanges(t *testing.T) {
	resetLearnCounters()
	rt, ap := newTestRuntime(t, 600, 100, fixedClock(time.Unix(1_000_000, 0)))

	for _, s := range []string{
		"192.168.1.10", "10.0.0.5", "172.16.0.9", "127.0.0.1",
		"169.254.1.1", "224.0.0.251", "255.255.255.255", "0.0.0.0",
		"fe80::1", "ff02::fb", "::1",
	} {
		before := learnPrivateSkip.Load()
		EnqueueLearn("ads.example.com", net.ParseIP(s), "", "block")
		drainQueue(rt)
		if got := learnPrivateSkip.Load(); got != before+1 {
			t.Fatalf("%s must be counted as private skip (delta=%d)", s, got-before)
		}
		if _, ok := rt.entries[s]; ok {
			t.Fatalf("%s must never be learned", s)
		}
	}
	if ap.addedCount() != 0 {
		t.Fatal("no reserved IP may reach the kernel applier")
	}
}

func TestLearnCapEvictsOldestExpiry(t *testing.T) {
	resetLearnCounters()
	now := time.Unix(1_000_000, 0)
	clock := fixedClock(now)
	rt, ap := newTestRuntime(t, 600, 2, func() time.Time { return clock() })

	add := func(ip string) {
		EnqueueLearn("ads.example.com", net.ParseIP(ip), "", "block")
		drainQueue(rt)
	}
	add("1.1.1.1") // expires first
	clock = advanceClock(clock, 10*time.Second)
	rt.now = func() time.Time { return clock() }
	add("2.2.2.2")
	clock = advanceClock(clock, 10*time.Second)
	rt.now = func() time.Time { return clock() }
	add("3.3.3.3") // cap hit: 1.1.1.1 (oldest expiry) must go

	if _, gone := ap.ttlOf("1.1.1.1"); gone {
		t.Fatal("oldest entry must be evicted")
	}
	for _, keep := range []string{"2.2.2.2", "3.3.3.3"} {
		if _, ok := ap.ttlOf(keep); !ok {
			t.Fatalf("%s must survive eviction", keep)
		}
	}
	if len(rt.entries) != 2 {
		t.Fatalf("store size=%d want 2", len(rt.entries))
	}
}

func TestLearnQueueOverflowIncrementsDropped(t *testing.T) {
	resetLearnCounters()
	rt, _ := newTestRuntime(t, 600, 100, fixedClock(time.Unix(1_000_000, 0)))

	before := learnDropped.Load()
	for i := 0; i < learnQueueCap+50; i++ {
		EnqueueLearn("ads.example.com", net.ParseIP("8.8.8.8"), "", "block")
	}
	if got := learnDropped.Load() - before; got < 1 {
		t.Fatalf("overflow must increment dropped counter, delta=%d", got)
	}
	drainQueue(rt)
}

func TestSweepAgesExpiredAndReassertsLive(t *testing.T) {
	resetLearnCounters()
	now := time.Unix(1_000_000, 0)
	clock := fixedClock(now)
	rt, ap := newTestRuntime(t, 600, 100, func() time.Time { return clock() })

	EnqueueLearn("a.ads.example.com", net.ParseIP("1.1.1.1"), "", "block")
	EnqueueLearn("b.ads.example.com", net.ParseIP("2.2.2.2"), "", "block")
	drainQueue(rt)

	clock = advanceClock(clock, 700*time.Second) // both expired by now
	rt.now = func() time.Time { return clock() }
	EnqueueLearn("c.ads.example.com", net.ParseIP("3.3.3.3"), "", "block")
	drainQueue(rt)
	rt.sweep()

	if !ap.removed["1.1.1.1"] || !ap.removed["2.2.2.2"] {
		t.Fatal("expired entries must be removed from the kernel set")
	}
	if len(rt.entries) != 1 {
		t.Fatalf("store must keep only live entries, got %d", len(rt.entries))
	}
	if ap.ensures == 0 {
		t.Fatal("sweep must re-ensure rules before reasserting entries")
	}
	if ttl, ok := ap.ttlOf("3.3.3.3"); !ok || ttl != 600 {
		t.Fatalf("live entry must be reasserted with fresh TTL, got %d %v", ttl, ok)
	}
}

func TestSweepApplyFailureIsFailOpenAndCounted(t *testing.T) {
	resetLearnCounters()
	rt, ap := newTestRuntime(t, 600, 100, fixedClock(time.Unix(1_000_000, 0)))
	ap.failAdd = true

	before := learnApplyFails.Load()
	rt.applyAdd([]net.IP{net.ParseIP("1.1.1.1")})
	if learnApplyFails.Load() == before {
		t.Fatal("apply failure must increment table_apply_fail_total")
	}
	// Entry handling continues: SNI layer unaffected (fail-open red line).
	if st := GetStats(); st.TableApplyFail < 1 {
		t.Fatal("stats must surface the failure")
	}
}

func TestPurgeUnblockedAfterListChange(t *testing.T) {
	resetLearnCounters()
	listPath := writeFile(t, "blocked.example.com\nother.example.org\n")
	Reload(config.AdBlockConfig{
		Enabled: true,
		Lists:   []config.AdBlockList{{Source: listPath, Enabled: true}},
	})
	rt, ap := newTestRuntime(t, 600, 100, fixedClock(time.Unix(1_000_000, 0)))

	seed := func(ip, domain string) {
		EnqueueLearn(domain, net.ParseIP(ip), "", "block")
		drainQueue(rt)
	}
	seed("1.1.1.1", "blocked.example.com") // still blocked -> kept
	seed("2.2.2.2", "removed.example.net") // never blocked -> purged
	seed("3.3.3.3", "other.example.org")   // blocked now...

	// ...but a reload that drops the whole list must purge everything.
	listPath2 := writeFile(t, "unrelated.example\n")
	Reload(config.AdBlockConfig{
		Enabled: true,
		Lists:   []config.AdBlockList{{Source: listPath2, Enabled: true}},
	})
	rt.purgeUnblocked()

	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if _, ok := rt.entries[ip]; ok {
			t.Fatalf("%s must be unlearned after its domain lost blocking", ip)
		}
		if !ap.removed[ip] {
			t.Fatalf("%s must be removed from the kernel set", ip)
		}
	}
	if len(rt.entries) != 0 {
		t.Fatalf("all entries must be gone, got %d", len(rt.entries))
	}
}

func TestAllowlistedDomainPurgesLearnedEntry(t *testing.T) {
	resetLearnCounters()
	blockPath := writeFile(t, "doubleclick.net\n")
	allowPath := writeFile(t, "")
	Reload(config.AdBlockConfig{
		Enabled:   true,
		Lists:     []config.AdBlockList{{Source: blockPath, Enabled: true}},
		Allowlist: []string{allowPath},
	})
	rt, _ := newTestRuntime(t, 600, 100, fixedClock(time.Unix(1_000_000, 0)))
	EnqueueLearn("ads.doubleclick.net", net.ParseIP("4.4.4.4"), "", "block")
	drainQueue(rt)
	if _, ok := rt.entries["4.4.4.4"]; !ok {
		t.Fatal("precondition: entry learned")
	}

	allowPath2 := writeFile(t, "doubleclick.net\n")
	Reload(config.AdBlockConfig{
		Enabled:   true,
		Lists:     []config.AdBlockList{{Source: blockPath, Enabled: true}},
		Allowlist: []string{allowPath2},
	})
	rt.purgeUnblocked()

	if _, ok := rt.entries["4.4.4.4"]; ok {
		t.Fatal("allowlisted domain must not keep a learned entry")
	}
}

func TestConfigureLearnLifecycleDisableFlushesAndCleansPersist(t *testing.T) {
	resetLearnCounters()
	dir := t.TempDir()
	persist := filepath.Join(dir, "adblock", "iplearn.json")

	ap := newRecordingApplier()
	SetLearnApplier(ap)
	t.Cleanup(func() {
		SetLearnApplier(nil)
		learnRT.Store(nil)
		learnFP.Store(nil)
	})

	on := config.AdBlockConfig{Enabled: true, IPLearn: true}
	ConfigureLearn(on, persist)
	if !LearnEnabled() {
		t.Fatal("learn must run when enabled")
	}

	off := config.AdBlockConfig{Enabled: false, IPLearn: true}
	ConfigureLearn(off, persist)
	if LearnEnabled() {
		t.Fatal("disabled layer must fully stop the sublayer")
	}
	if ap.flushes == 0 {
		t.Fatal("disable must flush the kernel set")
	}
	if _, err := os.Stat(persist); !os.IsNotExist(err) {
		t.Fatalf("disable must remove the persist snapshot, stat err=%v", err)
	}
}

func TestConfigureLearnIdempotentSameFingerprint(t *testing.T) {
	resetLearnCounters()
	persist := filepath.Join(t.TempDir(), "iplearn.json")
	SetLearnApplier(newRecordingApplier())
	t.Cleanup(func() {
		SetLearnApplier(nil)
		learnRT.Store(nil)
		learnFP.Store(nil)
	})

	cfg := config.AdBlockConfig{Enabled: true, IPLearn: true, IPLearnTTLSec: 600}
	ConfigureLearn(cfg, persist)
	rt1 := learnRT.Load()
	ConfigureLearn(cfg, persist)
	if learnRT.Load() != rt1 {
		t.Fatal("same fingerprint must not restart the worker")
	}

	cfg.IPLearnTTLSec = 1200
	ConfigureLearn(cfg, persist)
	if learnRT.Load() == rt1 {
		t.Fatal("changed fingerprint must restart the worker")
	}
	if LearnEnabled() != true || learnRT.Load().cfg.IPLearnTTLSec != 1200 {
		t.Fatal("reconfigured TTL must take effect")
	}
	StopLearn()
}

func TestPersistRoundTripFiltersExpired(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	persist := filepath.Join(t.TempDir(), "iplearn.json")

	writer := newLearnRuntime(config.AdBlockConfig{Enabled: true, IPLearn: true}, persist)
	writer.now = fixedClock(now)
	writer.entries["5.5.5.5"] = &LearnedEntry{IP: "5.5.5.5", Domain: "x.example", List: "block",
		LearnedAt: now.Unix(), ExpiresAt: now.Unix() + 600}
	writer.entries["6.6.6.6"] = &LearnedEntry{IP: "6.6.6.6", Domain: "y.example", List: "block",
		LearnedAt: now.Unix() - 9999, ExpiresAt: now.Unix() - 1} // expired
	writer.dirty = true
	writer.saveIfDirtyLocked()

	reader := newLearnRuntime(config.AdBlockConfig{Enabled: true, IPLearn: true}, persist)
	reader.now = fixedClock(now)
	reader.loadPersist()

	if _, ok := reader.entries["5.5.5.5"]; !ok {
		t.Fatal("live entry must survive persistence round trip")
	}
	if _, ok := reader.entries["6.6.6.6"]; ok {
		t.Fatal("expired entry must not be restored")
	}
	info, err := os.Stat(persist)
	if err != nil {
		t.Fatalf("persist file missing: %v", err)
	}
	if runtime.GOOS == "linux" && info.Mode().Perm() != 0o600 {
		t.Fatalf("persist file mode=%v want 0600", info.Mode().Perm())
	}
}

func TestCDNSkipCounterHookContract(t *testing.T) {
	resetLearnCounters()
	CountLearnCDNSkip()
	if learnCDNSkip.Load() != 1 {
		t.Fatalf("cdn skip=%d want 1", learnCDNSkip.Load())
	}
	if st := GetStats(); st.IPLearnCDNSkip != 1 {
		t.Fatalf("stats cdn skip=%d want 1", st.IPLearnCDNSkip)
	}
}

func TestLearnDisabledByDefaultInConfig(t *testing.T) {
	var cfg config.AdBlockConfig
	cfg.FillDefaults()
	if cfg.IPLearn {
		t.Fatal("ip_learn must default to false (conservative)")
	}
	if cfg.IPLearnTTLSec != config.DefaultIPLearnTTLSec || cfg.IPLearnMaxEntries != config.DefaultIPLearnMaxEntries {
		t.Fatalf("defaults drifted: ttl=%d max=%d", cfg.IPLearnTTLSec, cfg.IPLearnMaxEntries)
	}
}
