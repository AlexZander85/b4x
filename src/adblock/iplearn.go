// BLK-7 (addendum §BLK-8): kernel-level acceleration of repeat ad-blocks.
//
// The first SNI block of a domain enqueues (domain, dstIP, srcMAC, list) into
// a bounded channel — the packet hot path does NOTHING else (drop-on-full +
// counter). A single worker goroutine validates the candidate (private/
// reserved ranges), deduplicates, extends TTLs on repeat blocks, enforces the
// entry cap (oldest-expiry eviction) and materializes membership through the
// bound LearnApplier (src/tables backend: b4_adblock_learn set + drop rule
// ordered BEFORE the NFQUEUE capture rule).
//
// Red lines (addendum §BLK-8):
//   - never learn private/reserved/link-local/multicast/broadcast IPs;
//   - never learn IPs colliding with existing service sets (guard lives at
//     the NFQ hook site, which owns the matcher);
//   - allowlisted domains never teach (structural: Decide passes them) and
//     a later allowlisting purges previously learned entries;
//   - any table application failure is fail-open (log + counter; the SNI
//     layer keeps working through the NFQ decision point);
//   - disabling ip_learn fully tears the sublayer down (+ kernel set flush).
//
// Persistence follows the z2k#6 reassert pattern: the authoritative state is
// the in-process store; a best-effort snapshot lives next to the config
// (atomic 0600) and the kernel set is recreated/repopulated at startup and
// reasserted on every sweeper tick (kernel sets do not survive restarts and
// external table rebuilds).
package adblock

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

// LearnApplier is the kernel-side seam implemented by the tables package
// (iptables ipset / nftables set backends) and bound at startup. A nil
// applier means in-memory-only operation: guards, aging and metrics work,
// kernel materialization is skipped (fail-open posture).
type LearnApplier interface {
	// EnsureRules installs the learn set + drop rule pair idempotently.
	EnsureRules() error
	// AddIPs (re-)adds entries with a fresh timeout; re-adding an existing
	// IP extends its kernel lifetime (TTL extension on repeat blocks).
	AddIPs(ips []net.IP, ttlSec int) error
	// RemoveIPs drops entries (unknown entries are ignored).
	RemoveIPs(ips []net.IP) error
	// Flush clears every entry from the learn set.
	Flush() error
}

// LearnedEntry is one learned blocking fact (store + persist record).
type LearnedEntry struct {
	IP        string `json:"ip"`
	Domain    string `json:"domain"`
	List      string `json:"list"`
	LearnedAt int64  `json:"learned_at"` // unix seconds
	ExpiresAt int64  `json:"expires_at"` // unix seconds
}

type learnRequest struct {
	domain string
	ip     string // canonical string form (hot path clones; never aliases the packet buffer)
	mac    string
	list   string
}

const (
	learnQueueCap    = 256
	learnSweepEvery  = 60 * time.Second
	persistVersion   = 1
	persistFileName  = "iplearn.json"
	maxPersistBytes  = 4 << 20
	evictBatchRemove = 256
)

type learnRuntime struct {
	cfg        config.AdBlockConfig
	persist    string
	queue      chan learnRequest
	purge      chan struct{}
	reassert   chan struct{}
	done       chan struct{}
	finished   chan struct{}
	sweepEvery time.Duration
	now        func() time.Time

	mu      sync.Mutex
	entries map[string]*LearnedEntry
	dirty   bool
}

// Global sublayer state (mirrors the package's snapshot style).
var (
	learnRT      atomic.Pointer[learnRuntime]
	learnFP      atomic.Pointer[string]
	learnApplier atomic.Pointer[applierBox]
	refreshFunc  atomic.Pointer[refreshBox]

	learnTotal       atomic.Int64
	learnCDNSkip     atomic.Int64
	learnPrivateSkip atomic.Int64
	learnDropped     atomic.Int64
	learnApplyFails  atomic.Int64
)

type applierBox struct{ a LearnApplier }
type refreshBox struct{ f func() }

// SetLearnApplier binds the kernel-side backend (main.go wiring). Passing
// nil detaches it (in-memory mode).
func SetLearnApplier(a LearnApplier) {
	if a == nil {
		learnApplier.Store(nil)
		return
	}
	learnApplier.Store(&applierBox{a: a})
}

// SetRefreshTablesFunc binds the existing full-tables-refresh mechanism
// (TablesRefreshFunc closure). It is invoked ONCE on the disabled→enabled
// transition of ip_learn so capture-rule ordering is re-guaranteed and
// hardware offload windows get their coordinated reset on live systems.
func SetRefreshTablesFunc(f func()) {
	if f == nil {
		refreshFunc.Store(nil)
		return
	}
	refreshFunc.Store(&refreshBox{f: f})
}

func learnApply() LearnApplier {
	if b := learnApplier.Load(); b != nil {
		return b.a
	}
	return nil
}

func callRefreshTables(reason string) {
	if b := refreshFunc.Load(); b != nil {
		log.Infof("adblock: ip_learn transition (%s); requesting tables refresh", reason)
		b.f()
	}
}

// LearnEnabled reports whether the learn sublayer is currently running
// (cheap hot-path gate ahead of any matcher work).
func LearnEnabled() bool { return learnRT.Load() != nil }

// CountLearnCDNSkip records a skipped learn because the dst-IP matches an
// existing service set (shared CDN infrastructure; called at the NFQ hook).
func CountLearnCDNSkip() { learnCDNSkip.Add(1) }

// EnqueueLearn offers one blocking fact to the learn worker. Non-blocking:
// a full queue increments ip_learn_dropped_total and moves on. The hot path
// pays one IP-string allocation per BLOCKED flow, nothing per normal packet.
func EnqueueLearn(domain string, dst net.IP, srcMac, listName string) {
	rt := learnRT.Load()
	if rt == nil || dst == nil || domain == "" {
		return
	}
	req := learnRequest{domain: strings.ToLower(domain), ip: dst.String(), mac: srcMac, list: listName}
	select {
	case rt.queue <- req:
	default:
		learnDropped.Add(1)
	}
}

// RequestPurge asks the worker to drop every entry whose domain is no longer
// blocked (list removal / allowlisting / layer disable). Called after a
// successful Reload.
func RequestPurge() {
	rt := learnRT.Load()
	if rt == nil {
		return
	}
	select {
	case rt.purge <- struct{}{}:
	default: // worker busy; next sweeper pass re-evaluates anyway
	}
}

// RequestReassert asks the worker to immediately re-install rules and
// re-apply every live entry (z2k#6 self-heal). Bound to the tables layer's
// post-apply hook so external full-table rebuilds (config saves, link
// events) restore kernel acceleration within milliseconds instead of waiting
// for the next sweeper tick.
func RequestReassert() {
	rt := learnRT.Load()
	if rt == nil {
		return
	}
	select {
	case rt.reassert <- struct{}{}:
	default:
	}
}

// ConfigureLearn starts/stops/reconfigures the learn sublayer from config.
// Idempotent by fingerprint; safe to call on every config update. The
// disabled state fully tears the sublayer down including a kernel-set flush.
func ConfigureLearn(cfg config.AdBlockConfig, persistPath string) {
	cfg.FillDefaults()
	if !cfg.Enabled || !cfg.IPLearn {
		shutdownLearn()
		return
	}
	learnCfgMu.Lock()
	defer learnCfgMu.Unlock()
	fp := fmt.Sprintf("learn=%v|ttl=%d|max=%d|%s", cfg.IPLearn, cfg.IPLearnTTLSec, cfg.IPLearnMaxEntries, persistPath)
	if cur := learnFP.Load(); cur != nil && *cur == fp {
		return
	}

	wasOff := learnRT.Load() == nil
	stopRuntime(false) // superseded worker exits; kernel state kept for reuse

	rt := newLearnRuntime(cfg, persistPath)
	rt.loadPersist()
	learnFP.Store(&fp)
	learnRT.Store(rt)
	go rt.run()
	log.Infof("adblock: ip_learn enabled (ttl=%ds max=%d queue=%d)", cfg.IPLearnTTLSec, cfg.IPLearnMaxEntries, learnQueueCap)
	if wasOff {
		callRefreshTables("enabled")
	}
}

// learnCfgMu serializes ConfigureLearn/shutdownLearn so concurrent config
// updates cannot leak a worker goroutine between the fingerprint check and
// the runtime swap.
var learnCfgMu sync.Mutex

// shutdownLearn stops the worker, flushes the kernel set and removes the
// persist snapshot (the disabled state must leave no filtering residue).
func shutdownLearn() {
	learnCfgMu.Lock()
	defer learnCfgMu.Unlock()
	if learnRT.Load() == nil && learnFP.Load() == nil {
		return
	}
	stopRuntime(true)
	learnFP.Store(nil)
	log.Infof("adblock: ip_learn disabled")
}

// stopRuntime cancels the current worker and optionally flushes kernel
// state + persist file.
func stopRuntime(flush bool) {
	rt := learnRT.Swap(nil)
	if rt == nil {
		if flush {
			flushKernelAndPersist(nil)
		}
		return
	}
	close(rt.done)
	<-rt.finished // worker saves pending persist on exit
	if flush {
		flushKernelAndPersist(rt)
	}
}

func flushKernelAndPersist(rt *learnRuntime) {
	if a := learnApply(); a != nil {
		if err := a.Flush(); err != nil {
			learnApplyFails.Add(1)
			log.Warnf("adblock: ip_learn flush failed: %v", err)
		}
	}
	if rt != nil && rt.persist != "" {
		if err := os.Remove(rt.persist); err != nil && !os.IsNotExist(err) {
			log.Tracef("adblock: ip_learn persist remove: %v", err)
		}
	}
}

func newLearnRuntime(cfg config.AdBlockConfig, persistPath string) *learnRuntime {
	return &learnRuntime{
		cfg:        cfg,
		persist:    persistPath,
		queue:      make(chan learnRequest, learnQueueCap),
		purge:      make(chan struct{}, 1),
		reassert:   make(chan struct{}, 1),
		done:       make(chan struct{}),
		finished:   make(chan struct{}),
		sweepEvery: learnSweepEvery,
		now:        time.Now,
		entries:    make(map[string]*LearnedEntry, 64),
	}
}

func (rt *learnRuntime) run() {
	defer close(rt.finished)
	ticker := time.NewTicker(rt.sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-rt.done:
			rt.saveIfDirtyLocked()
			return
		case req := <-rt.queue:
			rt.handle(req)
		case <-rt.purge:
			rt.purgeUnblocked()
		case <-rt.reassert:
			rt.reassertKernel()
		case <-ticker.C:
			rt.sweep()
		}
	}
}

// reassertKernel re-installs rules and re-applies all live entries with
// fresh TTLs. Shared by the sweeper and the post-tables-rebuild hook.
func (rt *learnRuntime) reassertKernel() {
	a := learnApply()
	if a == nil {
		return
	}
	rt.mu.Lock()
	live := make([]net.IP, 0, len(rt.entries))
	now := rt.now().Unix()
	for key, e := range rt.entries {
		if e.ExpiresAt <= now {
			continue // aged; sweeper removes it from the store
		}
		if ip := net.ParseIP(key); ip != nil {
			live = append(live, ip)
		}
	}
	rt.mu.Unlock()

	if err := a.EnsureRules(); err != nil {
		learnApplyFails.Add(1)
		log.Warnf("adblock: ip_learn ensure rules failed (SNI layer unaffected): %v", err)
		return
	}
	if len(live) > 0 {
		rt.applyAdd(live)
	}
}

// isUnlearnableIP reports reserved address space that must never enter the
// kernel drop set: unspecified, loopback, private, link-local (v4+v6),
// multicast, broadcast, and IPv4-mapped forms thereof.
func isUnlearnableIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.IsUnspecified() || ip4.IsLoopback() || ip4.IsPrivate() ||
			ip4.IsLinkLocalUnicast() || ip4.IsLinkLocalMulticast() ||
			ip4.IsMulticast() || ip4.Equal(net.IPv4bcast)
	}
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast()
}

func (rt *learnRuntime) handle(req learnRequest) {
	ip := net.ParseIP(req.ip)
	if ip == nil {
		return
	}
	if isUnlearnableIP(ip) {
		learnPrivateSkip.Add(1)
		return
	}
	ttl := rt.cfg.IPLearnTTLSec
	now := rt.now().Unix()

	rt.mu.Lock()
	if cur, ok := rt.entries[req.ip]; ok {
		// Repeat block: extend lifetime, refresh attribution.
		cur.ExpiresAt = now + int64(ttl)
		cur.Domain = req.domain
		cur.List = req.list
		rt.dirty = true
		rt.mu.Unlock()
		rt.applyAdd([]net.IP{ip})
		return
	}

	if rt.cfg.IPLearnMaxEntries > 0 && len(rt.entries) >= rt.cfg.IPLearnMaxEntries {
		if victim := oldestEntryLocked(rt.entries); victim != nil {
			delete(rt.entries, victim.IP)
			rt.mu.Unlock()
			log.Infof("adblock: ip_learn cap %d reached; evicted %s (%s)", rt.cfg.IPLearnMaxEntries, victim.IP, victim.Domain)
			rt.applyRemove([]net.IP{net.ParseIP(victim.IP)})
			rt.mu.Lock()
		}
	}

	rt.entries[req.ip] = &LearnedEntry{
		IP:        req.ip,
		Domain:    req.domain,
		List:      req.list,
		LearnedAt: now,
		ExpiresAt: now + int64(ttl),
	}
	rt.dirty = true
	rt.mu.Unlock()

	learnTotal.Add(1)
	log.Infof("adblock: ip_learn %s (%s) ttl=%ds", req.ip, req.domain, ttl)
	rt.applyAdd([]net.IP{ip})
}

func oldestEntryLocked(entries map[string]*LearnedEntry) *LearnedEntry {
	var oldest *LearnedEntry
	for _, e := range entries {
		if oldest == nil || e.ExpiresAt < oldest.ExpiresAt {
			oldest = e
		}
	}
	return oldest
}

// purgeUnblocked drops entries whose domain is no longer honestly blocked:
// removed/disabled lists, later allowlisting, or a fully disabled layer.
func (rt *learnRuntime) purgeUnblocked() {
	s := snap.Load()
	layerActive := s != nil && enabledFlag.Load()

	var remove []*LearnedEntry
	rt.mu.Lock()
	for key, e := range rt.entries {
		keep := false
		if layerActive && !s.allow.match(e.Domain) && s.block.match(e.Domain) {
			keep = true
		}
		if !keep {
			remove = append(remove, e)
			delete(rt.entries, key)
			rt.dirty = true
		}
	}
	rt.mu.Unlock()

	if len(remove) == 0 {
		return
	}
	ips := make([]net.IP, 0, len(remove))
	for _, e := range remove {
		if ip := net.ParseIP(e.IP); ip != nil {
			ips = append(ips, ip)
		}
	}
	log.Infof("adblock: ip_learn unlearn %d entr%s (sources changed)", len(remove), plural(len(remove)))
	rt.applyRemove(ips)
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// sweep ages out expired entries, then delegates rule/entry reassertion to
// reassertKernel (z2k#6 self-heal against external table rebuilds and
// timeout drift) and persists pending changes.
func (rt *learnRuntime) sweep() {
	now := rt.now().Unix()

	rt.mu.Lock()
	var expired []*LearnedEntry
	for key, e := range rt.entries {
		if e.ExpiresAt <= now {
			expired = append(expired, e)
			delete(rt.entries, key)
			rt.dirty = true
		}
	}
	rt.mu.Unlock()

	if len(expired) > 0 {
		ips := make([]net.IP, 0, len(expired))
		for _, e := range expired {
			if ip := net.ParseIP(e.IP); ip != nil {
				ips = append(ips, ip)
			}
		}
		log.Infof("adblock: ip_learn aged out %d entr%s", len(expired), plural(len(expired)))
		rt.applyRemove(ips)
	}

	rt.reassertKernel()
	rt.saveIfDirtyLocked()
}

func (rt *learnRuntime) applyAdd(ips []net.IP) {
	a := learnApply()
	if a == nil {
		return
	}
	if err := a.AddIPs(ips, rt.cfg.IPLearnTTLSec); err != nil {
		learnApplyFails.Add(1)
		log.Warnf("adblock: ip_learn add failed (fail-open; SNI layer unaffected): %v", err)
	}
}

func (rt *learnRuntime) applyRemove(ips []net.IP) {
	a := learnApply()
	if a == nil {
		return
	}
	if err := a.RemoveIPs(ips); err != nil {
		learnApplyFails.Add(1)
		log.Warnf("adblock: ip_learn remove failed: %v", err)
	}
}

// ---- persistence (best-effort z2k#6 snapshot, atomic 0600) ----

type learnPersistFile struct {
	Version int            `json:"version"`
	Entries []LearnedEntry `json:"entries"`
}

func (rt *learnRuntime) loadPersist() {
	if rt.persist == "" {
		return
	}
	blob, err := os.ReadFile(rt.persist)
	if err != nil {
		return // absent = clean first-run path
	}
	if len(blob) > maxPersistBytes {
		log.Warnf("adblock: ip_learn persist oversized (%d bytes); ignoring", len(blob))
		return
	}
	var pf learnPersistFile
	if err := json.Unmarshal(blob, &pf); err != nil || pf.Version != persistVersion {
		log.Warnf("adblock: ip_learn persist unparsable; starting empty")
		return
	}
	now := rt.now().Unix()
	rt.mu.Lock()
	for _, e := range pf.Entries {
		if e.IP == "" || net.ParseIP(e.IP) == nil || e.Domain == "" {
			continue
		}
		if e.ExpiresAt <= now {
			continue // aged out while we were down
		}
		cp := e
		rt.entries[e.IP] = &cp
	}
	rt.mu.Unlock()
	log.Infof("adblock: ip_learn restored %d persisted entries", len(pf.Entries))
}

func (rt *learnRuntime) saveIfDirtyLocked() {
	rt.mu.Lock()
	dirty := rt.dirty
	rt.dirty = false
	snapshotLen := len(rt.entries)
	entries := make([]LearnedEntry, 0, snapshotLen)
	for _, e := range rt.entries {
		entries = append(entries, *e)
	}
	rt.mu.Unlock()

	if !dirty && rt.persist != "" {
		if _, err := os.Stat(rt.persist); err == nil {
			return
		}
	}
	if rt.persist == "" || !dirty {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].IP < entries[j].IP })
	pf := learnPersistFile{Version: persistVersion, Entries: entries}
	blob, err := json.Marshal(pf)
	if err != nil {
		return
	}
	if err := writeAtomic0600(rt.persist, blob); err != nil {
		log.Warnf("adblock: ip_learn persist save failed: %v", err)
	}
}

// writeAtomic0600 writes blob transactionally: temp file in the same
// directory, 0600 (mandatory on the Linux target), fsync, rename. Mirrors
// the transport/fxvpn secret-file discipline.
func writeAtomic0600(path string, blob []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}
	if _, err := tmp.Write(blob); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("fsync %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// PersistPathFor returns the learn-snapshot location next to the config
// (inside the adblock cache directory).
func PersistPathFor(cacheDir string) string {
	if cacheDir == "" {
		return ""
	}
	return filepath.Join(cacheDir, persistFileName)
}

// LearnedEntries returns a stable snapshot of live entries (status export).
func LearnedEntries() []LearnedEntry {
	rt := learnRT.Load()
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]LearnedEntry, 0, len(rt.entries))
	for _, e := range rt.entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// learnStats is the metrics view of the sublayer (embedded into Stats).
type learnStats struct {
	LearnTotal       int64 `json:"ip_learn_total"`
	LearnCDNSkip     int64 `json:"ip_learn_cdn_skip_total"`
	LearnPrivateSkip int64 `json:"ip_learn_private_skip_total"`
	LearnDropped     int64 `json:"ip_learn_dropped_total"`
	LearnActive      int64 `json:"ip_active_gauge"`
	TableApplyFail   int64 `json:"table_apply_fail_total"`
}

func currentLearnStats() learnStats {
	st := learnStats{
		LearnTotal:       learnTotal.Load(),
		LearnCDNSkip:     learnCDNSkip.Load(),
		LearnPrivateSkip: learnPrivateSkip.Load(),
		LearnDropped:     learnDropped.Load(),
		TableApplyFail:   learnApplyFails.Load(),
	}
	if rt := learnRT.Load(); rt != nil {
		rt.mu.Lock()
		st.LearnActive = int64(len(rt.entries))
		rt.mu.Unlock()
	}
	return st
}

// StopLearn is the shutdown counterpart of ConfigureLearn (persists pending
// changes; kernel state intentionally left to the tables teardown owner).
func StopLearn() {
	learnCfgMu.Lock()
	defer learnCfgMu.Unlock()
	stopRuntime(false)
}
