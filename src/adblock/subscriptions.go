// BLK-5: URL subscriptions with auto-refresh. Downloads are bounded
// (size-limit + timeout), validated before activation, atomically renamed,
// and never run on the packet hot path. A failed download keeps the previous
// active matcher (fail-open red line).
package adblock

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

const (
	fetchTimeout    = 60 * time.Second
	defaultCacheDir = "adblock"
)

var (
	fetchOK   atomic.Int64
	fetchFail atomic.Int64
)

func isURL(entry string) bool {
	return strings.HasPrefix(entry, "http://") || strings.HasPrefix(entry, "https://")
}

// splitLists separates enabled subscription URLs from enabled local files.
func splitLists(lists []config.AdBlockList) (urls, locals []config.AdBlockList) {
	for _, l := range lists {
		if !l.Enabled || strings.TrimSpace(l.Source) == "" {
			continue
		}
		if isURL(l.Source) {
			urls = append(urls, l)
		} else {
			locals = append(locals, l)
		}
	}
	return urls, locals
}

func CachePathFor(cacheDir, url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(cacheDir, "sub-"+hex.EncodeToString(sum[:12])+".domains")
}

// resolveCacheDir returns the effective cache directory for the config path.
func ResolveCacheDir(cfg config.AdBlockConfig, configPath string) string {
	if cfg.CacheDir != "" {
		return cfg.CacheDir
	}
	if configPath != "" {
		return filepath.Join(filepath.Dir(configPath), defaultCacheDir)
	}
	return filepath.Join(os.TempDir(), defaultCacheDir)
}

func maxBytesInBytes(maxEntries int) int {
	if maxEntries <= 0 {
		maxEntries = config.DefaultMaxListEntries
	}
	// ~64 bytes per entry is a generous ceiling for domains-format lines.
	return maxEntries * 64
}

func nameOf(url string) string {
	if i := strings.LastIndexByte(url, '/'); i >= 0 && i+1 < len(url) {
		return url[i+1:]
	}
	return url
}

// fetchToFile downloads url into dest via temp+rename with a hard size cap.
// The body is parsed (and therefore validated) BEFORE the rename.
func fetchToFile(client *http.Client, url, dest string, maxEntries int) error {
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("cache dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".fetch-*")
	if err != nil {
		return fmt.Errorf("temp: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(tmpName)
		}
	}()

	m := newMatcher(nameOf(url))
	sc := bufio.NewScanner(io.LimitReader(resp.Body, int64(maxBytesInBytes(maxEntries))))
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for sc.Scan() {
		domain, ok := normalizeListLine(sc.Text())
		if !ok {
			continue
		}
		if !m.add(domain) {
			continue
		}
		if maxEntries > 0 && m.entries >= maxEntries {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if m.entries == 0 {
		return fmt.Errorf("empty or unparsable list")
	}
	for d := range m.domains {
		fmt.Fprintln(tmp, d)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	ok = true
	return nil
}

var refState struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	fp     string
}

// DefaultSubscriptions are the built-in subscription URLs used when the
// layer is enabled without explicit lists (owner request 25.08). Every URL
// was verified live at inclusion time; formats must stay within the parser
// envelope (ABP network rules / hosts / plain domains).
//
//  1. AdGuard DNS filter (HostlistsRegistry hosts mirror): global base,
//     daily rebuilds, already includes regional ad networks.
//  2. AdGuard Russian filter: RU-specific ads/trackers.
//  3. StevenBlack unified hosts: independent second opinion baseline.
var DefaultSubscriptions = []string{
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
	"https://filters.adtidy.org/extension/chromium/filters/1.txt",
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
}

// resolveLists applies the default subscriptions when the layer is enabled
// with an empty list set. Explicit user lists always win.
func resolveLists(cfg config.AdBlockConfig) []config.AdBlockList {
	if len(cfg.Lists) == 0 {
		out := make([]config.AdBlockList, 0, len(DefaultSubscriptions))
		for _, u := range DefaultSubscriptions {
			out = append(out, config.AdBlockList{Source: u, Enabled: true})
		}
		return out
	}
	return cfg.Lists
}

// ApplyConfig is the single entry point from config updates: manages the
// subscription refresher lifecycle, the IP-learn sublayer (BLK-7) and applies
// the current lists. Safe to call from every worker/config update —
// internally idempotent.
func ApplyConfig(cfg config.AdBlockConfig, cacheDir, configPath string) {
	cfg.FillDefaults()
	cfg.Lists = resolveLists(cfg)
	if cacheDir == "" {
		cacheDir = ResolveCacheDir(cfg, configPath)
	}
	// Kernel-acceleration sublayer lifecycle (idempotent by fingerprint;
	// fully torn down incl. kernel-set flush when disabled).
	ConfigureLearn(cfg, PersistPathFor(cacheDir))
	interval := time.Duration(cfg.RefreshHours) * time.Hour
	urls, _ := splitLists(cfg.Lists)
	sources := make([]string, 0, len(urls))
	for _, u := range urls {
		sources = append(sources, u.Source)
	}
	wantRefresher := cfg.Enabled && len(urls) > 0
	fp := fmt.Sprintf("%v|%s|%d|%s", cfg.Enabled, cacheDir, cfg.RefreshHours, strings.Join(sources, ">"))

	refState.mu.Lock()
	switch {
	case !wantRefresher:
		if refState.cancel != nil {
			refState.cancel()
			refState.cancel, refState.fp = nil, ""
		}
		refState.mu.Unlock()
		Reload(effectiveConfig(cfg, cacheDir))
		return
	case refState.cancel != nil && refState.fp == fp:
		refState.mu.Unlock()
		return // same subscription set already refreshing
	case refState.cancel != nil:
		refState.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	refState.cancel, refState.fp = cancel, fp
	refState.mu.Unlock()

	go subscriptionLoop(ctx, cfg, cacheDir, interval)
	log.Infof("adblock: subscription refresher started (%d URL(s), interval %s)", len(urls), interval)
}

// effectiveConfig substitutes every enabled URL entry with its cache-file
// path (disabled entries dropped) so Reload only ever touches local files.
func effectiveConfig(cfg config.AdBlockConfig, cacheDir string) config.AdBlockConfig {
	urls, locals := splitLists(cfg.Lists)
	if len(urls) == 0 && len(locals) == len(cfg.Lists) {
		return cfg
	}
	out := cfg
	out.Lists = make([]config.AdBlockList, 0, len(locals)+len(urls))
	for _, l := range locals {
		out.Lists = append(out.Lists, config.AdBlockList{Source: l.Source, Enabled: true})
	}
	for _, u := range urls {
		out.Lists = append(out.Lists, config.AdBlockList{
			Source:  CachePathFor(cacheDir, u.Source),
			Enabled: true,
		})
	}
	return out
}

// StopRefresher cancels any running subscription refresh loop and the
// IP-learn worker (shutdown and tests), persisting pending learn state.
// The active matcher snapshot is left untouched.
func StopRefresher() {
	refState.mu.Lock()
	if refState.cancel != nil {
		refState.cancel()
		refState.cancel, refState.fp = nil, ""
	}
	refState.mu.Unlock()
	StopLearn()
}

// subscriptionLoop applies immediately, then re-checks per interval.
// interval<=0 means "download once when missing" — the loop parks on ctx
// after the first pass instead of spinning.
func subscriptionLoop(ctx context.Context, cfg config.AdBlockConfig, cacheDir string, interval time.Duration) {
	client := &http.Client{Timeout: fetchTimeout}
	for {
		refreshSubscriptions(client, cfg, cacheDir, interval, false)
		if interval <= 0 {
			<-ctx.Done()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// refreshSubscriptions fetches every missing/stale subscription (or ALL of
// them when force is set), then reloads against the effective set. Failures
// keep previous files.
func refreshSubscriptions(client *http.Client, cfg config.AdBlockConfig, cacheDir string, interval time.Duration, force bool) {
	urls, _ := splitLists(cfg.Lists)
	for _, sub := range urls {
		u := sub.Source
		dest := CachePathFor(cacheDir, u)
		need := force
		if !need {
			if st, err := os.Stat(dest); err != nil {
				need = true // first run: no cached copy yet
			} else if interval > 0 && time.Since(st.ModTime()) > interval {
				need = true
			}
		}
		if !need {
			continue
		}
		if err := fetchToFile(client, u, dest, cfg.MaxEntries); err != nil {
			fetchFail.Add(1)
			log.Warnf("adblock: subscription %s failed: %v (keeping previous)", nameOf(u), err)
			continue
		}
		fetchOK.Add(1)
		log.Infof("adblock: subscription %s updated", nameOf(u))
	}
	Reload(effectiveConfig(cfg, cacheDir))
}

// ForceRefresh synchronously re-downloads every enabled subscription,
// ignoring freshness, then reloads. Intended for the manual "refresh lists"
// UI action — call from a goroutine, never the hot path.
func ForceRefresh(cfg config.AdBlockConfig, cacheDir string) {
	cfg.FillDefaults()
	cfg.Lists = resolveLists(cfg)
	refreshSubscriptions(&http.Client{Timeout: fetchTimeout}, cfg, ResolveCacheDir(cfg, cacheDir), time.Hour, true)
}
