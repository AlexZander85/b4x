// Package adblock implements the SNI ad/tracker blocking layer
// (B4X_POST_V23_SNI_ADBLOCK_LAYER_ADDENDUM_v1.0.md): domain-list loading and
// the per-flow Decide() called from the NFQ pipeline at ClientHello /
// QUIC-Initial time only.
//
// Red lines: fail-open to disabled on any list error (never block-all); one
// decision per flow; no DNS interaction; ECH-only flows are counted as
// skipped, never blocked by their outer public name.
package adblock

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

type Decision uint8

const (
	DecisionPass Decision = iota
	DecisionBlock
)

func (d Decision) String() string {
	if d == DecisionBlock {
		return "block"
	}
	return "pass"
}

// matcher holds one domain set with classic sinkhole semantics: a listed
// domain matches itself and every subdomain via trailing-label walk.
type matcher struct {
	domains map[string]struct{}
	entries int
	name    string
}

func newMatcher(name string) *matcher {
	return &matcher{domains: make(map[string]struct{}, 1024), name: name}
}

func (m *matcher) add(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return false
	}
	if _, exists := m.domains[domain]; !exists {
		m.domains[domain] = struct{}{}
		m.entries++
	}
	return true
}

// match walks host labels right-to-left: "ads.example.com" checks
// "ads.example.com", "example.com", "com".
func (m *matcher) match(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for h != "" {
		if _, ok := m.domains[h]; ok {
			return true
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 || dot == len(h)-1 {
			return false
		}
		h = h[dot+1:]
	}
	return false
}

// snapshot is an immutable matcher pair swapped atomically on reload.
type snapshot struct {
	block *matcher
	allow *matcher
}

var (
	mu          sync.Mutex // serializes Reload calls
	snap        atomic.Pointer[snapshot]
	digest      atomic.Pointer[string] // config+files fingerprint of active snapshot
	enabledFlag atomic.Bool

	blockedTotal   atomic.Int64
	passTotal      atomic.Int64
	echSkipped     atomic.Int64
	allowlisted    atomic.Int64
	listMissing    atomic.Int64
	listInvalid    atomic.Int64
	reloadFailures atomic.Int64
)

// fileFingerprint fingerprints path set + size+mtime of each existing file so
// UpdateConfig can call Reload repeatedly without re-reading unchanged files.
func fileFingerprint(cfg config.AdBlockConfig) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("e=%v;a=%v;m=%d;", cfg.Enabled, cfg.Action, cfg.MaxEntries))
	appendPaths := func(paths []string) {
		for _, p := range paths {
			sb.WriteString(p)
			sb.WriteByte('|')
			if st, err := os.Stat(p); err == nil {
				fmt.Fprintf(&sb, "%d:%d;", st.Size(), st.ModTime().UnixNano())
			} else {
				sb.WriteString("missing;")
			}
		}
	}
	appendPaths(cfg.Lists)
	sb.WriteByte('>')
	appendPaths(cfg.Allowlist)
	return sb.String()
}

// parseListFile reads domains/hosts-format lines into the matcher.
// Accepted: "domain", "#comment", "!comment", hosts lines "0.0.0.0 domain",
// "::1 domain". "@@" exceptions are ignored with a warning count.
func parseListFile(path string, maxEntries int) (*matcher, int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	name := path
	m := newMatcher(name)
	warnExceptions := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if strings.HasPrefix(line, "@@") {
			warnExceptions++
			continue
		}
		fields := strings.Fields(line)
		switch len(fields) {
		case 1:
			// bare domain
		case 2:
			// hosts format: resolver-ip domain (take the domain field)
			line = fields[1]
		default:
			continue
		}
		if !m.add(line) {
			continue
		}
		if maxEntries > 0 && m.entries >= maxEntries {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, 0, warnExceptions, fmt.Errorf("scan %s: %w", path, err)
	}
	return m, m.entries, warnExceptions, nil
}

// Reload (re)builds the active snapshot from cfg. Idempotent: an unchanged
// fingerprint short-circuits before any IO. On total failure the previous
// snapshot stays active; if none exists, the layer stays disabled
// (fail-open red line).
func Reload(cfg config.AdBlockConfig) {
	cfg.FillDefaults()
	fp := fileFingerprint(cfg)
	if cur := digest.Load(); cur != nil && *cur == fp {
		return
	}

	mu.Lock()
	defer mu.Unlock()
	// Double-check under lock: another caller may have loaded this config.
	if cur := digest.Load(); cur != nil && *cur == fp {
		return
	}

	if !cfg.Enabled || len(cfg.Lists) == 0 {
		if cfg.Enabled && len(cfg.Lists) == 0 {
			listMissing.Add(1)
			log.Warnf("adblock: enabled but no lists configured; layer disabled")
		}
		disableWithFingerprint(fp)
		return
	}

	block := newMatcher("block")
	loadedAny := false
	for _, p := range cfg.Lists {
		m, n, _, err := parseListFile(p, cfg.MaxEntries)
		if err != nil {
			listInvalid.Add(1)
			log.Warnf("adblock: list %s invalid: %v", p, err)
			continue
		}
		block.domains = mergeInto(block.domains, m)
		loadedAny = true
		log.Infof("adblock: loaded %s (%d entries)", p, n)
	}
	allow := newMatcher("allow")
	for _, p := range cfg.Allowlist {
		m, n, _, err := parseListFile(p, cfg.MaxEntries)
		if err != nil {
			listInvalid.Add(1)
			log.Warnf("adblock: allowlist %s invalid: %v", p, err)
			continue
		}
		allow.domains = mergeInto(allow.domains, m)
		loadedAny = true
		log.Infof("adblock: loaded allowlist %s (%d entries)", p, n)
	}

	if !loadedAny {
		reloadFailures.Add(1)
		log.Warnf("adblock: no list could be loaded; layer disabled")
		disableWithFingerprint(fp)
		return
	}

	ns := &snapshot{block: block, allow: allow}
	snap.Store(ns)
	enabledFlag.Store(true)
	fpCopy := fp
	digest.Store(&fpCopy)
	log.Infof("adblock: active (%d block entries, %d allow entries)",
		block.entries, allow.entries)
}

func disableWithFingerprint(fp string) {
	snap.Store(&snapshot{block: newMatcher("block"), allow: newMatcher("allow")})
	enabledFlag.Store(false)
	fpCopy := fp
	digest.Store(&fpCopy)
}

func mergeInto(dst map[string]struct{}, m *matcher) map[string]struct{} {
	for d := range m.domains {
		dst[d] = struct{}{}
	}
	return dst
}

// Decide classifies one hostname. Allowlist wins over blocklists. The second
// return value names the matching list ("allow"/"block") when blocked or
// explicitly allowed.
func Decide(host string) (Decision, string) {
	s := snap.Load()
	if s == nil || !enabledFlag.Load() {
		passTotal.Add(1)
		return DecisionPass, ""
	}
	if s.allow.match(host) {
		allowlisted.Add(1)
		passTotal.Add(1)
		return DecisionPass, "allow"
	}
	if s.block.match(host) {
		blockedTotal.Add(1)
		return DecisionBlock, "block"
	}
	passTotal.Add(1)
	return DecisionPass, ""
}

// CountECHSkip records a flow whose real SNI is hidden behind ECH and which
// therefore cannot be evaluated honestly.
func CountECHSkip() { echSkipped.Add(1) }

// Stats returns current counters (metrics export).
type Stats struct {
	BlockedTotal int64
	PassTotal    int64
	ECHSkipped   int64
	Allowlisted  int64
	ListMissing  int64
	ListInvalid  int64
	ReloadFailed int64
	Enabled      bool
}

func GetStats() Stats {
	return Stats{
		BlockedTotal: blockedTotal.Load(),
		PassTotal:    passTotal.Load(),
		ECHSkipped:   echSkipped.Load(),
		Allowlisted:  allowlisted.Load(),
		ListMissing:  listMissing.Load(),
		ListInvalid:  listInvalid.Load(),
		ReloadFailed: reloadFailures.Load(),
		Enabled:      enabledFlag.Load(),
	}
}
