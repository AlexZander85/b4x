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

// normalizeListLine converts one raw list line into a lowercase domain
// entry. Accepted forms:
//   - plain "domain", trailing dots trimmed;
//   - hosts lines ("0.0.0.0 domain", "::1 domain");
//   - ABP/uBlock network rules "||domain^" and ".domain^" suffix form,
//     including "$modifier" tails (rule dropped conservatively when it
//     carries options we cannot express: regexes, wildcards).
//
// Comments (#/!), "@@" exceptions and unparsable lines yield ok=false.
func normalizeListLine(raw string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return "", false
	}
	if strings.HasPrefix(line, "@@") {
		return "", false
	}
	// ABP network rule family.
	if strings.HasPrefix(line, "||") {
		rest := line[2:]
		if i := strings.IndexAny(rest, "^$"); i >= 0 {
			rest = rest[:i]
		}
		rest = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rest)), ".")
		if rest == "" || strings.ContainsAny(rest, "*/?") {
			return "", false // regex/wildcard/path-bound rule: unsupported
		}
		return rest, true
	}
	if strings.HasPrefix(line, "/") {
		return "", false // raw regex rule: unsupported
	}
	fields := strings.Fields(line)
	switch len(fields) {
	case 1:
		line = fields[0]
	case 2:
		line = fields[1] // hosts format: resolver-ip domain
	default:
		return "", false
	}
	line = strings.TrimPrefix(line, ".")
	if i := strings.IndexAny(line, "^$"); i >= 0 {
		line = line[:i] // ABP anchor/options tail on plain-suffix rules
	}
	domain := strings.ToLower(strings.TrimSuffix(line, "."))
	if domain == "" || strings.ContainsAny(domain, "^$*") {
		return "", false
	}
	return domain, true
}

// parseListFile reads domains/hosts-format lines into the matcher.
func parseListFile(path string, maxEntries int) (*matcher, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	m := newMatcher(nameFromPath(path))
	sc := bufio.NewScanner(f)
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
		return nil, 0, fmt.Errorf("scan %s: %w", path, err)
	}
	return m, m.entries, nil
}

func nameFromPath(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 && i+1 < len(path) {
		return path[i+1:]
	}
	if i := strings.LastIndexByte(path, '\\'); i >= 0 && i+1 < len(path) {
		return path[i+1:]
	}
	return path
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
		m, n, err := parseListFile(p, cfg.MaxEntries)
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
		m, n, err := parseListFile(p, cfg.MaxEntries)
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
	FetchOK      int64
	FetchFail    int64
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
		FetchOK:      fetchOK.Load(),
		FetchFail:    fetchFail.Load(),
		Enabled:      enabledFlag.Load(),
	}
}
