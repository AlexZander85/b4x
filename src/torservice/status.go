package torservice

// Status projection + metric export (design §8.2 exportState, §9.5).

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/daniellavrushin/b4/config"

	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/transport/tor"
	"github.com/daniellavrushin/b4/transport/torscan"
)

// Status renders the API projection (nil-safe on stopped runtimes).
func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Status{
		Enabled:   r.cfg.Enabled,
		Running:   r.running,
		Listening: r.state == StateEstablished && r.socksAddr != "",
		State:     r.state,
		Hint:      r.hint,
		Entry: EntryView{
			Mode:   r.cfg.EffectiveEntryMode(),
			Active: entryRealName(r.entry),
			Winner: r.winner,
		},
		Bridges: BridgesView{
			Alive:       len(r.activeSet),
			ByTransport: countByTransport(r.activeSet),
			Source:      r.storeSource(),
			LastError:   r.lastCollectFail,
		},
		Bootstrap: BootstrapView{
			Progress: r.bootstrap.Progress,
			Tag:      r.bootstrap.Tag,
		},
		Egress: EgressView{
			Through: r.cfg.EffectiveEgressThrough(),
			Bait:    r.cfg.EffectiveBaitProfile(),
		},
		Exit: ExitView{
			IP:        r.exit.IP,
			Country:   r.exit.Country,
			IsTor:     r.exit.IsTor,
			CheckedAt: isoTime(r.exitAt),
		},
		Version: r.version,
		Events:  append([]tor.TorEvent(nil), r.events...),
	}
	return st
}

// exportState pushes the gauge vector (bounded, honest zeros — the series
// stay stable).
func (r *Runtime) exportState() {
	r.mu.Lock()
	state := r.state
	set := r.activeSet
	circuits := 0
	read, written := uint64(0), uint64(0)
	if r.ctl != nil && state == StateEstablished {
		if info, err := r.ctl.GetInfo("circuit-status", "traffic/read", "traffic/written"); err == nil {
			circuits = countCircuits(info["circuit-status"])
			read = parseBytes(info["traffic/read"])
			written = parseBytes(info["traffic/written"])
		}
	}
	byKind := countByTransport(set)
	r.mu.Unlock()

	met := observability.Default().Metrics
	met.Set(observability.MetricTorCircuitsAlive, nil, uint64(circuits))
	met.Set(observability.MetricTorBytesRead, nil, read)
	met.Set(observability.MetricTorBytesWritten, nil, written)
	for tr, n := range byKind {
		met.Set(observability.MetricTorBridgesAlive, map[string]string{"transport": tr}, uint64(n))
	}
}

// storeSource reads the store's source field (its own mutex — no deadlock
// against r.mu).
func (r *Runtime) storeSource() string {
	f, err := r.store.Load()
	if err != nil {
		return ""
	}
	return f.Source
}

// BridgeSource exposes the store's source field (API).
func (r *Runtime) BridgeSource() string { return r.storeSource() }

// RestartNow tears down and restarts from the winner (API endpoint).
func (r *Runtime) RestartNow(ctx context.Context) {
	r.teardown("manual-restart")
	r.restartFromWinner()
}

// Newnym rotates circuits (API endpoint).
func (r *Runtime) Newnym() error {
	r.mu.Lock()
	ctl := r.ctl
	r.mu.Unlock()
	if ctl == nil {
		return tor.ErrNotListening
	}
	if err := ctl.Signal("NEWNYM"); err != nil {
		return err
	}
	r.appendEvent(tor.TorEvent{Name: tor.EventTorRotated, Detail: "manual NEWNYM", At: r.opts.Now()})
	return nil
}

func countByTransport(set []tor.Bridge) map[string]int {
	if len(set) == 0 {
		return nil
	}
	out := map[string]int{}
	for _, b := range set {
		out[b.Transport]++
	}
	return out
}

func countCircuits(circuitStatus string) int {
	n := 0
	for _, line := range splitLines(circuitStatus) {
		if line != "" {
			n++
		}
	}
	return n
}

func parseBytes(v string) uint64 {
	var out uint64
	for _, c := range v {
		if c < '0' || c > '9' {
			continue
		}
		out = out*10 + uint64(c-'0')
	}
	return out
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func isoTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// SetEntry applies a new entry mode in memory and retires the current
// attempt (the ladder restarts from the new mode on the next ensure).
func (r *Runtime) SetEntry(mode string) {
	r.mu.Lock()
	r.cfg.Entry.Mode = mode
	r.entry = ""
	r.mixedTried = false
	_ = r.entryMem.Clear()
	r.mu.Unlock()
	r.teardown("entry-change")
}

// ValidEntryModes lists the accepted PUT /api/tor/entry values.
func ValidEntryModes() []string {
	return []string{
		config.TorEntryAuto, config.TorEntryWebtunnel, config.TorEntryObfs4,
		config.TorEntrySnowflake, config.TorEntryMeek, config.TorEntryVanilla,
		config.TorEntryDirect,
	}
}

// IsValidEntryMode validates one mode value.
func IsValidEntryMode(mode string) bool {
	switch mode {
	case config.TorEntryAuto, config.TorEntryWebtunnel, config.TorEntryObfs4,
		config.TorEntrySnowflake, config.TorEntryMeek, config.TorEntryVanilla,
		config.TorEntryDirect:
		return true
	}
	return false
}

// BridgesList projects the stored bridge file for the API.
func (r *Runtime) BridgesList() tor.BridgesFile {
	f, err := r.store.Load()
	if err != nil {
		return tor.BridgesFile{Schema: tor.BridgesFileSchema}
	}
	return f
}

// RefreshBridges forces one conveyor pass (API endpoint; bounded by the
// collector's own budgets).
func (r *Runtime) RefreshBridges(ctx context.Context) (tor.BridgesFile, error) {
	return r.collector.Collect(ctx, r.cfg.Bridges.BuiltinSnowflake, r.cfg.Bridges.Lines, r.cfg.EffectiveCountry(), r.cfg.Bridges.CollectURLs)
}

// ScanNow runs one bounded relay scan on demand (API/CLI endpoint). The
// scanner rides the egress dialer (bootstrap-source class — never through
// tor itself) and writes vanilla lines into the store when it finds any.
func (r *Runtime) ScanNow(ctx context.Context) (torscan.Result, error) {
	fetch := torscan.HTTPFetcher(&http.Client{Timeout: torscan.FetchTimeout})
	// the sources ride the egress dialer through a custom transport
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port := 0
			if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
				return nil, err
			}
			return r.dialer.Dial(ctx, tor.ClassBootstrapSrc, host, uint16(port))
		},
	}
	fetch = torscan.HTTPFetcher(&http.Client{Transport: tr, Timeout: torscan.FetchTimeout})
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port := 0
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			return nil, err
		}
		return r.dialer.Dial(ctx, tor.ClassBridgeVanilla, host, uint16(port))
	}
	s := torscan.NewScanner(fetch, dial)
	cfg := torscan.ScanConfig{
		Ports:     r.cfg.EffectiveScanPorts(),
		Countries: r.cfg.RelayScan.Countries,
		Goal:      r.cfg.EffectiveScanGoal(),
		Timeout:   time.Duration(r.cfg.EffectiveScanTimeoutSec()) * time.Second,
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 90 * time.Second
	}
	res, err := s.Scan(ctx, cfg, r.cfg.Bridges.CollectURLs, filepath.Join(r.cfg.EffectiveDataPath(), "onionoo-cache.json"))
	if err != nil {
		return res, err
	}
	// persist the vanilla lines into the store (merge with the old set)
	lines := res.BridgeLines()
	if len(lines) > 0 {
		prev, _ := r.store.Load()
		merged := map[string]bool{}
		for _, sb := range prev.Bridges {
			if sb.Transport == "vanilla" {
				merged[sb.Line] = true
			}
		}
		f := tor.BridgesFile{
			Schema:    tor.BridgesFileSchema,
			UpdatedAt: r.opts.Now().UnixMilli(),
			Source:    "relay-scan",
		}
		for line := range merged {
			f.Bridges = append(f.Bridges, tor.StoredBridge{Transport: "vanilla", Line: line})
		}
		for _, line := range lines {
			if _, ok := merged[line]; !ok {
				f.Bridges = append(f.Bridges, tor.StoredBridge{Transport: "vanilla", Line: line})
			}
		}
		if err := r.store.Save(f); err != nil {
			return res, fmt.Errorf("persist scan result: %w", err)
		}
		observability.Default().Metrics.Set(observability.MetricTorScanRelaysFound, nil, uint64(len(res.Relays)))
	}
	return res, nil
}
