package torservice

// Status projection + metric export (design §8.2 exportState, §9.5).

import (
	"context"
	"time"

	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/transport/tor"
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
