package tor

// Bootstrap progress watcher (patch-plan §7.4, design §4.4 — the Nova
// bootstrap supervision canon): poll `GETINFO status/bootstrap-phase`
// once per second, fail the attempt when the PROGRESS value stalls for
// 150 s WITHOUT GROWTH (the honest stall signal — tor retries internally,
// a flat percentage is the observable) or the hard cap hits (180 s; the
// snowflake-only entry gets 300 s — a cold snowflake sits at 50% for 150 s
// by design). Ten SILENT polls (control errors) are their own failure
// reason: a dead control port must not masquerade as a slow bootstrap.
//
// Log discipline: one line per TAG change or +10 progress; an unchanged
// state repeats at most every 30 s (bounded chatter, honest progress).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/log"
)

// Bootstrap watcher constants (design §4.4).
const (
	BootstrapPollInterval = 1 * time.Second
	BootstrapStallWindow  = 150 * time.Second
	BootstrapHardCap      = 180 * time.Second
	BootstrapSnowflakeCap = 300 * time.Second
	BootstrapSilentMax    = 10
	bootstrapLogRepeat    = 30 * time.Second
)

// Entry names used at this layer (the config enums live in src/config —
// importing it from here would close a cycle).
const (
	entryVanilla   = "vanilla"
	entryDirect    = "direct"
	entrySnowflake = "snowflake"
)

// Bootstrap failure reasons (the failure taxonomy, kebab-case classes).
var (
	ErrBootstrapTimeout = errors.New("tor bootstrap hard cap")
	ErrBootstrapStall   = errors.New("tor bootstrap stalled (no progress growth)")
	ErrBootstrapSilent  = errors.New("tor bootstrap control silent")
)

// BootstrapPhase is one decoded poll result.
type BootstrapPhase struct {
	Progress int
	Tag      string
	Summary  string
	At       time.Time
}

// BootstrapConfig carries the watcher windows (tests shrink them; the
// production defaults follow design §4.4).
type BootstrapConfig struct {
	PollInterval time.Duration
	StallWindow  time.Duration
	HardCap      time.Duration
	SnowflakeCap time.Duration
	SilentMax    int
	LogRepeat    time.Duration
}

// DefaultBootstrapConfig is the production window set.
func DefaultBootstrapConfig() BootstrapConfig {
	return BootstrapConfig{
		PollInterval: BootstrapPollInterval,
		StallWindow:  BootstrapStallWindow,
		HardCap:      BootstrapHardCap,
		SnowflakeCap: BootstrapSnowflakeCap,
		SilentMax:    BootstrapSilentMax,
		LogRepeat:    bootstrapLogRepeat,
	}
}

// BootstrapWatch polls the control client until bootstrap reaches 100, the
// stall window lapses without growth, the hard cap hits, or the control
// goes silent. onPhase receives every poll (the caller decides event
// dedup). Production windows; see BootstrapWatchCfg for tests.
func BootstrapWatch(ctx context.Context, ctl ControlClient, entry string, now func() time.Time, onPhase func(BootstrapPhase)) (BootstrapPhase, error) {
	return BootstrapWatchCfg(ctx, ctl, entry, DefaultBootstrapConfig(), now, onPhase)
}

// BootstrapWatchCfg is the window-configurable watcher.
func BootstrapWatchCfg(ctx context.Context, ctl ControlClient, entry string, cfg BootstrapConfig, now func() time.Time, onPhase func(BootstrapPhase)) (BootstrapPhase, error) {
	if now == nil {
		now = time.Now
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = BootstrapPollInterval
	}
	hardCap := cfg.HardCap
	if entry == entrySnowflake && cfg.SnowflakeCap > hardCap {
		hardCap = cfg.SnowflakeCap
	}
	start := now()

	var last BootstrapPhase
	lastGrowth := start
	lastLog := start
	silent := 0

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return last, err
		}
		info, err := ctl.GetInfo("status/bootstrap-phase")
		if err != nil || info["status/bootstrap-phase"] == "" {
			silent++
			if silent >= cfg.SilentMax {
				return last, fmt.Errorf("%w: %d consecutive failed polls", ErrBootstrapSilent, silent)
			}
		} else {
			silent = 0
			p, tag, summary := ParseBootstrapPhase(info["status/bootstrap-phase"])
			ph := BootstrapPhase{Progress: p, Tag: tag, Summary: summary, At: now()}
			grew := ph.Progress > last.Progress
			tagChanged := ph.Tag != last.Tag && ph.Tag != ""
			if onPhase != nil && (grew || tagChanged || last.Tag == "") {
				onPhase(ph)
			}
			if grew {
				lastGrowth = ph.At
			}
			if shouldLogBootstrap(last, ph, lastLog) {
				log.Infof("[tor] bootstrap %d%% (%s) %s", ph.Progress, ph.Tag, ph.Summary)
				lastLog = ph.At
			}
			last = ph
			if ph.Progress >= 100 {
				return ph, nil
			}
		}

		nowAt := now()
		if hardCap > 0 && nowAt.Sub(start) >= hardCap {
			return last, fmt.Errorf("%w: %s entry, reached %d%%", ErrBootstrapTimeout, entry, last.Progress)
		}
		if lastGrowth != start && nowAt.Sub(lastGrowth) >= cfg.StallWindow {
			return last, fmt.Errorf("%w: %ds at %d%% (tag %s)", ErrBootstrapStall,
				int(nowAt.Sub(lastGrowth).Seconds()), last.Progress, last.Tag)
		}

		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-ticker.C:
		}
	}
}

// shouldLogBootstrap: tag change, +10 progress, or a 30 s repeat.
func shouldLogBootstrap(prev, cur BootstrapPhase, lastLog time.Time) bool {
	if prev.Tag == "" {
		return true
	}
	if cur.Tag != prev.Tag {
		return true
	}
	if cur.Progress >= prev.Progress+10 {
		return true
	}
	return cur.At.Sub(lastLog) >= bootstrapLogRepeat
}
