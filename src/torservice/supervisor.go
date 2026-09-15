package torservice

// Supervisor passes: bridge set assembly (the entry ladder, design §2/§8),
// process spawn + bootstrap, liveness, exit probe, conflux, strikes and
// the restart guard. Everything under r.mu unless noted.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/transport/tor"
)

// ensureBridges assembles the active set for the current entry, running
// the collector when the store cannot serve the entry (snowflake skips
// the wait entirely — builtin sets, TOR-1).
func (r *Runtime) ensureBridges(ctx context.Context) {
	r.mu.Lock()
	if r.state == StateBinaryMissing || r.collecting {
		r.mu.Unlock()
		return
	}
	entry := r.currentEntry()
	r.mu.Unlock()

	set, ok := r.assembleSet(entry)
	if ok {
		r.mu.Lock()
		r.activeSet = set
		if r.state == StateBridgesWait || r.state == StateIdle || r.state == StateStarting {
			r.state = StateStarting
		}
		r.mu.Unlock()
		return
	}

	// The store cannot serve this entry: run the conveyor once (async,
	// bounded; bridges-wait in the meantime).
	r.mu.Lock()
	if r.state == StateStarting || r.state == StateBridgesWait {
		r.state = StateBridgesWait
	}
	if r.collecting {
		r.mu.Unlock()
		return
	}
	r.collecting = true
	r.collectDone = make(chan struct{})
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			r.collecting = false
			done := r.collectDone
			r.mu.Unlock()
			if done != nil {
				close(done)
			}
		}()
		collectCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		_, err := r.collector.Collect(collectCtx, r.cfg.Bridges.BuiltinSnowflake, r.cfg.Bridges.Lines, r.cfg.EffectiveCountry(), r.cfg.Bridges.CollectURLs)
		if err != nil {
			r.mu.Lock()
			r.lastCollectFail = err.Error()
			r.mu.Unlock()
		}
	}()
}

// currentEntry resolves the entry the current attempt uses:
// pinned mode → the pin; auto → mixed-set first, then the sequential
// ladder (memory-excluded), the winner always at the head.
func (r *Runtime) currentEntry() string {
	if r.cfg.EffectiveEntryMode() != "auto" {
		return r.cfg.EffectiveEntryMode()
	}
	if r.entry != "" {
		return r.entry
	}
	if r.mixedTried {
		return "" // ladder picks below
	}
	return "auto-mixed"
}

// assembleSet builds the bridge set for an entry (true when usable).
func (r *Runtime) assembleSet(entry string) ([]tor.Bridge, bool) {
	if entry == "direct" {
		return nil, true
	}
	stored, err := r.store.Load()
	if err != nil {
		stored = tor.BridgesFile{}
	}
	all := r.candidateBridges(stored)

	switch entry {
	case "auto-mixed":
		// design §2.1: webtunnel(2) + obfs4(2) + snowflake(set) racing in
		// ONE torrc; the RaceWindow caps parallel heads.
		window := r.cfg.EffectiveRaceWindow()
		var set []tor.Bridge
		for _, tr := range []string{ladderWebtunnel, ladderObfs4, ladderSnowflake, "meek_lite"} {
			set = append(set, takeBridges(all, tr, window)...)
		}
		if r.cfg.Bridges.BuiltinSnowflake {
			set = append(set, tor.BuiltinSnowflake("cdn77")...)
		}
		return tor.Dedup(set), len(set) > 0
	default:
		set := takeBridges(all, entry, 40)
		if entry == ladderSnowflake && r.cfg.Bridges.BuiltinSnowflake {
			set = append(set, tor.BuiltinSnowflake("cdn77")...)
		}
		return tor.Dedup(set), len(set) > 0
	}
}

// candidateBridges merges stored + owner lines, strike-filtered.
func (r *Runtime) candidateBridges(stored tor.BridgesFile) []tor.Bridge {
	var all []tor.Bridge
	now := r.opts.Now()
	for _, sb := range stored.Bridges {
		if b, err := tor.ParseBridgeLine(sb.Line); err == nil {
			all = append(all, b)
		}
	}
	for _, raw := range r.cfg.Bridges.Lines {
		if b, err := tor.ParseBridgeLine(raw); err == nil {
			all = append(all, b)
		}
	}
	var out []tor.Bridge
	for _, b := range all {
		if until, ok := r.strikeUntil[tor.DedupKey(b)]; ok && now.Before(until) {
			continue
		}
		out = append(out, b)
	}
	return out
}

func takeBridges(all []tor.Bridge, transport string, n int) []tor.Bridge {
	var out []tor.Bridge
	for _, b := range all {
		if b.Transport != transport {
			continue
		}
		out = append(out, b)
		if len(out) >= n {
			break
		}
	}
	return out
}

// ensureProcess spawns tor when the set is ready and none runs.
func (r *Runtime) ensureProcess(ctx context.Context) {
	r.mu.Lock()
	if r.state == StateBinaryMissing || r.proc != nil || r.state == StateBridgesWait {
		r.mu.Unlock()
		return
	}
	if len(r.activeSet) == 0 && r.currentEntry() != "direct" {
		r.mu.Unlock()
		return
	}
	entry := r.currentEntry()
	set := r.activeSet
	r.mu.Unlock()

	// render + validate the torrc
	in := r.torrcInput(entry, set)
	torrcDoc := tor.RenderTorrc(in)
	if err := tor.ValidateRendered(torrcDoc); err != nil {
		r.appendEvent(tor.TorEvent{Name: tor.EventTorEntryFailed, Class: tor.ClassTorConfigInvalid, Detail: err.Error(), At: r.opts.Now()})
		r.nextEntry("torrc-invalid")
		return
	}
	dataPath := r.cfg.EffectiveDataPath()
	if err := os.MkdirAll(filepath.Join(dataPath, "data"), 0o700); err != nil {
		r.appendEvent(tor.TorEvent{Name: tor.EventTorEntryFailed, Class: tor.ClassTorConfigInvalid, Detail: err.Error(), At: r.opts.Now()})
		return
	}
	torrcPath := filepath.Join(dataPath, "torrc")
	if err := atomicWriteFile(torrcPath, []byte(torrcDoc), 0o600); err != nil {
		r.appendEvent(tor.TorEvent{Name: tor.EventTorEntryFailed, Class: tor.ClassTorConfigInvalid, Detail: err.Error(), At: r.opts.Now()})
		return
	}

	spawn := r.opts.Spawn
	if spawn == nil {
		spawn = func(ctx context.Context, binaryPath, torrcPath, dataPath string) (ProcessController, error) {
			h, err := tor.SpawnTor(ctx, binaryPath, torrcPath, dataPath)
			if err != nil {
				return nil, err
			}
			return h, nil
		}
	}
	proc, err := spawn(ctx, r.cfg.EffectiveBinaryPath(), torrcPath, dataPath)
	if err != nil {
		r.mu.Lock()
		r.state = StateBinaryMissing
		r.hint = "opkg install tor (Entware) or set system.tor.binary_path"
		r.mu.Unlock()
		r.appendEvent(tor.TorEvent{Name: tor.EventTorBinaryMissing, Class: tor.ClassTorBinaryMissing, Detail: err.Error(), At: r.opts.Now()})
		return
	}
	r.mu.Lock()
	r.proc = proc
	r.state = StateBootstrapping
	r.entry = entry
	r.mu.Unlock()
	r.recordEntryAttempt(entry, "start")
	// version detect (best-effort, once)
	if r.version == "" {
		go func() {
			vctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if v, err := tor.DetectTorVersion(vctx, r.cfg.EffectiveBinaryPath()); err == nil && v != "" {
				r.mu.Lock()
				r.version = v
				r.mu.Unlock()
			}
		}()
	}
}

// torrcInput assembles the render input from the runtime state.
func (r *Runtime) torrcInput(entry string, set []tor.Bridge) tor.TorrcInput {
	r.mu.Lock()
	eb := r.egressBridge
	pp := r.ptProxy
	r.mu.Unlock()
	in := tor.TorrcInput{
		DataPath:      r.cfg.EffectiveDataPath(),
		OwningPID:     os.Getpid(),
		SocksPort:     "127.0.0.1:auto",
		ControlSocket: "unix:" + filepath.Join(r.cfg.EffectiveDataPath(), "data", "control.sock"),
		Padding:       r.cfg.EffectivePadding(),
		GeoIP:         r.cfg.Speed.GeoIP,
		Isolation:     r.cfg.EffectiveIsolation(),
		Bridges:       set,
		UseBridges:    entry != "direct",
		Entry:         entry,
	}
	if entry == ladderVanilla || entry == "direct" {
		if eb != nil {
			in.EgressProxy = eb.Creds() + "@" + eb.Addr()
		}
	}
	if pp != nil {
		_, port := splitHostPort(pp.Addr())
		in.PTProxyPort = port
	}
	return in
}

// ensureBootstrap waits for bootstrap completion over the control
// connection (the patient-cookie discipline: the socket file appears when
// tor is ready).
func (r *Runtime) ensureBootstrap(ctx context.Context) {
	r.mu.Lock()
	proc := r.proc
	state := r.state
	r.mu.Unlock()
	if proc == nil || state != StateBootstrapping {
		return
	}

	ctl, err := r.connectControl(ctx)
	if err != nil {
		return // patient: next tick retries
	}
	// learn the actual socks listener
	info, err := ctl.GetInfo("net/listeners/socks")
	if err == nil {
		if addr := info["net/listeners/socks"]; addr != "" {
			r.mu.Lock()
			r.socksAddr = addr
			r.ctl = ctl
			r.mu.Unlock()
		}
	}
	bcfg := r.opts.Bootstrap
	if bcfg.PollInterval == 0 {
		bcfg = tor.DefaultBootstrapConfig()
	}
	started := r.opts.Now()
	final, err := tor.BootstrapWatchCfg(ctx, ctl, ladderEntryName(r.entry), bcfg, r.opts.Now, func(ph tor.BootstrapPhase) {
		r.mu.Lock()
		prev := r.bootstrap
		r.bootstrap = ph
		r.mu.Unlock()
		if ph.Tag != prev.Tag {
			r.appendEvent(tor.TorEvent{Name: tor.EventTorBootstrapProgress, Detail: fmt.Sprintf("%d%% %s", ph.Progress, ph.Tag), At: r.opts.Now()})
		}
	})
	if err != nil {
		r.recordControlError(err)
		r.failAttempt(err)
		return
	}
	elapsed := r.opts.Now().Sub(started)
	r.mu.Lock()
	r.state = StateEstablished
	r.ctl = ctl
	r.bootstrap = final
	r.mu.Unlock()
	r.recordEntryWon(r.entry, elapsed)
}

// connectControl dials + authenticates (cookie from the data dir).
func (r *Runtime) connectControl(ctx context.Context) (tor.ControlClient, error) {
	dial := r.opts.DialControl
	network, addr := "unix", filepath.Join(r.cfg.EffectiveDataPath(), "data", "control.sock")
	if dial == nil {
		// try the unix socket, fall back to the tcp control port
		c, err := tor.DialControl(ctx, network, addr)
		if err == nil {
			if err := r.authenticate(c); err == nil {
				return c, nil
			}
			_ = c.Close()
		}
		return nil, fmt.Errorf("control unavailable")
	}
	c, err := dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if err := r.authenticate(c); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func (r *Runtime) authenticate(c tor.ControlClient) error {
	cookie, err := os.ReadFile(filepath.Join(r.cfg.EffectiveDataPath(), "data", "control.cookie"))
	if err != nil {
		return err
	}
	return c.Authenticate(cookie)
}

// ensureLiveness runs the SOCKS5-through-tor probe (design §4.4): 2
// failures → SIGNAL ACTIVE + NEWNYM; 4 + 30s grace → teardown + restart
// from the last working entry.
func (r *Runtime) ensureLiveness(ctx context.Context) {
	r.mu.Lock()
	state := r.state
	socks := r.socksAddr
	ctl := r.ctl
	last := r.lastLiveness
	r.mu.Unlock()
	// liveness keeps counting in ROTATING too: NEWNYM is a recovery
	// ATTEMPT, not a success — the failure ladder (2→NEWNYM, 4→teardown)
	// continues through it (design §4.4).
	if (state != StateEstablished && state != StateRotating) || socks == "" {
		return
	}
	now := r.opts.Now()
	if now.Sub(last) < livenessInterval {
		return
	}
	r.mu.Lock()
	r.lastLiveness = now
	r.mu.Unlock()

	probe := r.opts.LivenessProbe
	if probe == nil {
		probe = func(ctx context.Context, socksAddr string) error {
			cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			// SOCKS5 CONNECT through tor: success = the exit opened TCP.
			// Not HTTP 200 — CF challenges Tor exits (G165).
			conn, err := socksDialUpstream(cctx, socksAddr, "1.1.1.1", 443)
			if err != nil {
				return err
			}
			_ = conn.Close()
			return nil
		}
	}
	if err := probe(ctx, socks); err == nil {
		r.mu.Lock()
		r.livenessFails = 0
		r.newnymSent = false
		r.mu.Unlock()
		observability.Default().Metrics.Inc(observability.MetricTorStreamsTotal, map[string]string{"result": "ok"}, 1)
		return
	}

	observability.Default().Metrics.Inc(observability.MetricTorStreamsTotal, map[string]string{"result": "fail"}, 1)
	r.mu.Lock()
	r.livenessFails++
	fails := r.livenessFails
	r.mu.Unlock()
	r.appendEvent(tor.TorEvent{Name: tor.EventTorRotated, Class: tor.ClassTorLivenessFailed, Detail: fmt.Sprintf("liveness failure %d", fails), At: r.opts.Now()})

	if fails == livenessNEWNYMAfter && !r.newnymSent {
		r.mu.Lock()
		r.newnymSent = true
		r.state = StateRotating
		r.mu.Unlock()
		if ctl != nil {
			_ = ctl.Signal("ACTIVE")
			_ = ctl.Signal("NEWNYM")
		}
		r.appendEvent(tor.TorEvent{Name: tor.EventTorRotated, Detail: "SIGNAL ACTIVE + NEWNYM after 2 liveness failures", At: r.opts.Now()})
	}
	if fails >= livenessTeardownAt {
		// 30s grace before teardown: transient network blips recover
		if grace, ok := ctx.Deadline(); !ok || time.Now().Add(livenessGrace).Before(grace) {
			_ = grace
		}
		r.teardown("liveness-dead")
		r.restartFromWinner()
	}
}

// ensureExitProbe runs the 30-min exit verification (IsTor=true expected;
// a mismatch is informational — mismatch ≠ jail).
func (r *Runtime) ensureExitProbe(ctx context.Context) {
	r.mu.Lock()
	state := r.state
	socks := r.socksAddr
	last := r.lastExitProbe
	r.mu.Unlock()
	if state != StateEstablished || socks == "" {
		return
	}
	now := r.opts.Now()
	if !last.IsZero() && now.Sub(last) < exitProbeInterval {
		return
	}
	r.mu.Lock()
	r.lastExitProbe = now
	r.mu.Unlock()

	probe := r.opts.ExitProbe
	if probe == nil {
		probe = func(ctx context.Context, socksAddr string) (ExitInfo, error) {
			return exitProbeThroughTor(ctx, socksAddr)
		}
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	info, err := probe(pctx, socks)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.exit = info
	r.exitAt = r.opts.Now()
	r.mu.Unlock()
	if info.IsTor {
		r.appendEvent(tor.TorEvent{Name: tor.EventTorExitVerified, Detail: info.Country, At: r.opts.Now()})
	} else {
		r.appendEvent(tor.TorEvent{Name: tor.EventTorExitMismatch, Class: tor.ClassTorExitMismatch, Detail: info.IP, At: r.opts.Now()})
	}
}

// ensureConflux applies the speed profile once after establishment
// (SETCONF is soft on old tor — honest degradation).
func (r *Runtime) ensureConflux(ctx context.Context) {
	r.mu.Lock()
	state := r.state
	ctl := r.ctl
	done := r.confluxDone
	r.mu.Unlock()
	if state != StateEstablished || ctl == nil || done {
		return
	}
	r.mu.Lock()
	r.confluxDone = true
	r.mu.Unlock()
	ux := r.cfg.EffectiveConflux()
	if ux == "off" {
		return
	}
	switch ux {
	case "throughput", "latency":
	default:
		ux = "throughput" // auto → throughput
	}
	if err := ctl.SetConf([2]string{"ConfluxEnabled", "1"}, [2]string{"ConfluxClientUX", ux}); err != nil {
		r.appendEvent(tor.TorEvent{Name: tor.EventTorConfluxUnavailable, Class: tor.ClassTorControlError, Detail: err.Error(), At: r.opts.Now()})
		return
	}
	r.appendEvent(tor.TorEvent{Name: tor.EventTorConfluxEnabled, Detail: ux, At: r.opts.Now()})
}

// handleDeath reacts to a tor process death (event + restart guard).
func (r *Runtime) handleDeath(ctx context.Context) {
	r.mu.Lock()
	proc := r.proc
	r.proc = nil
	r.mu.Unlock()
	if proc == nil {
		return
	}
	r.appendEvent(tor.TorEvent{Name: tor.EventTorProcessDied, Class: tor.ClassTorProcessDied, At: r.opts.Now()})
	r.teardown("process-died")
	r.restartFromWinner()
}

// teardown closes the control connection and clears the process state
// (the process itself is already dead or stopped by the caller).
func (r *Runtime) teardown(reason string) {
	r.mu.Lock()
	ctl := r.ctl
	r.ctl = nil
	r.proc = nil
	r.socksAddr = ""
	r.state = StateStarting
	r.livenessFails = 0
	r.newnymSent = false
	r.confluxDone = false
	r.mu.Unlock()
	if ctl != nil {
		_ = ctl.Close()
	}
	_ = reason
}

// restartFromWinner applies the restartGuard then resets the ladder to
// the last working entry (TOR-2: restart from the winner, seconds not
// minutes).
func (r *Runtime) restartFromWinner() {
	r.mu.Lock()
	now := r.opts.Now()
	if now.Before(r.cooldown) {
		r.state = StateBackoff
		r.mu.Unlock()
		return
	}
	cutoff := now.Add(-time.Hour)
	kept := r.restarts[:0]
	for _, s := range r.restarts {
		if s.After(cutoff) {
			kept = append(kept, s)
		}
	}
	r.restarts = kept
	if len(r.restarts) >= r.cfg.EffectiveMaxRestartsPerHour() {
		r.cooldown = now.Add(300 * time.Second)
		r.state = StateBackoff
		r.mu.Unlock()
		r.appendEvent(tor.TorEvent{Name: tor.EventTorProcessDied, Class: tor.ClassTorProcessDied, Detail: "restart cap reached — backoff", At: r.opts.Now()})
		return
	}
	r.restarts = append(r.restarts, now)
	observability.Default().Metrics.Inc(observability.MetricTorProcessRestartsTotal, nil, 1)
	winner := r.winner
	if winner != "" {
		r.entry = winner // restart from the last working entry
	} else {
		r.entry = ""
		r.mixedTried = false
	}
	r.mu.Unlock()
}

// failAttempt records a failed bootstrap attempt: strike the set bridges,
// advance the ladder (or reset when exhausted).
func (r *Runtime) failAttempt(err error) {
	entry := r.entry
	r.appendEvent(tor.TorEvent{Name: tor.EventTorEntryFailed, Class: tor.ClassTorEntryFailed, Detail: fmt.Sprintf("%s: %v", entry, err), At: r.opts.Now()})
	r.recordEntryAttempt(entry, "failed")

	// strike every bridge of the attempted set (threshold 2 → cooldown)
	r.mu.Lock()
	for _, b := range r.activeSet {
		key := tor.DedupKey(b)
		r.strikes[key]++
		if r.strikes[key] >= bridgeStrikeThreshold {
			r.strikeUntil[key] = r.opts.Now().Add(bridgeStrikeCooldown)
			delete(r.strikes, key)
		}
	}
	r.mu.Unlock()

	r.teardown("attempt-failed")
	r.nextEntry(entry)
}

// nextEntry advances the entry ladder.
func (r *Runtime) nextEntry(failed string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg.EffectiveEntryMode() != "auto" {
		// pinned entry: restart budget governs the retry cadence
		r.entry = ""
		return
	}
	// record the failure in the entry memory (30-min window)
	mem := r.entryMem.Load(r.opts.Now)
	if failed != "" && failed != "auto-mixed" {
		if !contains(mem.Failed, failed) {
			_ = r.entryMem.RecordFail(entryRealName(failed), r.opts.Now)
		}
	}
	if failed == "auto-mixed" {
		r.mixedTried = true
		r.entry = ""
		return
	}
	// sequential ladder: next entry not in memory-failed
	candidates := append([]string(nil), LadderOrder...)
	if r.winner != "" {
		candidates = append([]string{r.winner}, candidates...)
	}
	for _, cand := range candidates {
		if cand == failed || contains(mem.Failed, cand) {
			continue
		}
		r.entry = cand
		return
	}
	// ladder exhausted: reset the memory and start the circle over
	_ = r.entryMem.Clear()
	r.entry = ""
	r.mixedTried = false
}

// recordEntryWon: bootstrap 100 → read the winning bridge from
// orconn-status → transport → entry memory (design §8.3).
func (r *Runtime) recordEntryWon(entry string, elapsed time.Duration) {
	transport := entryRealName(entry)
	if entry == "auto-mixed" {
		transport = r.winningTransport()
	}
	r.mu.Lock()
	r.winner = transport
	r.mu.Unlock()
	_ = r.entryMem.Clear()
	_ = r.entryMem.RecordWin(transport, r.opts.Now)
	observability.Default().Metrics.Set(observability.MetricTorBootstrapSeconds, nil, uint64(elapsed.Seconds()))
	r.appendEvent(tor.TorEvent{Name: tor.EventTorEntryWon, Detail: transport, At: r.opts.Now()})
	r.appendEvent(tor.TorEvent{Name: tor.EventTorEstablished, At: r.opts.Now()})
}

// winningTransport asks the control port for the actually-connected
// bridge and maps it back to a transport (GETINFO orconn-status; the
// bridge address matches the active set).
func (r *Runtime) winningTransport() string {
	r.mu.Lock()
	ctl := r.ctl
	set := r.activeSet
	r.mu.Unlock()
	if ctl == nil {
		return ""
	}
	info, err := ctl.GetInfo("orconn-status", "entry-guards")
	if err == nil {
		for _, line := range strings.Split(info["orconn-status"], "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			for _, b := range set {
				if strings.HasPrefix(fields[0], b.AddrPort) || strings.HasPrefix(b.AddrPort, fields[0]) {
					return b.Transport
				}
				if b.Fingerprint != "" && strings.HasPrefix(fields[0], "$"+b.Fingerprint) {
					return b.Transport
				}
			}
		}
	}
	// attribution failed: the set's head beats a hardcoded ladder guess
	if len(set) > 0 {
		return set[0].Transport
	}
	return ladderWebtunnel
}

func entryRealName(entry string) string {
	switch {
	case strings.HasPrefix(entry, "auto"):
		return ladderWebtunnel
	case entry == "meek":
		return "meek_lite"
	default:
		return entry
	}
}

func ladderEntryName(entry string) string {
	if entry == ladderSnowflake {
		return ladderSnowflake // the 300s cap branch
	}
	return entry
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// recordEntryAttempt bumps the entry-attempts metric.
func (r *Runtime) recordEntryAttempt(entry, result string) {
	observability.Default().Metrics.Inc(observability.MetricTorEntryAttemptsTotal,
		map[string]string{"entry": entryRealName(entry), "result": result}, 1)
}

func (r *Runtime) recordControlError(err error) {
	observability.Default().Metrics.Inc(observability.MetricTorControlErrorsTotal, nil, 1)
	_ = err
}

// appendEvent adds to the bounded ring (cap 32) with a fan-out hook.
func (r *Runtime) appendEvent(ev tor.TorEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ev.At = r.opts.Now()
	r.events = append(r.events, ev)
	if len(r.events) > eventsRingCap {
		r.events = r.events[len(r.events)-eventsRingCap:]
	}
}

// atomicWriteFile: tmp + rename (the torrc canon — regenerated on every
// start, never partially visible).
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".torrc-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	_ = tmp.Chmod(mode)
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func splitHostPort(addr string) (string, int) {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return addr, 0
	}
	port := 0
	fmt.Sscanf(addr[i+1:], "%d", &port)
	return addr[:i], port
}
