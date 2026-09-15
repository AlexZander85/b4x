package torservice

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

func (r *Runtime) ensureBridges(ctx context.Context) {
	r.mu.Lock()
	if r.state == StateBinaryMissing || r.collecting || r.retiring {
		r.mu.Unlock()
		return
	}
	entry := r.currentEntry()
	r.mu.Unlock()

	if r.entryUnsupportedByPolicy(entry) {
		r.appendEvent(tor.TorEvent{
			Name: tor.EventTorCarrierUnsupported, Class: tor.ClassTorCarrierPolicy,
			Detail: fmt.Sprintf("entry=%s requires UDP but through=%s is a TCP-only pinned carrier", entry, r.cfg.EffectiveEgressThrough()),
			At: r.opts.Now(),
		})
		if r.cfg.EffectiveEntryMode() == "auto" {
			r.nextEntry(entry)
			return
		}
		r.mu.Lock()
		r.state = StateBackoff
		r.cooldown = r.opts.Now().Add(300 * time.Second)
		r.hint = "snowflake needs direct/auto packet egress; named carriers are strict TCP-only"
		r.mu.Unlock()
		return
	}

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

func (r *Runtime) entryUnsupportedByPolicy(entry string) bool {
	return entry == ladderSnowflake && tor.IsPinnedCarrierPolicy(r.cfg.EffectiveEgressThrough())
}

func (r *Runtime) currentEntry() string {
	if r.cfg.EffectiveEntryMode() != "auto" {
		return r.cfg.EffectiveEntryMode()
	}
	if r.entry != "" {
		return r.entry
	}
	if r.mixedTried {
		// Defensive fallback. nextEntry normally selects an explicit
		// sequential candidate as soon as mixed-set fails, but never return an
		// empty transport if state is recovered from an interrupted attempt.
		for _, cand := range LadderOrder {
			if !r.entryUnsupportedByPolicy(cand) {
				return cand
			}
		}
		return ladderWebtunnel
	}
	return "auto-mixed"
}

// assembleSet gives RaceWindow one global meaning: maximum total heads in
// the mixed torrc. It round-robins WT/obfs4/snowflake so no transport can
// consume the whole FD budget. meek_lite remains manual-only as designed.
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
		if r.cfg.Bridges.BuiltinSnowflake && !tor.IsPinnedCarrierPolicy(r.cfg.EffectiveEgressThrough()) {
			all = append(all, tor.BuiltinSnowflake("cdn77")...)
		}
		transports := []string{ladderWebtunnel, ladderObfs4}
		if !tor.IsPinnedCarrierPolicy(r.cfg.EffectiveEgressThrough()) {
			transports = append(transports, ladderSnowflake)
		}
		budget := r.cfg.EffectiveRaceWindow()
		var set []tor.Bridge
		for round := 0; len(set) < budget; round++ {
			progress := false
			for _, tr := range transports {
				if len(set) >= budget {
					break
				}
				cand := takeBridges(all, tr, round+1)
				if len(cand) <= round {
					continue
				}
				set = append(set, cand[round])
				progress = true
			}
			if !progress {
				break
			}
		}
		set = tor.Dedup(set)
		return set, len(set) > 0
	default:
		set := takeBridges(all, entry, 40)
		if entry == ladderSnowflake && r.cfg.Bridges.BuiltinSnowflake && !tor.IsPinnedCarrierPolicy(r.cfg.EffectiveEgressThrough()) {
			set = append(set, tor.BuiltinSnowflake("cdn77")...)
		}
		set = tor.Dedup(set)
		return set, len(set) > 0
	}
}

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

func (r *Runtime) ensureProcess(ctx context.Context) {
	r.mu.Lock()
	if r.state == StateBinaryMissing || r.proc != nil || r.state == StateBridgesWait || r.retiring {
		r.mu.Unlock()
		return
	}
	if len(r.activeSet) == 0 && r.currentEntry() != "direct" {
		r.mu.Unlock()
		return
	}
	entry := r.currentEntry()
	set := append([]tor.Bridge(nil), r.activeSet...)
	r.mu.Unlock()

	res := r.resourceSnapshot()
	if res.FDLimit > 0 && res.FDLimit < 512 {
		r.appendEvent(tor.TorEvent{
			Name: tor.EventTorResourceWarning, Class: tor.ClassTorResourceLimit,
			Detail: fmt.Sprintf("RLIMIT_NOFILE=%d; monitor Tor/PT FD pressure", res.FDLimit), At: r.opts.Now(),
		})
	}

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
	if r.proc != nil || r.retiring {
		r.mu.Unlock()
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		proc.Stop(stopCtx, nil)
		return
	}
	r.proc = proc
	r.state = StateBootstrapping
	r.entry = entry
	r.hint = ""
	r.mu.Unlock()
	r.recordEntryAttempt(entry, "start")
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

func (r *Runtime) torrcInput(entry string, set []tor.Bridge) tor.TorrcInput {
	r.mu.Lock()
	eb := r.egressBridge
	pp := r.ptProxy
	r.mu.Unlock()
	in := tor.TorrcInput{
		DataPath: r.cfg.EffectiveDataPath(), OwningPID: os.Getpid(), SocksPort: "127.0.0.1:auto",
		ControlSocket: filepath.Join(r.cfg.EffectiveDataPath(), "data", "control.sock"),
		Padding: r.cfg.EffectivePadding(), GeoIP: r.cfg.Speed.GeoIP, Isolation: r.cfg.EffectiveIsolation(),
		Bridges: set, UseBridges: entry != "direct", Entry: entry,
	}
	if entry == ladderVanilla || entry == "direct" {
		if eb != nil {
			in.EgressProxyAddr = eb.Addr()
			in.EgressProxyUsername = eb.Username()
			in.EgressProxyPassword = eb.Password()
		}
	}
	if pp != nil {
		_, port := splitHostPort(pp.Addr())
		in.PTProxyPort = port
	}
	return in
}

func (r *Runtime) ensureBootstrap(ctx context.Context) {
	r.mu.Lock()
	proc := r.proc
	state := r.state
	entry := r.entry
	r.mu.Unlock()
	if proc == nil || state != StateBootstrapping {
		return
	}
	ctl, err := r.connectControl(ctx)
	if err != nil {
		return
	}
	// Ownership of a successfully authenticated control connection does not
	// depend on the SOCKS listener already being published. Save it now so
	// winner attribution and shutdown remain available during early startup.
	r.mu.Lock()
	oldCtl := r.ctl
	r.ctl = ctl
	r.mu.Unlock()
	if oldCtl != nil && oldCtl != ctl {
		_ = oldCtl.Close()
	}
	if info, err := ctl.GetInfo("net/listeners/socks"); err == nil {
		if addr := info["net/listeners/socks"]; addr != "" {
			r.mu.Lock()
			r.socksAddr = addr
			r.mu.Unlock()
		}
	}
	bcfg := r.opts.Bootstrap
	if bcfg.PollInterval == 0 {
		bcfg = tor.DefaultBootstrapConfig()
	}
	started := r.opts.Now()
	final, err := tor.BootstrapWatchCfg(ctx, ctl, ladderEntryName(entry), bcfg, r.opts.Now, func(ph tor.BootstrapPhase) {
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
	r.bootstrap = final
	r.mu.Unlock()
	r.recordEntryWon(entry, elapsed)
}

func (r *Runtime) connectControl(ctx context.Context) (tor.ControlClient, error) {
	dial := r.opts.DialControl
	network, addr := "unix", filepath.Join(r.cfg.EffectiveDataPath(), "data", "control.sock")
	if dial == nil {
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

func (r *Runtime) ensureLiveness(ctx context.Context) {
	r.mu.Lock()
	state := r.state
	socks := r.socksAddr
	ctl := r.ctl
	last := r.lastLiveness
	fails := r.livenessFails
	deadSince := r.livenessDeadSince
	r.mu.Unlock()
	if (state != StateEstablished && state != StateRotating) || socks == "" {
		return
	}
	now := r.opts.Now()
	if fails >= livenessTeardownAt && !deadSince.IsZero() && now.Sub(deadSince) >= livenessGrace {
		r.teardown("liveness-dead")
		r.restartFromWinner()
		return
	}
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
		r.livenessDeadSince = time.Time{}
		r.newnymSent = false
		if r.state == StateRotating {
			r.state = StateEstablished
		}
		r.mu.Unlock()
		observability.Default().Metrics.Inc(observability.MetricTorStreamsTotal, map[string]string{"result": "ok"}, 1)
		return
	}

	observability.Default().Metrics.Inc(observability.MetricTorStreamsTotal, map[string]string{"result": "fail"}, 1)
	r.mu.Lock()
	r.livenessFails++
	fails = r.livenessFails
	if fails >= livenessTeardownAt && r.livenessDeadSince.IsZero() {
		r.livenessDeadSince = now
	}
	r.mu.Unlock()
	r.appendEvent(tor.TorEvent{Name: tor.EventTorRotated, Class: tor.ClassTorLivenessFailed, Detail: fmt.Sprintf("liveness failure %d", fails), At: now})

	if fails == livenessNEWNYMAfter && !r.newnymSent {
		r.mu.Lock()
		r.newnymSent = true
		r.state = StateRotating
		r.mu.Unlock()
		if ctl != nil {
			_ = ctl.Signal("ACTIVE")
			_ = ctl.Signal("NEWNYM")
		}
		r.appendEvent(tor.TorEvent{Name: tor.EventTorRotated, Detail: "SIGNAL ACTIVE + NEWNYM after 2 liveness failures", At: now})
	}
}

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
	if ux == "auto" || ux == "" {
		if r.resourceSnapshot().LowMemory {
			ux = "throughput_lowmem"
		} else {
			ux = "throughput"
		}
	}
	switch ux {
	case "throughput", "latency", "throughput_lowmem", "latency_lowmem":
	default:
		ux = "throughput"
	}
	r.mu.Lock()
	r.confluxUX = ux
	r.mu.Unlock()
	if err := ctl.SetConf([2]string{"ConfluxEnabled", "1"}, [2]string{"ConfluxClientUX", ux}); err != nil {
		r.appendEvent(tor.TorEvent{Name: tor.EventTorConfluxUnavailable, Class: tor.ClassTorControlError, Detail: err.Error(), At: r.opts.Now()})
		return
	}
	r.appendEvent(tor.TorEvent{Name: tor.EventTorConfluxEnabled, Detail: ux, At: r.opts.Now()})
	_ = ctx
}

func (r *Runtime) handleDeath(ctx context.Context) {
	r.mu.Lock()
	if r.retiring {
		r.mu.Unlock()
		return
	}
	proc := r.proc
	ctl := r.ctl
	if proc == nil {
		r.mu.Unlock()
		return
	}
	r.proc = nil
	r.ctl = nil
	r.socksAddr = ""
	r.state = StateStarting
	r.livenessFails = 0
	r.livenessDeadSince = time.Time{}
	r.newnymSent = false
	r.confluxDone = false
	r.confluxUX = ""
	r.mu.Unlock()
	if ctl != nil {
		_ = ctl.Close()
	}
	r.appendEvent(tor.TorEvent{Name: tor.EventTorProcessDied, Class: tor.ClassTorProcessDied, At: r.opts.Now()})
	r.restartFromWinner()
	_ = ctx
}

func (r *Runtime) retireCurrentProcess(reason string) bool {
	r.mu.Lock()
	if r.retiring {
		r.mu.Unlock()
		return false
	}
	proc := r.proc
	ctl := r.ctl
	if proc == nil {
		r.ctl = nil
		r.socksAddr = ""
		r.state = StateStarting
		r.livenessFails = 0
		r.livenessDeadSince = time.Time{}
		r.newnymSent = false
		r.confluxDone = false
		r.confluxUX = ""
		r.mu.Unlock()
		if ctl != nil {
			_ = ctl.Close()
		}
		return true
	}
	r.retiring = true
	r.mu.Unlock()

	stopCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	proc.Stop(stopCtx, ctl)
	cancel()
	if ctl != nil {
		_ = ctl.Close()
	}
	if a, ok := proc.(interface{ Alive() bool }); ok && a.Alive() {
		r.mu.Lock()
		r.retiring = false
		r.state = StateBackoff
		r.cooldown = r.opts.Now().Add(300 * time.Second)
		r.hint = "owned Tor could not be retired safely; refusing replacement spawn"
		r.mu.Unlock()
		r.appendEvent(tor.TorEvent{Name: tor.EventTorProcessDied, Class: tor.ClassTorProcessDied, Detail: "retire refused/failed: " + reason, At: r.opts.Now()})
		return false
	}

	r.mu.Lock()
	if r.proc == proc {
		r.proc = nil
	}
	if r.ctl == ctl {
		r.ctl = nil
	}
	r.socksAddr = ""
	if !r.stopped {
		r.state = StateStarting
	}
	r.livenessFails = 0
	r.livenessDeadSince = time.Time{}
	r.newnymSent = false
	r.confluxDone = false
	r.confluxUX = ""
	r.retiring = false
	r.mu.Unlock()
	return true
}

func (r *Runtime) teardown(reason string) {
	_ = r.retireCurrentProcess(reason)
}

func (r *Runtime) restartFromWinner() {
	r.mu.Lock()
	now := r.opts.Now()
	if r.retiring || now.Before(r.cooldown) {
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
	if winner != "" && !(winner == ladderSnowflake && tor.IsPinnedCarrierPolicy(r.cfg.EffectiveEgressThrough())) {
		r.entry = winner
	} else {
		r.entry = ""
		r.mixedTried = false
	}
	r.mu.Unlock()
}

func (r *Runtime) failAttempt(err error) {
	r.mu.Lock()
	entry := r.entry
	set := append([]tor.Bridge(nil), r.activeSet...)
	r.mu.Unlock()
	r.appendEvent(tor.TorEvent{Name: tor.EventTorEntryFailed, Class: tor.ClassTorEntryFailed, Detail: fmt.Sprintf("%s: %v", entry, err), At: r.opts.Now()})
	r.recordEntryAttempt(entry, "failed")

	r.mu.Lock()
	for _, b := range set {
		key := tor.DedupKey(b)
		r.strikes[key]++
		if r.strikes[key] >= bridgeStrikeThreshold {
			r.strikeUntil[key] = r.opts.Now().Add(bridgeStrikeCooldown)
			delete(r.strikes, key)
		}
	}
	r.mu.Unlock()

	if !r.retireCurrentProcess("attempt-failed") {
		return
	}
	r.nextEntry(entry)
}

func (r *Runtime) nextEntry(failed string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg.EffectiveEntryMode() != "auto" {
		r.entry = ""
		return
	}
	mem := r.entryMem.Load(r.opts.Now)
	if failed != "" && failed != "auto-mixed" {
		if !contains(mem.Failed, failed) {
			_ = r.entryMem.RecordFail(entryRealName(failed), r.opts.Now)
			mem.Failed = append(mem.Failed, entryRealName(failed))
		}
	}
	if failed == "auto-mixed" {
		r.mixedTried = true
	}
	candidates := append([]string(nil), LadderOrder...)
	if failed != "auto-mixed" && r.winner != "" {
		candidates = append([]string{r.winner}, candidates...)
	}
	for _, cand := range candidates {
		if cand == failed || contains(mem.Failed, cand) || r.entryUnsupportedByPolicy(cand) {
			continue
		}
		r.entry = cand
		return
	}
	_ = r.entryMem.Clear()
	r.entry = ""
	r.mixedTried = false
}

func (r *Runtime) recordEntryWon(entry string, elapsed time.Duration) {
	transport := entryRealName(entry)
	bridgeID := ""
	if entry == "auto-mixed" {
		br, ok := r.winningBridge()
		if !ok {
			observability.Default().Metrics.Set(observability.MetricTorBootstrapSeconds, nil, uint64(elapsed.Seconds()))
			r.appendEvent(tor.TorEvent{Name: tor.EventTorEntryAttributionUnknown, Class: tor.ClassTorControlError, Detail: "bootstrap reached 100 but active bridge could not be attributed", At: r.opts.Now()})
			r.appendEvent(tor.TorEvent{Name: tor.EventTorEstablished, At: r.opts.Now()})
			return
		}
		transport = br.Transport
		bridgeID = tor.DedupKey(br)
	} else {
		r.mu.Lock()
		for _, br := range r.activeSet {
			if br.Transport == transport {
				bridgeID = tor.DedupKey(br)
				break
			}
		}
		r.mu.Unlock()
	}

	r.mu.Lock()
	r.winner = transport
	r.winnerBridge = bridgeID
	r.mu.Unlock()
	if r.cfg.EffectiveEntryMode() == "auto" {
		_ = r.entryMem.Clear()
		_ = r.entryMem.RecordWinBridge(transport, bridgeID, r.opts.Now)
	}
	observability.Default().Metrics.Set(observability.MetricTorBootstrapSeconds, nil, uint64(elapsed.Seconds()))
	r.appendEvent(tor.TorEvent{Name: tor.EventTorEntryWon, Detail: transport, At: r.opts.Now()})
	r.appendEvent(tor.TorEvent{Name: tor.EventTorEstablished, At: r.opts.Now()})
}

func (r *Runtime) winningBridge() (tor.Bridge, bool) {
	r.mu.Lock()
	ctl := r.ctl
	set := append([]tor.Bridge(nil), r.activeSet...)
	r.mu.Unlock()
	if ctl == nil {
		return tor.Bridge{}, false
	}
	info, err := ctl.GetInfo("orconn-status", "entry-guards")
	if err != nil {
		return tor.Bridge{}, false
	}
	matches := map[string]tor.Bridge{}
	for _, line := range strings.Split(info["orconn-status"], "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		for _, br := range set {
			if bridgeMatchesORConn(br, id) {
				matches[tor.DedupKey(br)] = br
			}
		}
	}
	if len(matches) != 1 {
		return tor.Bridge{}, false
	}
	for _, br := range matches {
		return br, true
	}
	return tor.Bridge{}, false
}

func bridgeMatchesORConn(b tor.Bridge, id string) bool {
	if id == b.AddrPort || strings.HasPrefix(id, b.AddrPort+"~") {
		return true
	}
	if b.Fingerprint == "" {
		return false
	}
	fp := strings.ToUpper(b.Fingerprint)
	upper := strings.ToUpper(id)
	return strings.HasPrefix(upper, "$"+fp) || strings.HasPrefix(upper, fp)
}

func (r *Runtime) winningTransport() string {
	if br, ok := r.winningBridge(); ok {
		return br.Transport
	}
	return ""
}

func entryRealName(entry string) string {
	if entry == "meek" {
		return "meek_lite"
	}
	return entry
}

func ladderEntryName(entry string) string {
	if entry == ladderSnowflake {
		return ladderSnowflake
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

func (r *Runtime) recordEntryAttempt(entry, result string) {
	observability.Default().Metrics.Inc(observability.MetricTorEntryAttemptsTotal,
		map[string]string{"entry": entryRealName(entry), "result": result}, 1)
}

func (r *Runtime) recordControlError(err error) {
	observability.Default().Metrics.Inc(observability.MetricTorControlErrorsTotal, nil, 1)
	_ = err
}

func (r *Runtime) appendEvent(ev tor.TorEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ev.At = r.opts.Now()
	r.events = append(r.events, ev)
	if len(r.events) > eventsRingCap {
		r.events = r.events[len(r.events)-eventsRingCap:]
	}
}

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

func (r *Runtime) ensureRelayScan(ctx context.Context) {
	if !r.cfg.RelayScan.Enabled {
		return
	}
	r.mu.Lock()
	if r.scanning || r.opts.Now().Before(r.nextScanAt) {
		r.mu.Unlock()
		return
	}
	r.scanning = true
	r.nextScanAt = r.opts.Now().Add(6 * time.Hour)
	r.mu.Unlock()
	go func() {
		defer func() {
			r.mu.Lock()
			r.scanning = false
			r.mu.Unlock()
		}()
		sctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.cfg.EffectiveScanTimeoutSec())*time.Second)
		defer cancel()
		if _, err := r.ScanNow(sctx); err != nil {
			r.appendEvent(tor.TorEvent{Name: tor.EventTorEntryFailed, Class: tor.ClassTorNoBridges, Detail: "relay-scan: " + err.Error(), At: r.opts.Now()})
		}
	}()
	_ = ctx
}
