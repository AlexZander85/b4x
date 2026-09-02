// Health layer for the Opera reserve transport (design §4 — built from
// scratch; the upstream references have nothing of the kind). Rotation and
// region-failover policy is ported from the Nova state machine
// (nova_opera_failover.py): failure limits before switching, explicit EU->AM
// alternate only, desired-region retry with exponential backoff (300s base,
// 1800s cap). Program invariants on top: restart cap <=6/hour + 300s
// cooldown, running/listening reported separately.
//
// Threading model: one mutex; Tick(now) is the deterministic core driven by
// Run()'s ticker or directly by tests with an injected clock. No goroutines
// are spawned by New — Run is opt-in so OP4 wiring owns the lifecycle.
package opera

import (
        "context"
        "errors"
        "fmt"
        "sync"
        "time"
)

// ProbeVerdict is the tri-state probe outcome (design §4):
//   - ProbeOK: the level passed;
//   - ProbeFail: node/network-side negative — counts toward rotation;
//   - ProbeCantBind: the probe could not be EXECUTED because of local
//     configuration (errSetup guards) — never rotates a healthy node.
type ProbeVerdict int

const (
        ProbeOK ProbeVerdict = iota
        ProbeFail
        ProbeCantBind
)

func (v ProbeVerdict) String() string {
        switch v {
        case ProbeOK:
                return "ok"
        case ProbeFail:
                return "fail"
        default:
                return "cant-bind"
        }
}

// HealthConfig tunes the supervisor. Zero fields fall back to defaults.
type HealthConfig struct {
        // Region is the desired megaregion (EU/AS/AM whitelist).
        Region string
        // ControlTarget is the host:port used for the deep CONNECT probe.
        ControlTarget string
        // CheapInterval is the L1 (TCP/TLS handshake) cadence.
        CheapInterval time.Duration
        // DeepInterval is the L2 (end-to-end CONNECT) cadence; must be >= CheapInterval.
        DeepInterval time.Duration
        // FailureLimit: consecutive Fail verdicts before rotating to the next
        // cached candidate (Nova direct_failure_limit).
        FailureLimit int
        // RestartCapPerHour bounds expensive recovery actions (<=6/hour).
        RestartCapPerHour int
        // Cooldown after hitting the restart cap / between recovery attempts.
        Cooldown time.Duration
        // RefreshEvery is the JWT rotation cadence (SurfEasy issues 4h tokens).
        RefreshEvery time.Duration
        // RetryBase/RetryMax shape the exponential backoff for returning to the
        // desired region (Nova: base 300s, max 1800s).
        RetryBase time.Duration
        RetryMax  time.Duration
        // Now is the injectable clock (tests); nil => time.Now UTC.
        Now func() time.Time
}

// DefaultHealthConfig returns the program-invariant defaults (design §4).
func DefaultHealthConfig(region string) HealthConfig {
        return HealthConfig{
                Region:            region,
                ControlTarget:     "www.gstatic.com:80",
                CheapInterval:     60 * time.Second,
                DeepInterval:      5 * time.Minute,
                FailureLimit:      3,
                RestartCapPerHour: 6,
                Cooldown:          300 * time.Second,
                RefreshEvery:      4 * time.Hour,
                RetryBase:         300 * time.Second,
                RetryMax:          1800 * time.Second,
        }
}

func (c *HealthConfig) resolve() error {
        def := DefaultHealthConfig("EU")
        if c.Region == "" {
                c.Region = def.Region
        }
        r, err := NormalizeRegion(c.Region)
        if err != nil {
                return err
        }
        c.Region = r
        if c.ControlTarget == "" {
                c.ControlTarget = def.ControlTarget
        }
        if c.CheapInterval <= 0 {
                c.CheapInterval = def.CheapInterval
        }
        if c.DeepInterval < c.CheapInterval {
                c.DeepInterval = def.DeepInterval
        }
        if c.FailureLimit <= 0 {
                c.FailureLimit = def.FailureLimit
        }
        if c.RestartCapPerHour <= 0 {
                c.RestartCapPerHour = def.RestartCapPerHour
        }
        if c.Cooldown <= 0 {
                c.Cooldown = def.Cooldown
        }
        if c.RefreshEvery <= 0 {
                c.RefreshEvery = def.RefreshEvery
        }
        if c.RetryBase <= 0 {
                c.RetryBase = def.RetryBase
        }
        if c.RetryMax < c.RetryBase {
                c.RetryMax = def.RetryMax
        }
        if c.Now == nil {
                c.Now = func() time.Time { return time.Now().UTC() }
        }
        return nil
}

// Prober executes the two-level probe against one candidate node.
// Returned errors are classified via probeVerdictOf: errSetup-wrapped =>
// ProbeCantBind, everything else => ProbeFail.
type Prober interface {
        ProbeCheap(ctx context.Context, entry SEIPEntry) error
        ProbeDeep(ctx context.Context, entry SEIPEntry) error
}

// defaultProber probes through the live client's credentials.
type defaultProber struct {
        c       *Client
        control string
}

func (p defaultProber) nodeDialer(entry SEIPEntry) (*NodeDialer, error) {
        return p.c.NodeDialer(entry, "")
}

func (p defaultProber) ProbeCheap(ctx context.Context, entry SEIPEntry) error {
        nd, err := p.nodeDialer(entry)
        if err != nil {
                return err
        }
        conn, err := nd.DialNodeTLS(ctx)
        if err != nil {
                return err
        }
        return conn.Close()
}

func (p defaultProber) ProbeDeep(ctx context.Context, entry SEIPEntry) error {
        nd, err := p.nodeDialer(entry)
        if err != nil {
                return err
        }
        conn, err := nd.DialContext(ctx, "tcp", p.control)
        if err != nil {
                return err
        }
        return conn.Close()
}

func probeVerdictOf(err error) ProbeVerdict {
        switch {
        case err == nil:
                return ProbeOK
        case errors.Is(err, errSetup):
                return ProbeCantBind
        default:
                return ProbeFail
        }
}

// HealthStatus is the running/listening pair plus rotation machinery state
// (design §4: "process alive, port closed" must stay distinguishable).
type HealthStatus struct {
        Running   bool // control plane established (identity + credentials)
        Listening bool // data plane verified usable by the last DEEP probe
        Degraded  string

        Region        string // effective region (may be the alternate)
        DesiredRegion string
        ActiveNode    string
        CachedNodes   int

        ConsecFails       int
        RestartsLastHour  int
        CooldownUntil     time.Time
        NextDesiredRetry  time.Time
        LastRefreshAt     time.Time
        LastProbeAt       time.Time
        LastVerdict       ProbeVerdict
        LastError         string
        DiscoverCalls     int
}

// HealthSupervisor owns session bootstrap, JWT refresh cadence, two-level
// probing, candidate rotation and capped recovery for one Opera transport.
type HealthSupervisor struct {
        c   *Client
        cfg HealthConfig
        pb  Prober

        mu               sync.Mutex
        ctx              context.Context
        started          bool
        sessionOK        bool
        credsDead        bool // server rejected credentials — slot must not be re-adopted
        listening        bool
        degraded         string
        nodes            []SEIPEntry
        idx              int
        region           string // effective (may differ from desired after alternate)
        consecFails      int
        restarts         []time.Time
        cooldownUntil    time.Time
        retryRound       int
        nextDesiredRetry time.Time
        lastDeepAt       time.Time
        lastDeepOK       bool
        lastRefreshAt    time.Time
        lastProbeAt      time.Time
        lastVerdict      ProbeVerdict
        lastErr          string
        discoverCalls    int
}

// NewHealthSupervisor validates config and wires the supervisor around a
// live client. The prober defaults to real network probes; tests inject fakes.
func NewHealthSupervisor(c *Client, cfg HealthConfig) (*HealthSupervisor, error) {
        if c == nil {
                return nil, fmt.Errorf("health supervisor: nil client")
        }
        if err := cfg.resolve(); err != nil {
                return nil, fmt.Errorf("health supervisor: %w", err)
        }
        return &HealthSupervisor{
                c:      c,
                cfg:    cfg,
                pb:     defaultProber{c: c, control: cfg.ControlTarget},
                ctx:    context.Background(),
                region: cfg.Region,
        }, nil
}

// SetProber replaces the prober (test injection).
func (h *HealthSupervisor) SetProber(p Prober) {
        h.mu.Lock()
        h.pb = p
        h.mu.Unlock()
}

// Now exposes the supervisor's injectable clock (operaservice.Kick uses it
// so manual kicks share the same time source as the ticker loop).
func (h *HealthSupervisor) Now() time.Time { return h.cfg.Now() }

// Run drives Tick with the configured cadence until ctx is cancelled.
func (h *HealthSupervisor) Run(ctx context.Context) {
        t := time.NewTicker(h.cfg.CheapInterval)
        defer t.Stop()
        for {
                select {
                case <-ctx.Done():
                        return
                case <-t.C:
                        h.Tick(h.cfg.Now())
                }
        }
}

// Tick advances one supervision step at wall-clock `now`. Deterministic:
// all decisions derive from now + recorded timestamps.
func (h *HealthSupervisor) Tick(now time.Time) {
        h.mu.Lock()
        defer h.mu.Unlock()
        h.started = true
        h.lastProbeAt = now

        if h.degraded != "" {
                return // fail-closed terminal state (e.g. API pin mismatch)
        }

        // Bootstrap once: identity slot adopt/register + first discover.
        if !h.sessionOK {
                if err := h.bootstrap(now); err != nil {
                        h.lastErr = err.Error()
                        return
                }
        }
        // Desired-region return (Nova begin_desired_retry).
        if h.region != h.cfg.Region && !h.nextDesiredRetry.IsZero() && now.After(h.nextDesiredRetry) {
                h.beginDesiredRetry(now)
        }

        // JWT refresh cadence (4h).
        if !h.lastRefreshAt.IsZero() && now.Sub(h.lastRefreshAt) >= h.cfg.RefreshEvery {
                if err := h.c.RefreshCredentials(h.ctx); err != nil {
                        h.lastRefreshAt = now // do not hammer within the same interval
                        h.noteAPIFailure(err, now)
                        return
                }
                h.lastRefreshAt = now
        }

        // Two-level probe: deep when due, cheap otherwise.
        entry := h.currentLocked()
        deepDue := h.lastDeepAt.IsZero() || now.Sub(h.lastDeepAt) >= h.cfg.DeepInterval
        var err error
        if deepDue {
                err = h.pb.ProbeDeep(h.ctx, entry)
        } else {
                err = h.pb.ProbeCheap(h.ctx, entry)
        }
        h.applyProbe(deepDue, err, now)
}

// ---------------------------------------------------------------------------
// Internals (caller holds h.mu).
// ---------------------------------------------------------------------------

func (h *HealthSupervisor) now() time.Time { return h.cfg.Now() }

func (h *HealthSupervisor) currentLocked() SEIPEntry {
        if len(h.nodes) == 0 {
                return SEIPEntry{}
        }
        return h.nodes[h.idx%len(h.nodes)]
}

// discoverLocked fetches nodes for region and adopts them (idx reset).
func (h *HealthSupervisor) discoverLocked(region string) error {
        ips, err := h.c.Discover(h.ctx, region)
        h.discoverCalls++
        if err != nil {
                return err
        }
        if len(ips) == 0 {
                return fmt.Errorf("discover %s returned no endpoints", region)
        }
        h.nodes = ips
        h.idx = 0
        h.region = region
        return nil
}

func (h *HealthSupervisor) bootstrap(now time.Time) error {
        var err error
        if h.credsDead {
                // Previous control-channel exchange proved local credentials dead
                // (auth refused server-side): blind slot adoption would resurrect a
                // stale JWT — register a fresh anonymous device through the cap.
                err = h.registerFreshCapped(now)
        } else {
                err = h.c.EnsureSession(h.ctx)
        }
        if err != nil {
                if !errors.Is(err, errRestartCapped) {
                        h.noteAPIFailure(err, now)
                }
                return err
        }
        h.sessionOK = true
        h.lastRefreshAt = now
        if err := h.discoverLocked(h.region); err != nil {
                // Session lives; data-plane cache is empty until discover succeeds.
                return err
        }
        return nil
}

// errRestartCapped reports that recovery was withheld by the <=6/hour cap.
var errRestartCapped = errors.New("restart capped")

// registerFreshCapped performs the ONE expensive recovery action — fresh
// anonymous device registration — under the restart cap + cooldown.
func (h *HealthSupervisor) registerFreshCapped(now time.Time) error {
        h.pruneRestarts(now)
        if now.Before(h.cooldownUntil) || len(h.restarts) >= h.cfg.RestartCapPerHour {
                if u := now.Add(h.cfg.Cooldown); u.After(h.cooldownUntil) {
                        h.cooldownUntil = u
                }
                return errRestartCapped
        }
        h.restarts = append(h.restarts, now)
        if err := h.c.RegisterNew(h.ctx); err != nil {
                return err
        }
        h.credsDead = false
        h.sessionOK = true
        h.lastRefreshAt = now
        h.listening = false
        h.lastDeepOK = false
        _ = h.discoverLocked(h.region)
        return nil
}

// noteAPIFailure routes control-channel failures: pin mismatch is a terminal
// degraded state (fail closed — design §3), auth refusal marks the local
// credentials dead and triggers one capped recovery attempt immediately;
// everything else is surfaced only. Recovery never re-enters bootstrap, so
// a persistently refusing API cannot recurse within a single Tick.
func (h *HealthSupervisor) noteAPIFailure(err error, now time.Time) {
        if IsClass(err, ClassAPIPinMismatch) {
                h.degraded = string(ClassAPIPinMismatch)
                return
        }
        if IsClass(err, ClassAPIAuthRefused) || errors.Is(err, ErrIdentityCorrupt) {
                h.credsDead = true
                h.sessionOK = false
                _ = h.registerFreshCapped(now)
        }
}

func (h *HealthSupervisor) applyProbe(deep bool, err error, now time.Time) {
        switch probeVerdictOf(err) {
        case ProbeCantBind:
                h.lastVerdict = ProbeCantBind
                if err != nil {
                        h.lastErr = err.Error()
                }
                return
        case ProbeOK:
                h.consecFails = 0
                h.lastVerdict = ProbeOK
                h.lastErr = ""
                if deep {
                        h.lastDeepAt = now
                        h.lastDeepOK = true
                        h.listening = true
                }
                // Nova record_success: being healthy at the desired region clears
                // the alternate-region retry machinery.
                if h.region == h.cfg.Region {
                        h.retryRound = 0
                        h.nextDesiredRetry = time.Time{}
                }
                return
        default: // ProbeFail
                h.consecFails++
                h.lastVerdict = ProbeFail
                if err != nil {
                        h.lastErr = err.Error()
                }
                if deep {
                        h.lastDeepAt = now
                        h.lastDeepOK = false
                        h.listening = false
                }
                if h.consecFails >= h.cfg.FailureLimit {
                        h.rotate(now)
                }
        }
}

// rotate moves to the next cached candidate without touching the session
// ("без пересоздания слушателя"); on cache exhaustion it re-discovers, and
// only then falls back to the alternate region (Nova semantics).
func (h *HealthSupervisor) rotate(now time.Time) {
        h.consecFails = 0
        if len(h.nodes) > 1 && h.idx < len(h.nodes)-1 {
                h.idx++
                return
        }
        if err := h.discoverLocked(h.region); err == nil {
                return
        }
        // Rediscover failed: alternate region per Nova — only EU has an explicit
        // AM fallback; the switch commits BEFORE its discovery succeeds so the
        // scheduled retries target the alternate even while it is unreachable.
        // Any other desired region is retried in place.
        if h.cfg.Region == RegionEU && h.region != RegionAM {
                h.region = RegionAM
                if err := h.discoverLocked(RegionAM); err == nil {
                        h.scheduleDesiredRetry(now)
                        return
                }
        }
        h.scheduleDesiredRetry(now)
}

func (h *HealthSupervisor) scheduleDesiredRetry(now time.Time) {
        delay := h.cfg.RetryBase << min64(int64(h.retryRound), 6)
        if delay > h.cfg.RetryMax {
                delay = h.cfg.RetryMax
        }
        h.retryRound++
        h.nextDesiredRetry = now.Add(delay)
}

func (h *HealthSupervisor) beginDesiredRetry(now time.Time) {
        if err := h.discoverLocked(h.cfg.Region); err != nil {
                h.scheduleDesiredRetry(now)
                return
        }
        h.retryRound = 0
        h.nextDesiredRetry = time.Time{}
}

func (h *HealthSupervisor) pruneRestarts(now time.Time) {
        cut := now.Add(-time.Hour)
        kept := h.restarts[:0]
        for _, ts := range h.restarts {
                if ts.After(cut) {
                        kept = append(kept, ts)
                }
        }
        h.restarts = kept
}

// ActiveEntry returns a copy of the currently selected node entry.
func (h *HealthSupervisor) ActiveEntry() SEIPEntry {
        h.mu.Lock()
        defer h.mu.Unlock()
        return h.currentLocked()
}

// SetDesiredRegion switches the desired megaregion WITHOUT touching the
// device identity (design §5: the device stays the same — region lives in
// discover). An established session immediately attempts discovery toward
// the new region; failure schedules the usual backoff.
func (h *HealthSupervisor) SetDesiredRegion(region string) error {
        r, err := NormalizeRegion(region)
        if err != nil {
                return err
        }
        h.mu.Lock()
        defer h.mu.Unlock()
        if h.cfg.Region == r {
                return nil
        }
        h.cfg.Region = r
        h.degraded = "" // a live region command re-arms a degraded supervisor
        if !h.sessionOK {
                return nil
        }
        if err := h.discoverLocked(r); err != nil {
                // Alternate-region machinery takes over from here: if we were sitting
                // on an alternate for the old desired, the next Tick returns toward
                // the new desired via begin_desired_retry scheduling.
                h.scheduleDesiredRetry(h.now())
                return err
        }
        h.retryRound = 0
        h.nextDesiredRetry = time.Time{}
        return nil
}

// Status snapshots the supervisor state.
func (h *HealthSupervisor) Status() HealthStatus {
        h.mu.Lock()
        defer h.mu.Unlock()
        st := HealthStatus{
                Running:          h.started && h.sessionOK,
                Listening:        h.listening,
                Degraded:         h.degraded,
                Region:           h.region,
                DesiredRegion:    h.cfg.Region,
                CachedNodes:      len(h.nodes),
                ConsecFails:      h.consecFails,
                RestartsLastHour: len(h.restarts),
                CooldownUntil:    h.cooldownUntil,
                NextDesiredRetry: h.nextDesiredRetry,
                LastRefreshAt:    h.lastRefreshAt,
                LastProbeAt:      h.lastProbeAt,
                LastVerdict:      h.lastVerdict,
                LastError:        h.lastErr,
                DiscoverCalls:    h.discoverCalls,
        }
        if len(h.nodes) > 0 {
                st.ActiveNode = h.currentLocked().NetAddr()
        }
        return st
}

func min64(a, b int64) int64 {
        if a < b {
                return a
        }
        return b
}
