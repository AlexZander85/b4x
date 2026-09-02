// Health layer for the Opera reserve transport (design §4 — built from
// scratch; the upstream references have nothing of the kind). Rotation and
// region-failover policy is ported from the Nova state machine
// (nova_opera_failover.py): failure limits before switching, explicit EU->AM
// alternate only, desired-region retry with exponential backoff (300s base,
// 1800s cap). Program invariants on top: restart cap <=6/hour + 300s
// cooldown, running/listening reported separately.
//
// Threading model (review E-OPERA C2 fix): one mutex guards the STATE
// MACHINE only — no network I/O ever happens under h.mu. Tick is a small
// deterministic pipeline: plan (lock) -> execute (unlocked, bounded
// contexts) -> apply (lock), looping a bounded number of steps so one tick
// can still bootstrap, refresh AND probe like the original synchronous
// core. Probes carry hard deadlines (cheap 10s / deep 15s) and derive from
// the Run() context, so Stop() aborts in-flight I/O and a silent (wedged)
// node can no longer pin the supervisor or block Status(). One flight at a
// time: a concurrent Tick (ticker vs Kick) returns immediately.
package opera

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Probe budgets (review C2): the L1 TCP/TLS handshake and the L2
// end-to-end CONNECT must both finish inside a hard deadline. The node
// handshake uses HandshakeContext — without a deadline a node that accepts
// TCP and stays silent would pin the tick forever.
const (
	probeBudgetCheap = 10 * time.Second
	probeBudgetDeep  = 15 * time.Second
	// Control-channel ops (bootstrap / recovery / refresh / rotation
	// rediscover) ride the client's per-RPC 90s cap; the tick-level budget
	// keeps the whole step bounded even through a slow carrier chain.
	controlBudget = 120 * time.Second
	// maxTickSteps bounds the plan->execute->apply loop (bootstrap,
	// desired-retry, refresh, probe, rotate — one tick never chains more).
	maxTickSteps = 4
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
	// ProbeBudgetCheap/Deep override the hard probe deadlines (tests and
	// constrained deployments); zero falls back to the C2 constants.
	ProbeBudgetCheap time.Duration
	ProbeBudgetDeep  time.Duration
	// NodeCache persists the last successful discover as an offline asset
	// (review H3); nil keeps the in-memory-only behavior.
	NodeCache *NodeCache
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
	if c.ProbeBudgetCheap <= 0 {
		c.ProbeBudgetCheap = probeBudgetCheap
	}
	if c.ProbeBudgetDeep <= 0 {
		c.ProbeBudgetDeep = probeBudgetDeep
	}
	return nil
}

// Prober executes the two-level probe against one candidate node.
// Returned errors are classified via probeVerdictOf: errSetup-wrapped =>
// ProbeCantBind, everything else => ProbeFail. The ctx the health layer
// passes is ALWAYS deadline-bounded; implementations must honor it.
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
	// NodesSource: "live" (fresh discover) | "cache" (offline asset after
	// an API failure / 801) | "" (never discovered). Silent-fallback
	// discipline: a cache adoption is always visible here.
	NodesSource string

	ConsecFails      int
	RestartsLastHour int
	CooldownUntil    time.Time
	NextDesiredRetry time.Time
	LastRefreshAt    time.Time
	LastProbeAt      time.Time
	LastVerdict      ProbeVerdict
	LastError        string
	DiscoverCalls    int
}

// tickAction enumerates the one thing a plan step wants executed.
type tickAction int

const (
	actNone tickAction = iota
	actBootstrap
	actRecover
	actDesiredRetry
	actRefresh
	actProbe
	actRotate
)

// tickPlan is the locked-state snapshot one pipeline step executes.
type tickPlan struct {
	action tickAction
	deep   bool      // for actProbe
	entry  SEIPEntry // for actProbe
	region string    // for actRotate (rediscover target)
}

// stepResult carries the unguarded-I/O outcome back into apply.
type stepResult struct {
	err      error       // primary op error (nil = ok)
	discover []SEIPEntry // primary discover payload (nil when not attempted)
	discN    int         // discover attempts made (discoverCalls bookkeeping)
	discErr  error       // primary discover error
	// EU->AM alternate attempt (rotation only; Nova parity — the region
	// commits BEFORE the alternate discovery proves anything):
	altRegion []SEIPEntry
	altErr    error
	altIsAM   bool
	capped    bool // recover withheld by the restart cap
}

// tickDone marks which actions already ran in the CURRENT Tick — at most
// one of each per tick (parity with the single-pass original).
type tickDone struct {
	bootstrapped bool
	recovered    bool
	desiredRetry bool
	refreshed    bool
	probed       bool
	rotated      bool
}

// HealthSupervisor owns session bootstrap, JWT refresh cadence, two-level
// probing, candidate rotation and capped recovery for one Opera transport.
type HealthSupervisor struct {
	c   *Client
	cfg HealthConfig
	pb  Prober

	mu               sync.Mutex
	runCtx           context.Context // Run's context (probes die with Stop); nil in direct-Tick tests
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
	rotateQueued     bool // probe apply exhausted the cache -> rediscover step

	nodesSource string // "live" | "cache" | ""
	nodesSaved  time.Time
	pendingSave *NodeCacheRecord // flushed (file I/O) OUTSIDE the mutex
	cache       *NodeCache

	busy atomic.Bool // one Tick flight at a time (ticker vs Kick)
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
		region: cfg.Region,
		cache:  cfg.NodeCache,
	}, nil
}

// SetProber replaces the prober (test injection).
func (h *HealthSupervisor) SetProber(p Prober) {
	h.mu.Lock()
	h.pb = p
	h.mu.Unlock()
}

// Now exposes the supervisor's injectable clock (operaservice.Kick uses it
// so manual kicks share the ticker's time source).
func (h *HealthSupervisor) Now() time.Time { return h.cfg.Now() }

// Run drives Tick with the configured cadence until ctx is cancelled. The
// first tick fires immediately (review L1: fxvpn/proton parity — the
// session bootstrap must not wait a full CheapInterval). ctx feeds every
// probe: cancelling it (daemon Stop) aborts in-flight network I/O instead
// of orphaning a wedged handshake (review C2c).
func (h *HealthSupervisor) Run(ctx context.Context) {
	h.mu.Lock()
	h.runCtx = ctx
	h.mu.Unlock()
	h.Tick(h.cfg.Now())
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
// all decisions derive from now + recorded timestamps. Synchronous and
// bounded: every network op runs WITHOUT the state mutex and under a hard
// context deadline, so a silent node delays one tick by at most its budget
// and Status() stays responsive throughout.
func (h *HealthSupervisor) Tick(now time.Time) {
	// One flight at a time: an async Kick colliding with the ticker step
	// just no-ops (the ticker step is at most one interval behind).
	if !h.busy.CompareAndSwap(false, true) {
		return
	}
	defer h.busy.Store(false)

	done := tickDone{}
	for step := 0; step < maxTickSteps; step++ {
		plan := h.planLocked(now, &done)
		if plan.action == actNone {
			break
		}
		res := h.execute(plan)
		if !h.apply(plan, res, now, &done) {
			break
		}
	}
	// Node-cache persistence rides AFTER the state phases: file I/O never
	// happens under h.mu (C2 discipline).
	h.flushPendingCache()
}

// ---------------------------------------------------------------------------
// Plan (caller holds h.mu): decide ONE action from the current state.
// ---------------------------------------------------------------------------

func (h *HealthSupervisor) planLocked(now time.Time, done *tickDone) tickPlan {
	h.lastProbeAt = now
	h.started = true

	if h.degraded != "" {
		return tickPlan{action: actNone} // fail-closed terminal state
	}
	if h.rotateQueued && !done.rotated {
		return tickPlan{action: actRotate, region: h.region}
	}
	if !h.sessionOK {
		if h.credsDead {
			if !done.recovered {
				return tickPlan{action: actRecover}
			}
			return tickPlan{action: actNone}
		}
		if !done.bootstrapped {
			return tickPlan{action: actBootstrap}
		}
		return tickPlan{action: actNone}
	}
	// Desired-region return (Nova begin_desired_retry) outranks refresh.
	if h.region != h.cfg.Region && !h.nextDesiredRetry.IsZero() &&
		now.After(h.nextDesiredRetry) && !done.desiredRetry {
		return tickPlan{action: actDesiredRetry}
	}
	// JWT refresh cadence (4h).
	if !h.lastRefreshAt.IsZero() && now.Sub(h.lastRefreshAt) >= h.cfg.RefreshEvery && !done.refreshed {
		return tickPlan{action: actRefresh}
	}
	// Two-level probe: deep when due, cheap otherwise — once per tick.
	if !done.probed {
		entry := h.currentLocked()
		deepDue := h.lastDeepAt.IsZero() || now.Sub(h.lastDeepAt) >= h.cfg.DeepInterval
		return tickPlan{action: actProbe, deep: deepDue, entry: entry}
	}
	return tickPlan{action: actNone}
}

// ---------------------------------------------------------------------------
// Execute (NO lock held): bounded network I/O only.
// ---------------------------------------------------------------------------

func (h *HealthSupervisor) runCtxOf() context.Context {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.runCtx != nil {
		return h.runCtx
	}
	return context.Background()
}

// boundedCtx derives runCtx with a hard deadline (every tick op).
func (h *HealthSupervisor) boundedCtx(budget time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(h.runCtxOf(), budget)
}

func (h *HealthSupervisor) execute(plan tickPlan) stepResult {
	switch plan.action {
	case actBootstrap:
		return h.execBootstrap()
	case actRecover:
		return h.execRecover()
	case actDesiredRetry:
		ctx, cancel := h.boundedCtx(controlBudget)
		defer cancel()
		ips, err := h.c.Discover(ctx, h.desiredRegion())
		return stepResult{discover: ips, discErr: err, discN: 1}
	case actRefresh:
		ctx, cancel := h.boundedCtx(controlBudget)
		defer cancel()
		return stepResult{err: h.c.RefreshCredentials(ctx)}
	case actProbe:
		return h.execProbe(plan)
	case actRotate:
		return h.execRotate(plan)
	default:
		return stepResult{}
	}
}

func (h *HealthSupervisor) execBootstrap() stepResult {
	ctx, cancel := h.boundedCtx(controlBudget)
	defer cancel()
	if err := h.c.EnsureSession(ctx); err != nil {
		return stepResult{err: err}
	}
	ips, derr := h.c.Discover(ctx, h.effectiveRegion())
	return stepResult{discover: ips, discErr: derr, discN: 1}
}

func (h *HealthSupervisor) execRecover() stepResult {
	// Cap check + restart stamp happen under the state lock (cheap, no I/O);
	// the expensive registration runs unlocked.
	now := h.cfg.Now()
	if !h.claimRecoverySlot(now) {
		return stepResult{capped: true}
	}
	ctx, cancel := h.boundedCtx(controlBudget)
	defer cancel()
	if err := h.c.RegisterNew(ctx); err != nil {
		return stepResult{err: err}
	}
	ips, derr := h.c.Discover(ctx, h.effectiveRegion())
	return stepResult{discover: ips, discErr: derr, discN: 1}
}

// claimRecoverySlot applies the <=6/hour cap + cooldown to one recovery
// attempt; true means the caller may run the expensive registration.
func (h *HealthSupervisor) claimRecoverySlot(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneRestarts(now)
	if now.Before(h.cooldownUntil) || len(h.restarts) >= h.cfg.RestartCapPerHour {
		if u := now.Add(h.cfg.Cooldown); u.After(h.cooldownUntil) {
			h.cooldownUntil = u
		}
		return false
	}
	h.restarts = append(h.restarts, now)
	return true
}

func (h *HealthSupervisor) execProbe(plan tickPlan) stepResult {
	budget := h.cfg.ProbeBudgetCheap
	if plan.deep {
		budget = h.cfg.ProbeBudgetDeep
	}
	ctx, cancel := h.boundedCtx(budget)
	defer cancel()
	if plan.deep {
		return stepResult{err: h.pb.ProbeDeep(ctx, plan.entry)}
	}
	return stepResult{err: h.pb.ProbeCheap(ctx, plan.entry)}
}

// execRotate re-discovers the current region (cache-exhausted rotation).
// When that fails and the desired region is EU, the Nova alternate commit
// + AM discover attempt piggybacks on the same step (old rotate() parity).
func (h *HealthSupervisor) execRotate(plan tickPlan) stepResult {
	ctx, cancel := h.boundedCtx(controlBudget)
	defer cancel()
	res := stepResult{}
	res.discover, res.discErr = h.c.Discover(ctx, plan.region)
	res.discN = 1
	if (res.discErr != nil || len(res.discover) == 0) && h.euAlternateEligible(plan.region) {
		res.altRegion, res.altErr = h.c.Discover(ctx, RegionAM)
		res.altIsAM = true
		res.discN++
	}
	return res
}

// euAlternateEligible snapshots whether the EU->AM alternate may be tried
// (only EU has an explicit AM fallback; AS and AM retry in place).
func (h *HealthSupervisor) euAlternateEligible(failedRegion string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg.Region == RegionEU && failedRegion != RegionAM
}

// ---------------------------------------------------------------------------
// Apply (locked inside): fold results into the state machine. Returns false
// when the pipeline stops (degraded / bootstrap failure / rotation done).
// ---------------------------------------------------------------------------

func (h *HealthSupervisor) apply(plan tickPlan, res stepResult, now time.Time, done *tickDone) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch plan.action {
	case actBootstrap:
		done.bootstrapped = true
		return h.applyBootstrap(res, now)
	case actRecover:
		done.recovered = true
		return h.applyRecover(res, now)
	case actDesiredRetry:
		done.desiredRetry = true
		return h.applyDesiredRetry(res, now)
	case actRefresh:
		done.refreshed = true
		return h.applyRefresh(res, now)
	case actProbe:
		done.probed = true
		return h.applyProbe(plan.deep, res.err, now)
	case actRotate:
		done.rotated = true
		return h.applyRotate(plan, res, now)
	}
	return true
}

func (h *HealthSupervisor) applyBootstrap(res stepResult, now time.Time) bool {
	if res.err != nil {
		h.lastErr = res.err.Error()
		h.noteAPIFailure(res.err, now)
		return false
	}
	h.sessionOK = true
	h.lastRefreshAt = now
	if res.discN > 0 {
		h.discoverCalls += res.discN
		if res.discErr == nil && len(res.discover) > 0 {
			h.adoptDiscoverLocked(res.discover, h.region, now)
		} else {
			// API refused the region (801) => design §2 item 5: work from
			// the cache. Any other discover failure => offline-boot asset
			// only while fresh enough (review H3).
			if res.discErr != nil {
				h.lastErr = res.discErr.Error()
			}
			h.adoptCacheFallbackLocked(h.region, now, IsClass(res.discErr, ClassDiscoverRegionUnavailable))
		}
	}
	return true
}

func (h *HealthSupervisor) applyRecover(res stepResult, now time.Time) bool {
	if res.capped {
		// Restart cap holds: stay unbootstrapped, retry next tick (the
		// cooldown window slides inside claimRecoverySlot).
		h.lastErr = errRestartCapped.Error()
		return false
	}
	if res.err != nil {
		h.lastErr = res.err.Error()
		h.noteAPIFailure(res.err, now)
		return false
	}
	h.credsDead = false
	h.sessionOK = true
	h.lastRefreshAt = now
	h.listening = false
	h.lastDeepOK = false
	if res.discN > 0 {
		h.discoverCalls += res.discN
		if res.discErr == nil && len(res.discover) > 0 {
			h.adoptDiscoverLocked(res.discover, h.region, now)
		} else {
			h.adoptCacheFallbackLocked(h.region, now, IsClass(res.discErr, ClassDiscoverRegionUnavailable))
		}
	}
	return true
}

// applyDesiredRetry folds the Nova begin_desired_retry outcome.
func (h *HealthSupervisor) applyDesiredRetry(res stepResult, now time.Time) bool {
	h.discoverCalls += res.discN
	if res.discErr == nil && len(res.discover) > 0 {
		h.adoptDiscoverLocked(res.discover, h.cfg.Region, now)
		h.retryRound = 0
		h.nextDesiredRetry = time.Time{}
		return true
	}
	if res.discErr != nil {
		h.lastErr = res.discErr.Error()
	}
	// 801 on the desired region with a cached list for it: keep serving
	// from the cache instead of silently failing the switch (review M4).
	if IsClass(res.discErr, ClassDiscoverRegionUnavailable) && h.adoptCacheFallbackLocked(h.cfg.Region, now, true) {
		h.retryRound = 0
		h.nextDesiredRetry = time.Time{}
		return true
	}
	h.scheduleDesiredRetry(now)
	return true
}

func (h *HealthSupervisor) applyRefresh(res stepResult, now time.Time) bool {
	h.lastRefreshAt = now // do not hammer within the same interval
	if res.err != nil {
		h.lastErr = res.err.Error()
		h.noteAPIFailure(res.err, now)
	}
	return true
}

func (h *HealthSupervisor) applyRotate(plan tickPlan, res stepResult, now time.Time) bool {
	h.rotateQueued = false
	h.discoverCalls += res.discN
	if res.discErr == nil && len(res.discover) > 0 {
		h.adoptDiscoverLocked(res.discover, plan.region, now)
		return false // rotation completes the tick (old rotate() parity)
	}
	// 801/failed rediscover with a cached list: adopt the offline asset
	// before reaching for the alternate (review M4/H3).
	if h.adoptCacheFallbackLocked(plan.region, now, IsClass(res.discErr, ClassDiscoverRegionUnavailable)) {
		return false
	}
	// Rediscover failed: alternate region per Nova — only EU has an explicit
	// AM fallback; the switch commits BEFORE its discovery succeeds so the
	// scheduled retries target the alternate even while it is unreachable.
	// Any other desired region is retried in place.
	if res.altIsAM {
		h.region = RegionAM
		if res.altErr == nil && len(res.altRegion) > 0 {
			h.adoptDiscoverLocked(res.altRegion, RegionAM, now)
		}
	}
	h.scheduleDesiredRetry(now)
	return false
}

// noteAPIFailure routes control-channel failures: pin mismatch is a terminal
// degraded state (fail closed — design §3), auth refusal marks the local
// credentials dead and defers recovery to the next plan step (actRecover —
// the restart cap still applies); everything else is surfaced only.
// Caller holds h.mu.
func (h *HealthSupervisor) noteAPIFailure(err error, now time.Time) {
	if IsClass(err, ClassAPIPinMismatch) {
		h.degraded = string(ClassAPIPinMismatch)
		return
	}
	if IsClass(err, ClassAPIAuthRefused) || errors.Is(err, ErrIdentityCorrupt) {
		h.credsDead = true
		h.sessionOK = false
	}
}

// applyProbe folds one probe outcome into the rotation counters.
func (h *HealthSupervisor) applyProbe(deep bool, err error, now time.Time) bool {
	switch probeVerdictOf(err) {
	case ProbeCantBind:
		h.lastVerdict = ProbeCantBind
		if err != nil {
			h.lastErr = err.Error()
		}
		return true
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
		return true
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
			h.consecFails = 0
			if len(h.nodes) > 1 && h.idx < len(h.nodes)-1 {
				h.idx++ // next candidate from the cache, no I/O needed
			} else {
				h.rotateQueued = true // cache exhausted -> rediscover step
			}
		}
		return true
	}
}

// adoptDiscoverLocked replaces the node cache (idx reset) from a LIVE
// discover and queues the offline-asset persistence.
func (h *HealthSupervisor) adoptDiscoverLocked(ips []SEIPEntry, region string, now time.Time) {
	h.nodes = ips
	h.idx = 0
	h.region = region
	h.nodesSource = "live"
	h.nodesSaved = now
	if h.cache != nil {
		h.pendingSave = &NodeCacheRecord{Region: region, Entries: ips, SavedAt: now}
	}
}

// adoptCacheFallbackLocked adopts the persisted offline asset when the
// live discover failed. force=true (801 region-unavailable) adopts even a
// stale exact-region record (design §2 item 5: "работать из кэша");
// otherwise only a fresh-enough record is auto-adopted. Returns whether
// the cache carried usable nodes. Caller holds h.mu.
func (h *HealthSupervisor) adoptCacheFallbackLocked(region string, now time.Time, force bool) bool {
	if h.cache == nil {
		return false
	}
	rec, ok := h.cache.FallbackFor(region, now)
	if !ok {
		return false
	}
	if !force && !FreshEnough(rec, now) {
		return false
	}
	if rec.Region != region && !force {
		// A foreign-region record only substitutes when the API said the
		// requested region is gone (801) — otherwise wait for the live
		// discover (region intent must not drift silently).
		return false
	}
	h.nodes = rec.Entries
	h.idx = 0
	h.region = rec.Region
	h.nodesSource = "cache"
	h.nodesSaved = rec.SavedAt
	return true
}

// flushPendingCache persists the queued record outside the state mutex.
func (h *HealthSupervisor) flushPendingCache() {
	h.mu.Lock()
	rec := h.pendingSave
	h.pendingSave = nil
	cache := h.cache
	h.mu.Unlock()
	if rec == nil || cache == nil {
		return
	}
	_ = cache.Save(rec.Region, rec.Entries, rec.SavedAt)
}

// effectiveRegion snapshots the effective region for unlocked I/O phases.
func (h *HealthSupervisor) effectiveRegion() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.region
}

// desiredRegion snapshots the desired region for unlocked I/O phases.
func (h *HealthSupervisor) desiredRegion() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg.Region
}

// errRestartCapped reports that recovery was withheld by the <=6/hour cap.
var errRestartCapped = errors.New("restart capped")

// ActiveEntry returns a copy of the currently selected node entry.
func (h *HealthSupervisor) ActiveEntry() SEIPEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.currentLocked()
}

// SetDesiredRegion switches the desired megaregion WITHOUT touching the
// device identity (design §5: the device stays the same — region lives in
// discover). Discovery I/O runs OUTSIDE the state mutex (review C2
// discipline); failure schedules the usual backoff.
func (h *HealthSupervisor) SetDesiredRegion(region string) error {
	r, err := NormalizeRegion(region)
	if err != nil {
		return err
	}
	h.mu.Lock()
	if h.cfg.Region == r {
		h.mu.Unlock()
		return nil
	}
	h.cfg.Region = r
	h.degraded = "" // a live region command re-arms a degraded supervisor
	if !h.sessionOK {
		h.mu.Unlock()
		return nil
	}
	h.mu.Unlock()

	ctx, cancel := h.boundedCtx(controlBudget)
	defer cancel()
	ips, derr := h.c.Discover(ctx, r)

	now := h.cfg.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.discoverCalls++
	if derr == nil && len(ips) > 0 {
		h.adoptDiscoverLocked(ips, r, now)
		h.retryRound = 0
		h.nextDesiredRetry = time.Time{}
		return nil
	}
	if derr != nil {
		h.lastErr = derr.Error()
	} else {
		h.lastErr = fmt.Sprintf("discover %s returned no endpoints", r)
	}
	// 801 with a cached list for the requested region: the switch still
	// happens — from the offline asset (review M4: the region command must
	// not silently fail while the cache is alive).
	if IsClass(derr, ClassDiscoverRegionUnavailable) && h.adoptCacheFallbackLocked(r, now, true) {
		h.retryRound = 0
		h.nextDesiredRetry = time.Time{}
		return nil
	}
	// Alternate-region machinery takes over from here: if we were sitting
	// on an alternate for the old desired, the next Tick returns toward
	// the new desired via begin_desired_retry scheduling.
	h.scheduleDesiredRetry(h.cfg.Now())
	if derr != nil {
		return derr
	}
	return errors.New(h.lastErr)
}

// Status snapshots the supervisor state. Never blocks on network I/O —
// the mutex guards the state machine only (review C2).
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
		NodesSource:      h.nodesSource,
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

func (h *HealthSupervisor) now() time.Time { return h.cfg.Now() }

func (h *HealthSupervisor) currentLocked() SEIPEntry {
	if len(h.nodes) == 0 {
		return SEIPEntry{}
	}
	return h.nodes[h.idx%len(h.nodes)]
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

func (h *HealthSupervisor) scheduleDesiredRetry(now time.Time) {
	delay := h.cfg.RetryBase << min64(int64(h.retryRound), 6)
	if delay > h.cfg.RetryMax {
		delay = h.cfg.RetryMax
	}
	h.retryRound++
	h.nextDesiredRetry = now.Add(delay)
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
