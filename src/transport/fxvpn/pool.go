// Account pool (design Part II II.2.1): lifecycle provisioning ->
// verifying -> active -> standby -> cooling_down -> exhausted(reset_at) ->
// banned/refused over the real FxA/Guardian clients from FX1.
//
// Rotation contract (pre-emptive):
//   - trigger A: remaining quota fraction below RotateThresholdPct (def 15);
//   - trigger B: X-Quota-Reset inside ResetLeadWindow (the serving account
//     steps aside BEFORE its refill so it refills undisturbed);
//   - the NEXT account is fully warmed (fresh FxA access + NEW Guardian
//     proxy pass) BEFORE the atomic swap; live TCP streams of the old
//     session die naturally - the pool swaps identity descriptors only,
//     session objects belong to the supervisor (FX4 wiring).
//
// Reset-aware recycling: exhausted accounts return to standby when their
// reset timestamp passes; exhausted-without-reset-info stays parked (manual).
//
// BLOCKED semantics: when nothing can serve (all exhausted-in-future /
// banned / refused), RotateIfDue returns ErrPoolBlocked and announces
// fxvpn_pool_blocked exactly ONCE per episode - no loops, ever.
package fxvpn

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Account lifecycle states (design II.2.1).
type AccountState string

const (
	StateProvisioning AccountState = "provisioning"
	StateVerifying    AccountState = "verifying"    // needs interactive code (L0 CLI path)
	StateStandby      AccountState = "standby"      // verified, ready to serve
	StateActive       AccountState = "active"       // serving traffic
	StateCoolingDown  AccountState = "cooling_down" // retired; eligible after cooldown
	StateExhausted    AccountState = "exhausted"    // quota gone until ResetAt
	StateBanned       AccountState = "banned"       // terminal: FxA rejects credentials
	StateRefused      AccountState = "refused"      // terminal-ish: entitlement rejected
)

// Pool event types (taxonomy continuation).
const (
	EvAccountActivated = "fxvpn_account_activated"
	EvQuotaWarning     = "fxvpn_quota_warning"
	EvPoolBlocked      = "fxvpn_pool_blocked"
	EvAccountExhausted = "fxvpn_account_exhausted"
	EvAccountRecycled  = "fxvpn_account_recycled"
)

var ErrPoolBlocked = errors.New("fxvpn: account pool blocked (no servable account)")

// PoolConfig tunes the pool; zero durations/counts take defaults.
type PoolConfig struct {
	RotateThresholdPct int           // default 15 (% of remaining)
	ResetLeadWindow    time.Duration // default 24h
	CoolingDownPeriod  time.Duration // default 5m
	RefreshMaxAttempts int           // default 3, then banned
	PassRenewLead      time.Duration // default 2m (reference proxyPassRenewLead)
	RefreshBackoffBase time.Duration // default 30s

	Now    func() time.Time
	Jitter func() time.Duration // extra backoff randomness; tests pin it
	Events func(PoolEvent)
}

// PoolEvent is one taxonomy occurrence; Label carries the redacted account
// label only - tokens/passwords NEVER travel through events (red line 2).
type PoolEvent struct {
	Type   string
	Label  string
	Detail string
}

type accountRT struct {
	acct  Account
	state AccountState

	quotaLeft int64 // -1 unknown
	quotaMax  int64 // -1 unknown
	resetAt   time.Time

	access         *TokenResponse
	accessExpireAt time.Time
	pass           *ProxyPassInfo

	refreshFails int
	nextTryAt    time.Time
	eligibleAt   time.Time // cooling_down gate

	warned bool // quota warning announced for the current cycle
}

// Pool manages the account fleet over FX1 control-plane clients.
type Pool struct {
	mu               sync.Mutex
	cfg              PoolConfig
	store            *AccountStore
	fxa              *FXA
	guardian         *Guardian
	accounts         []*accountRT
	active           int // index into accounts; -1 none
	blockedAnnounced bool
}

// NewPool loads the store and builds the runtime. Absent file yields an
// empty pool (Status reports empty/blocked); corrupt file propagates
// ErrStoreCorrupt so the caller can quarantine-react deliberately.
func NewPool(store *AccountStore, fxa *FXA, g *Guardian, cfg PoolConfig) (*Pool, error) {
	if cfg.RotateThresholdPct <= 0 {
		cfg.RotateThresholdPct = 15
	}
	if cfg.ResetLeadWindow <= 0 {
		cfg.ResetLeadWindow = 24 * time.Hour
	}
	if cfg.CoolingDownPeriod <= 0 {
		cfg.CoolingDownPeriod = 5 * time.Minute
	}
	if cfg.RefreshMaxAttempts <= 0 {
		cfg.RefreshMaxAttempts = 3
	}
	if cfg.PassRenewLead <= 0 {
		cfg.PassRenewLead = 2 * time.Minute
	}
	if cfg.RefreshBackoffBase <= 0 {
		cfg.RefreshBackoffBase = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Jitter == nil {
		cfg.Jitter = func() time.Duration { return 0 }
	}
	p := &Pool{cfg: cfg, store: store, fxa: fxa, guardian: g, active: -1}
	file, err := store.Load()
	if err != nil {
		if errors.Is(err, ErrStoreAbsent) {
			return p, nil
		}
		return nil, err
	}
	for _, a := range file.Accounts {
		p.accounts = append(p.accounts, &accountRT{acct: a, state: StateProvisioning, quotaLeft: -1, quotaMax: -1})
	}
	return p, nil
}

// Bootstrap brings every account up (design II.2.1 provisioning path).
// Single-account failures never abort the walk: they land the account in
// verifying/exhausted/banned/refused and the pool continues. Hard errors
// (control-plane transport, pin mismatch, challenge) propagate - fail-closed.
func (p *Pool) Bootstrap(ctx context.Context) error {
	p.mu.Lock()
	order := make([]*accountRT, len(p.accounts))
	copy(order, p.accounts)
	p.mu.Unlock()

	for _, rt := range order {
		if err := p.bringUp(ctx, rt); err != nil {
			return err
		}
	}
	return nil
}

// bringUp moves one account as far as it can go right now.
func (p *Pool) bringUp(ctx context.Context, rt *accountRT) error {
	p.mu.Lock()
	if rt.state == StateActive || rt.state == StateStandby {
		p.mu.Unlock()
		return nil
	}
	now := p.cfg.Now()
	if now.Before(rt.nextTryAt) {
		p.mu.Unlock()
		return nil // backoff gate; not an error
	}
	needsInteractive := rt.acct.RefreshToken == ""
	p.mu.Unlock()

	if needsInteractive {
		// L0 contract: the daemon never invents credentials. Password-only
		// accounts wait for the interactive CLI (login + emailed code).
		p.setState(rt, StateVerifying)
		return nil
	}

	tok, err := p.fxa.RefreshToken(ctx, rt.acct.RefreshToken)
	if err != nil {
		return p.refreshFailed(rt, err)
	}
	p.mu.Lock()
	rt.access = tok
	rt.accessExpireAt = now.Add(time.Duration(tok.ExpiresIn) * time.Second)
	rt.refreshFails = 0
	p.mu.Unlock()

	pass, err := p.fetchPass(ctx, rt, tok.AccessToken)
	if err != nil {
		return err // hard errors propagate; exhaustion/refusal already recorded
	}
	if pass == nil {
		return nil // account landed exhausted/refused
	}
	p.activateLocked(rt, pass)
	return nil
}

// refreshFailed applies backoff and the N-strikes ban rule.
func (p *Pool) refreshFailed(rt *accountRT, err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	rt.refreshFails++
	base := p.cfg.RefreshBackoffBase << uint(minInt(rt.refreshFails-1, 6))
	rt.nextTryAt = p.cfg.Now().Add(base + p.cfg.Jitter())
	if rt.refreshFails >= p.cfg.RefreshMaxAttempts {
		rt.state = StateBanned
		p.emit(PoolEvent{Type: EvPoolBlocked, Label: labelOf(rt), Detail: "account banned after repeated refresh failures"})
		return nil // pool-level concern, not a hard error
	}
	rt.state = StateVerifying
	return nil
}

// fetchPass obtains a fresh proxy pass for rt's access token, recording
// quota/entitlement verdicts as account states (nil,nil = state recorded).
func (p *Pool) fetchPass(ctx context.Context, rt *accountRT, accessToken string) (*ProxyPassInfo, error) {
	pass, err := p.guardian.FetchProxyPass(ctx, accessToken)
	if err == nil {
		return pass, nil
	}
	var qe *QuotaError
	if errors.As(err, &qe) {
		reset := time.Time{}
		if qe.HasRetryAfter {
			reset = p.cfg.Now().Add(qe.RetryAfter)
		}
		p.mu.Lock()
		p.markExhausted(rt, reset)
		p.mu.Unlock()
		return nil, nil //nolint:nilnil // exhaustion is a state, not a failure
	}
	var ti *TokenInvalidError
	if errors.As(err, &ti) {
		// One activation attempt before refusing (reference refresh->activate->retry).
		if _, aerr := p.guardian.Activate(ctx, accessToken); aerr == nil {
			pass, rerr := p.guardian.FetchProxyPass(ctx, accessToken)
			if rerr == nil {
				return pass, nil
			}
		}
		p.mu.Lock()
		rt.state = StateRefused
		p.mu.Unlock()
		p.emit(PoolEvent{Type: EvPoolBlocked, Label: labelOf(rt), Detail: "entitlement refused"})
		return nil, nil //nolint:nilnil
	}
	return nil, err // pin mismatch / challenge / transport: fail-closed upward
}

// markExhausted records quota death for an account (mu held by caller where
// noted; this variant locks itself when called from fetch paths).
func (p *Pool) markExhausted(rt *accountRT, reset time.Time) {
	rt.state = StateExhausted
	rt.resetAt = reset
	rt.warned = false
	if p.active >= 0 && p.accounts[p.active] == rt {
		p.active = -1 // seat vacated immediately
	}
	p.emit(PoolEvent{Type: EvAccountExhausted, Label: labelOf(rt), Detail: describeReset(reset)})
}

// activateLocked promotes a warmed account to standby and to active when
// the seat is empty. Caller must NOT hold mu (fetch happens outside).
func (p *Pool) activateLocked(rt *accountRT, pass *ProxyPassInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rt.pass = pass
	rt.quotaLeft = parseQuotaInt(pass.QuotaLeft, -1)
	rt.quotaMax = parseQuotaInt(pass.QuotaMax, -1)
	rt.resetAt = parseResetTime(pass.QuotaReset)
	rt.warned = false
	rt.state = StateStandby
	if p.active < 0 || p.accounts[p.active] == nil {
		p.setActiveIndex(indexOf(p.accounts, rt))
	}
}

func (p *Pool) setActiveIndex(i int) {
	p.active = i
	if i >= 0 && i < len(p.accounts) {
		p.accounts[i].state = StateActive
	}
	p.emit(PoolEvent{Type: EvAccountActivated, Label: p.activeLabelLocked(), Detail: ""})
}

// RotateIfDue applies the pre-emptive rotation contract to the ACTIVE
// account: threshold/reset-lead triggers warm up the next standby and swap
// atomically; a vacated seat (exhaustion) is filled if possible; when
// nothing can serve, ErrPoolBlocked + one blocked announcement.
func (p *Pool) RotateIfDue(ctx context.Context) (bool, error) {
	p.mu.Lock()
	now := p.cfg.Now()
	var active *accountRT
	if p.active >= 0 {
		active = p.accounts[p.active]
	}
	due := false
	if active != nil && active.state == StateActive {
		due = p.rotationDueLocked(active, now)
	}
	if !due && active != nil && active.state == StateActive {
		p.mu.Unlock()
		return false, nil
	}
	order := p.candidateOrderLocked(p.active)
	p.mu.Unlock()

	for _, cand := range order {
		st, elig := p.stateAndEligibility(cand)
		switch {
		case st == StateCoolingDown && now.Before(elig):
			continue // retired too recently: anti-flap
		case st == StateVerifying:
			if now.Before(p.nextTryAtOf(cand)) {
				continue // refresh backoff gate
			}
		case st != StateStandby && st != StateCoolingDown:
			continue // not servable (exhausted/banned/refused/active)
		}
		pass, err := p.warmCandidate(ctx, cand)
		if err != nil {
			return false, err // hard control-plane error: fail-closed
		}
		if pass == nil {
			continue // landed exhausted/refused during warmup; try next
		}
		p.swapTo(cand, pass)
		return true, nil
	}

	// Nothing warmed: structural verdict.
	p.mu.Lock()
	blockedNow := p.computeBlockedLocked(now)
	announced := false
	if blockedNow && !p.blockedAnnounced {
		p.blockedAnnounced = true
		announced = true
	} else if !blockedNow {
		p.blockedAnnounced = false
	}
	p.mu.Unlock()
	if blockedNow {
		if announced {
			p.emit(PoolEvent{Type: EvPoolBlocked, Label: "", Detail: "no servable account"})
		}
		return false, ErrPoolBlocked
	}
	return false, nil
}

// rotationDueLocked implements triggers A (threshold) and B (reset lead).
func (p *Pool) rotationDueLocked(a *accountRT, now time.Time) bool {
	if a.quotaMax > 0 && a.quotaLeft >= 0 {
		if a.quotaLeft*100 < a.quotaMax*int64(p.cfg.RotateThresholdPct) {
			return true
		}
	}
	if !a.resetAt.IsZero() && now.Add(p.cfg.ResetLeadWindow).After(a.resetAt) {
		return true
	}
	return false
}

// candidateOrderLocked lists accounts starting after `from` (round-robin;
// from<0 walks from index 0).
func (p *Pool) candidateOrderLocked(from int) []*accountRT {
	n := len(p.accounts)
	if n == 0 {
		return nil
	}
	out := make([]*accountRT, 0, n)
	for i := 1; i <= n; i++ {
		idx := from + i
		if from < 0 {
			idx = i - 1
		}
		out = append(out, p.accounts[idx%n])
	}
	return out
}

func (p *Pool) nextTryAtOf(rt *accountRT) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return rt.nextTryAt
}

// warmCandidate refreshes access when stale and mints a NEW proxy pass.
func (p *Pool) warmCandidate(ctx context.Context, rt *accountRT) (*ProxyPassInfo, error) {
	now := p.cfg.Now()
	p.mu.Lock()
	if now.Before(rt.nextTryAt) {
		p.mu.Unlock()
		return nil, nil // backoff gate
	}
	needRefresh := rt.access == nil || now.Add(p.cfg.PassRenewLead).After(rt.accessExpireAt)
	hasRT := rt.acct.RefreshToken != ""
	rtState := rt.state
	p.mu.Unlock()
	_ = rtState

	if needRefresh {
		if !hasRT {
			p.mu.Lock()
			rt.state = StateVerifying
			p.mu.Unlock()
			return nil, nil
		}
		tok, err := p.fxa.RefreshToken(ctx, rt.acct.RefreshToken)
		if err != nil {
			if ferr := p.refreshFailed(rt, err); ferr != nil {
				return nil, ferr
			}
			return nil, nil
		}
		p.mu.Lock()
		rt.access = tok
		rt.accessExpireAt = now.Add(time.Duration(tok.ExpiresIn) * time.Second)
		rt.refreshFails = 0
		p.mu.Unlock()
	}

	pass, err := p.fetchPass(ctx, rt, p.accessTokenOf(rt))
	if err != nil {
		return nil, err
	}
	if pass == nil {
		return nil, nil
	}

	p.mu.Lock()
	rt.pass = pass
	rt.quotaLeft = parseQuotaInt(pass.QuotaLeft, -1)
	rt.quotaMax = parseQuotaInt(pass.QuotaMax, -1)
	rt.resetAt = parseResetTime(pass.QuotaReset)
	rt.warned = false
	if rt.state == StateCoolingDown || rt.state == StateProvisioning {
		rt.state = StateStandby
	}
	p.mu.Unlock()
	return pass, nil
}

// swapTo performs the atomic identity switch: old active retires into
// cooling_down, candidate takes the seat with its fresh pass.
func (p *Pool) swapTo(cand *accountRT, pass *ProxyPassInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now()
	if p.active >= 0 && p.accounts[p.active] != cand {
		old := p.accounts[p.active]
		old.state = StateCoolingDown
		old.eligibleAt = now.Add(p.cfg.CoolingDownPeriod)
	}
	cand.pass = pass
	cand.warned = false
	cand.state = StateStandby
	p.setActiveIndex(indexOf(p.accounts, cand))
}

// ReportQuota records fresh X-Quota-* numbers for the ACTIVE account and
// announces fxvpn_quota_warning exactly once per cycle when the remaining
// fraction crosses the threshold.
func (p *Pool) ReportQuota(left, max int64, reset time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active < 0 {
		return
	}
	a := p.accounts[p.active]
	a.quotaLeft, a.quotaMax = left, max
	if !reset.IsZero() {
		a.resetAt = reset
	}
	if a.warned || max <= 0 || left < 0 {
		return
	}
	if left*100 < max*int64(p.cfg.RotateThresholdPct) {
		a.warned = true
		p.emit(PoolEvent{Type: EvQuotaWarning, Label: labelOf(a),
			Detail: strconv.FormatInt(left, 10) + "/" + strconv.FormatInt(max, 10)})
	}
}

// MarkExhausted records quota death for the ACTIVE account (Guardian 429 or
// edge CONNECT 429): seat vacates immediately, reset calendar applies.
func (p *Pool) MarkExhausted(reset time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active < 0 {
		return
	}
	p.markExhausted(p.accounts[p.active], reset)
}

// MarkAuthRejected puts the ACTIVE account back into verifying so the next
// rotation attempt refreshes credentials once; repeated strikes ban it.
func (p *Pool) MarkAuthRejected() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active < 0 {
		return
	}
	a := p.accounts[p.active]
	a.state = StateVerifying
	a.nextTryAt = p.cfg.Now().Add(p.cfg.RefreshBackoffBase + p.cfg.Jitter())
	p.active = -1
}

// RecycleDue returns exhausted accounts whose reset has passed back to
// standby (reset-aware recycling) and reports their labels.
func (p *Pool) RecycleDue() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now()
	var out []string
	for _, rt := range p.accounts {
		if rt.state != StateExhausted || rt.resetAt.IsZero() || rt.resetAt.After(now) {
			continue
		}
		rt.state = StateStandby
		rt.warned = false
		out = append(out, labelOf(rt))
		p.emit(PoolEvent{Type: EvAccountRecycled, Label: labelOf(rt)})
	}
	return out
}

// RenewActivePassIfNeeded re-mints the active proxy pass when inside the
// renewal lead (reference proxyPassRenewLead = 2 min). Returns whether a
// new pass was issued.
func (p *Pool) RenewActivePassIfNeeded(ctx context.Context) (*ProxyPassInfo, error) {
	p.mu.Lock()
	if p.active < 0 {
		p.mu.Unlock()
		return nil, nil
	}
	a := p.accounts[p.active]
	expiredSoon := a.pass == nil || p.cfg.Now().Add(p.cfg.PassRenewLead).After(a.pass.ExpiresAt())
	p.mu.Unlock()
	if !expiredSoon {
		return nil, nil
	}
	pass, err := p.guardian.FetchProxyPass(ctx, p.accessTokenOf(a))
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	a.pass = pass
	p.mu.Unlock()
	return pass, nil
}

// AccountView is the redaction-safe snapshot row (GUI/API shape, Дополнение 3).
type AccountView struct {
	Label     string       `json:"label"`
	State     AccountState `json:"state"`
	QuotaLeft int64        `json:"quota_left"`
	QuotaMax  int64        `json:"quota_max"`
	ResetAt   string       `json:"reset_at,omitempty"`
	Active    bool         `json:"active"`
}

// PoolStatus is the structural verdict for supervisors/GUI.
type PoolStatus struct {
	Blocked bool          `json:"blocked"`
	Empty   bool          `json:"empty"`
	Views   []AccountView `json:"accounts"`
}

// Status snapshots the pool. Blocked is structural: no account can serve
// right now (all exhausted-in-future / banned / refused / verifying).
func (p *Pool) Status() PoolStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now()
	st := PoolStatus{}
	st.Empty = len(p.accounts) == 0
	for i, rt := range p.accounts {
		v := AccountView{
			Label:     labelOf(rt),
			State:     rt.state,
			QuotaLeft: rt.quotaLeft,
			QuotaMax:  rt.quotaMax,
			Active:    i == p.active,
		}
		if !rt.resetAt.IsZero() {
			v.ResetAt = rt.resetAt.UTC().Format(time.RFC3339)
		}
		st.Views = append(st.Views, v)
	}
	st.Blocked = p.computeBlockedLocked(now)
	return st
}

// ActiveBearer returns the Authorization header value for the serving
// session, plus whether an active account exists at all.
func (p *Pool) ActiveBearer() (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active < 0 || p.accounts[p.active].pass == nil {
		return "", false
	}
	return p.accounts[p.active].pass.BearerToken(), true
}

// ---- internal helpers --------------------------------------------------------

func (p *Pool) computeBlockedLocked(now time.Time) bool {
	for _, rt := range p.accounts {
		switch rt.state {
		case StateActive, StateStandby:
			return false
		case StateCoolingDown:
			if !now.Before(rt.eligibleAt) {
				return false
			}
		}
	}
	return true
}

func (p *Pool) stateAndEligibility(rt *accountRT) (AccountState, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return rt.state, rt.eligibleAt
}

func (p *Pool) stateOf(rt *accountRT) AccountState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return rt.state
}

func eligibleAtOf(rt *accountRT) time.Time { return rt.eligibleAt }

func (p *Pool) accessTokenOf(rt *accountRT) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rt.access == nil {
		return ""
	}
	return rt.access.AccessToken
}

func (p *Pool) setState(rt *accountRT, s AccountState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rt.state = s
}

func (p *Pool) emit(ev PoolEvent) {
	if p.cfg.Events != nil {
		p.cfg.Events(ev)
	}
}

func (p *Pool) activeLabelLocked() string {
	if p.active < 0 {
		return ""
	}
	return labelOf(p.accounts[p.active])
}

func labelOf(rt *accountRT) string {
	if rt == nil {
		return ""
	}
	if rt.acct.Label != "" {
		return rt.acct.Label
	}
	return rt.acct.Redacted()
}

func describeReset(reset time.Time) string {
	if reset.IsZero() {
		return "quota exhausted (reset unknown)"
	}
	return "until " + reset.UTC().Format(time.RFC3339)
}

func indexOf(list []*accountRT, want *accountRT) int {
	for i, rt := range list {
		if rt == want {
			return i
		}
	}
	return -1
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseQuotaInt parses an X-Quota-* numeric header; unknown shapes map to def.
func parseQuotaInt(s string, def int64) int64 {
	s = strings.TrimSpace(strings.Trim(s, `"`))
	if s == "" {
		return def
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int64(f)
	}
	return def
}

// parseResetTime understands RFC3339 and unix-seconds reset stamps; anything
// else yields zero (exhausted-without-calendar stays parked for manual care).
func parseResetTime(s string) time.Time {
	s = strings.TrimSpace(strings.Trim(s, `"`))
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil && secs > 1_000_000_000 {
		return time.Unix(secs, 0)
	}
	return time.Time{}
}
