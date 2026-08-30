// Seek ladder (design §5) — active probing of peer AWG parameters: for each
// candidate endpoint the seeker walks a profile ladder, driving a real
// single-shot session per attempt and classifying the outcome structurally:
//
//	handshake ok + data flows            -> WINNER  (persist last-good)
//	handshake ok + tx grows / rx == 0    -> awg-version-mismatch -> next profile
//	handshake never completes            -> candidate failure      -> next endpoint
//
// Candidate failures accumulate strikes; after StrikesToCooldown failures an
// endpoint cools down for Cooldown (default 300 s) and is skipped by later
// runs. The winner is persisted to LastGoodStore and offered first.
package transportwg

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Seek budgets (design §5: handshake 5 s, per-attempt ~7 s, overall
// 80–120 s; cooldown 300 s after two strikes).
// PATCH-12 (WG MINOR 7): the KPI §1.3 budget is PER ENDPOINT —
// DefaultSeekPerEndpointDeadline bounds ONE candidate's ladder; the TOTAL
// derives from it (n candidates) unless explicitly overridden.
const (
	DefaultSeekHandshakeTimeout    = 5 * time.Second
	DefaultSeekGateWindow          = 900 * time.Millisecond
	DefaultSeekGateGap             = 100 * time.Millisecond
	DefaultSeekGateRoundTrips      = 2
	DefaultSeekAttemptBudget       = 7 * time.Second
	DefaultSeekTotalDeadline       = 90 * time.Second
	DefaultSeekPerEndpointDeadline = 90 * time.Second
	DefaultSeekCooldown            = 300 * time.Second
	DefaultSeekStrikes             = 2
)

// AttemptRecord traces one ladder step for reports/tests.
type AttemptRecord struct {
	Endpoint netip.AddrPort
	Profile  string
	Outcome  FailureClass // "winner" on success
	Err      string
}

// Winner is the successful outcome of a Seek run.
type Winner struct {
	Endpoint netip.AddrPort
	Profile  string
}

// SeekResult reports the winner (if any) and the full attempt log.
type SeekResult struct {
	Winner   *Winner
	Attempts []AttemptRecord
}

// StrikeState is the shareable strike/cooldown book (pointer-semantics so
// several seeker instances can share one book across runs).
type StrikeState struct {
	mu        sync.Mutex
	strikes   map[string]int
	coolUntil map[string]time.Time
}

func NewStrikeState() *StrikeState {
	return &StrikeState{
		strikes:   map[string]int{},
		coolUntil: map[string]time.Time{},
	}
}

// Cooling reports whether the endpoint is currently cooling down.
func (ss *StrikeState) Cooling(c netip.AddrPort, now time.Time) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	until, ok := ss.coolUntil[c.String()]
	return ok && now.Before(until)
}

// Strike registers one failure; returns true when cooldown got armed.
func (ss *StrikeState) Strike(c netip.AddrPort, now time.Time, threshold int, cooldown time.Duration) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	key := c.String()
	ss.strikes[key]++
	if ss.strikes[key] >= threshold {
		ss.coolUntil[key] = now.Add(cooldown)
		delete(ss.strikes, key)
		return true
	}
	return false
}

// Clear resets strikes for an endpoint (after a win).
func (ss *StrikeState) Clear(c netip.AddrPort) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.strikes, c.String())
}

// SeekerConfig assembles the seek run.
type SeekerConfig struct {
	Base       SessionConfig // Ident/Tunnel/SockOpts reused; endpoint/profile/health overridden
	Candidates []netip.AddrPort
	Target     ProfileTarget
	LadderIDs  []string // optional explicit order override (validated IDs)

	Store               LastGoodStore // optional
	HandshakeTimeout    time.Duration // default 5 s
	GateWindow          time.Duration // default 900 ms
	GateRoundTrips      int           // default 2
	GateGap             time.Duration // default 100 ms
	AttemptBudget       time.Duration // default 7 s
	TotalDeadline       time.Duration // 0 = derived: PerEndpointDeadline x candidates
	PerEndpointDeadline time.Duration // PATCH-12: per-candidate ladder budget; default 90 s (KPI §1.3)
	Cooldown            time.Duration // default 300 s
	StrikesToCooldown   int           // default 2

	Now func() time.Time

	OnEvent func(AttemptRecord)

	// TunnelFactory overrides the per-attempt TUN construction (test hook;
	// production leaves nil and attempts run their configured real mode).
	TunnelFactory func(TunnelConfig) (*Tunnel, error)

	// Strikes carries cross-run strike/cooldown state. nil -> the seeker
	// allocates its own (single-lifetime usage).
	Strikes *StrikeState

	// AllowOutOfCatalog is a TESTS-ONLY escape (loopback fake edges bind
	// outside the endpoint catalog). Production MUST leave it false: with
	// the gate on, every candidate AND the last-good entry are validated
	// against InWGCatalog/KnownWGPort and silently skipped otherwise
	// (design §11.5 via MASQUE §34: no arbitrary endpoints, ever).
	AllowOutOfCatalog bool
}

func (c *SeekerConfig) fillDefaults() {
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = DefaultSeekHandshakeTimeout
	}
	if c.GateWindow == 0 {
		c.GateWindow = DefaultSeekGateWindow
	}
	if c.GateGap == 0 {
		c.GateGap = DefaultSeekGateGap
	}
	if c.GateRoundTrips == 0 {
		c.GateRoundTrips = DefaultSeekGateRoundTrips
	}
	if c.AttemptBudget == 0 {
		c.AttemptBudget = DefaultSeekAttemptBudget
	}
	if c.PerEndpointDeadline == 0 {
		c.PerEndpointDeadline = DefaultSeekPerEndpointDeadline
	}
	// PATCH-12: TotalDeadline stays 0 when unset — Seek derives it from the
	// per-endpoint budget and the candidate count (KPI §1.3 is per ENDPOINT).
	if c.Cooldown == 0 {
		c.Cooldown = DefaultSeekCooldown
	}
	if c.StrikesToCooldown == 0 {
		c.StrikesToCooldown = DefaultSeekStrikes
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Seeker executes bounded seek runs.
type Seeker struct {
	cfg     SeekerConfig
	strikes *StrikeState

	mu sync.Mutex
}

func NewSeeker(cfg SeekerConfig) (*Seeker, error) {
	cfg.fillDefaults()
	if cfg.Base.Ident == nil {
		return nil, newFailure(ClassParamRejected, "nil-identity", nil)
	}
	if len(cfg.Candidates) == 0 {
		return nil, newFailure(ClassParamRejected, "no-candidates", nil)
	}
	for _, id := range cfg.LadderIDs {
		if _, err := LookupProfile(id); err != nil {
			return nil, newFailure(ClassParamRejected, "ladder", err)
		}
	}
	// PATCH-12: the production budget band (KPI §1.3: 80–120 s per endpoint).
	// The tests-only escape (AllowOutOfCatalog, same posture as the endpoint
	// gate) also unlocks shrunk budgets for CI.
	if !cfg.AllowOutOfCatalog && cfg.PerEndpointDeadline != 0 &&
		(cfg.PerEndpointDeadline < 80*time.Second || cfg.PerEndpointDeadline > 120*time.Second) {
		return nil, newFailure(ClassParamRejected, "per-endpoint-deadline",
			fmt.Errorf("%s outside the 80-120s production band", cfg.PerEndpointDeadline))
	}
	strikes := cfg.Strikes
	if strikes == nil {
		strikes = NewStrikeState()
	}
	return &Seeker{cfg: cfg, strikes: strikes}, nil
}

func (s *Seeker) emit(rec AttemptRecord) {
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(rec)
	}
}

func containsAddr(list []netip.AddrPort, v netip.AddrPort) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// orderedCandidates returns candidates with the last-good endpoint first,
// skipping cooled-down endpoints. With the catalog gate on (default), the
// last-good binding is honored only while the stored pair still lives
// inside a catalog pool — a stale or out-of-pool entry is dropped and the
// ladder re-seeks (warp-socks rule: last_good-first only while it is still
// in the pool).
func (s *Seeker) orderedCandidates(now time.Time) []netip.AddrPort {
	var preferred netip.AddrPort
	hasPreferred := false
	if s.cfg.Store != nil {
		if lg, ok := s.cfg.Store.Get(); ok && s.admissible(lg.Endpoint) {
			preferred = lg.Endpoint
			hasPreferred = true
		}
	}
	out := make([]netip.AddrPort, 0, len(s.cfg.Candidates))
	push := func(c netip.AddrPort) {
		if containsAddr(out, c) || s.strikes.Cooling(c, now) {
			return
		}
		if !s.admissible(c) {
			return
		}
		out = append(out, c)
	}
	if hasPreferred {
		push(preferred)
	}
	for _, c := range s.cfg.Candidates {
		push(c)
	}
	return out
}

// admissible applies the §34-analog gate unless the tests-only escape is set.
func (s *Seeker) admissible(c netip.AddrPort) bool {
	return s.cfg.AllowOutOfCatalog || endpointInCatalog(c)
}

// orderedLadder returns profiles for one candidate: last-good profile first
// when it matches the stored endpoint, then the target ladder.
func (s *Seeker) orderedLadder(cand netip.AddrPort) ([]ProfileTemplate, error) {
	var preferredID string
	if s.cfg.Store != nil {
		if lg, ok := s.cfg.Store.Get(); ok && lg.Endpoint == cand {
			preferredID = lg.ProfileID
		}
	}
	ladder := s.cfg.LadderIDs
	if len(ladder) == 0 {
		templates, err := LadderFor(s.cfg.Target, preferredID)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(templates))
		for _, t := range templates {
			out = append(out, t.ID)
		}
		ladder = out
	}
	out := make([]ProfileTemplate, 0, len(ladder))
	seen := map[string]bool{}
	for _, id := range ladder {
		tpl, err := LookupProfile(id)
		if err != nil {
			return nil, err
		}
		if tpl.Target != s.cfg.Target || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, tpl)
	}
	return out, nil
}

// Seek runs the ladder until a winner or budget exhaustion.
// PATCH-12: every candidate's ladder runs under ITS OWN deadline
// (PerEndpointDeadline); a candidate's budget expiry moves to the NEXT
// candidate instead of killing the run. The total deadline is a ceiling
// over everything: explicit when set, otherwise derived as
// PerEndpointDeadline x candidate count (KPI §1.3 semantics).
func (s *Seeker) Seek(ctx context.Context) (SeekResult, error) {
	s.cfg.fillDefaults()

	total := s.cfg.TotalDeadline
	if total <= 0 {
		total = s.cfg.PerEndpointDeadline * time.Duration(max(1, len(s.cfg.Candidates)))
	}
	totalCtx, cancelTotal := context.WithTimeout(ctx, total)
	defer cancelTotal()

	res := SeekResult{}
	now := s.cfg.Now()
	cands := s.orderedCandidates(now)
	if len(cands) == 0 {
		return res, newFailure(ClassStallRX, "all-candidates-cooling", nil)
	}

	for _, cand := range cands {
		if totalCtx.Err() != nil {
			break
		}
		candCtx, cancelCand := context.WithTimeout(totalCtx, s.cfg.PerEndpointDeadline)
		ladder, err := s.orderedLadder(cand)
		if err != nil {
			cancelCand()
			return res, newFailure(ClassParamRejected, "ladder", err)
		}
		nextCandidate := false
		for _, tpl := range ladder {
			if totalCtx.Err() != nil {
				cancelCand()
				return res, totalCtx.Err()
			}
			// PATCH-12: this candidate's own budget expired — move
			// to the NEXT candidate instead of dying with the run.
			if candCtx.Err() != nil {
				rec := AttemptRecord{Endpoint: cand, Profile: tpl.ID, Outcome: ClassStallRX, Err: "endpoint-budget"}
				res.Attempts = append(res.Attempts, rec)
				s.emit(rec)
				nextCandidate = true
				break
			}
			prof, berr := tpl.Build()
			if berr != nil {
				rec := AttemptRecord{Endpoint: cand, Profile: tpl.ID, Outcome: ClassJunkProfileFailed, Err: berr.Error()}
				res.Attempts = append(res.Attempts, rec)
				s.emit(rec)
				continue
			}

			outcome := s.attempt(candCtx, cand, prof)
			switch {
			case outcome.won:
				rec := AttemptRecord{Endpoint: cand, Profile: tpl.ID, Outcome: "winner"}
				res.Attempts = append(res.Attempts, rec)
				s.emit(rec)
				res.Winner = &Winner{Endpoint: cand, Profile: tpl.ID}
				if s.cfg.Store != nil {
					_ = s.cfg.Store.Put(Attempt{Endpoint: cand, ProfileID: tpl.ID, At: s.cfg.Now()})
				}
				s.strikes.Clear(cand)
				cancelCand()
				return res, nil
			case outcome.fail != nil && outcome.fail.Class == ClassVersionMismatch:
				rec := AttemptRecord{Endpoint: cand, Profile: tpl.ID, Outcome: ClassVersionMismatch, Err: outcome.fail.Reason}
				res.Attempts = append(res.Attempts, rec)
				s.emit(rec)
				// parameter disagreement: try the NEXT PROFILE here.
			default:
				cls := ClassStallRX
				reason := "attempt-failed"
				if outcome.fail != nil {
					cls = outcome.fail.Class
					reason = outcome.fail.Reason
				}
				rec := AttemptRecord{Endpoint: cand, Profile: tpl.ID, Outcome: cls, Err: reason}
				res.Attempts = append(res.Attempts, rec)
				s.emit(rec)
				nextCandidate = true
			}
			if nextCandidate {
				break
			}
		}
		cancelCand()
		if nextCandidate {
			s.strikes.Strike(cand, s.cfg.Now(), s.cfg.StrikesToCooldown, s.cfg.Cooldown)
		}
	}
	if res.Winner == nil {
		return res, newFailure(ClassStallRX, "seek-exhausted", nil)
	}
	return res, nil
}

type attemptOutcome struct {
	won  bool
	fail *Failure
}

// attempt drives ONE single-shot session against cand with the given
// profile and classifies its conclusion.
func (s *Seeker) attempt(ctx context.Context, cand netip.AddrPort, prof Profile) attemptOutcome {
	sc := s.cfg.Base
	sc.Profile = prof
	sc.Endpoint = cand.String()
	sc.MaxGenerations = 1
	sc.Health.HandshakeTimeout = s.cfg.HandshakeTimeout
	sc.Health.RestartBackoff = 50 * time.Millisecond
	sc.Health.KeepaliveSec = 1
	sc.Health.Gate.RoundTrips = s.cfg.GateRoundTrips
	sc.Health.Gate.Window = s.cfg.GateWindow
	sc.Health.Gate.Gap = s.cfg.GateGap

	estCh := make(chan struct{}, 1)
	lostCh := make(chan Failure, 1)
	sc.Callbacks.OnEstablished = func() {
		select {
		case estCh <- struct{}{}:
		default:
		}
	}
	sc.Callbacks.OnLost = func(f Failure) {
		select {
		case lostCh <- f:
		default:
		}
	}

	actx, acancel := context.WithTimeout(ctx, s.cfg.AttemptBudget)
	defer acancel()
	sc.Health.Watchdog.Tick = 200 * time.Millisecond

	sess, err := NewSession(sc)
	if err != nil {
		return attemptOutcome{fail: &Failure{Class: ClassParamRejected, Reason: "session-build", Err: err}}
	}
	if s.cfg.TunnelFactory != nil {
		sess.newTunnelFn = s.cfg.TunnelFactory
	}
	if err := sess.Start(); err != nil {
		return attemptOutcome{fail: &Failure{Class: ClassParamRejected, Reason: "session-start", Err: err}}
	}
	defer sess.Stop()

	for {
		select {
		case <-actx.Done():
			rec := AttemptRecord{Endpoint: cand, Outcome: ClassStallRX, Err: "attempt-budget"}
			s.emit(rec)
			return attemptOutcome{fail: newFailure(ClassStallRX, "attempt-budget", actx.Err())}
		case <-estCh:
			return attemptOutcome{won: true}
		case f := <-lostCh:
			return attemptOutcome{fail: &f}
		}
	}
}

var _ = fmt.Sprintf // keep fmt if diagnostics evolve
