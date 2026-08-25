// Endpoint discovery (design §4; addendum v1.2 §34 bounded verification):
// ranks versioned-catalog candidates by MEASURED data-plane quality and
// maintains the last-good cache + per-endpoint cooldowns.
//
// Field rules implemented here (research Part 3, all with file:line):
//   - "handshake ≠ quality": a candidate is verified only after a validated
//     CONNECT-IP session carries a durability burst of probes
//     (warpscout masque.go:449-452 lesson);
//   - MASQUE flaps: every candidate gets up to MinAttempts connect+validate
//     rounds before it is declared dead;
//   - torn-down detection: the burst is BurstCount probes spaced
//     BurstInterval; a tail-run of >= TailRunLimit unanswered probes after
//     answered ones means the edge accepted control but dropped traffic
//     mid-stream — the ONLY way to see DPI teardown;
//   - ranking metric: loss -> in-tunnel RTT (time to the second echo).
//     Host-ICMP is deliberately NOT used (z2k #13: ICMP through the tunnel
//     is dropped 100%); throughput is outside ranking;
//   - last-good cache: at start/reconnect a fast re-verify (5s budget) runs
//     first; pass => the whole scan is skipped;
//   - cooldown: an endpoint failing twice in a row is excluded for 300s
//     (in-memory, engine lifetime);
//   - strategies turbo/balanced/thorough with tier-adjusted concurrency
//     (Low=4 / Medium=10 / High=16) and per-probe timeout 2s (design v2
//     number replacing Aether's 6/10s — deviation recorded in report);
//   - cf-warp-colo telemetry captured per candidate from ConnectResult.
//
// The §34 no-arbitrary-scan gate lives in CatalogCandidates: everything it
// returns is inside the versioned map. Tests inject their own loopback
// candidates via CandidatesOverride (documented test-only field).
package transportwarp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ScanStrategy selects the Aether-style scan shape.
type ScanStrategy string

const (
	// StrategyTurbo verifies as few candidates as possible and stops at the
	// first verified winner (early exit).
	StrategyTurbo ScanStrategy = "turbo"
	// StrategyBalanced verifies a small bounded set (production default).
	StrategyBalanced ScanStrategy = "balanced"
	// StrategyThorough walks the whole candidate list within its budget.
	StrategyThorough ScanStrategy = "thorough"
)

// ResourceTier adjusts concurrency (sysprofile numbers).
type ResourceTier string

const (
	TierLow    ResourceTier = "low"
	TierMedium ResourceTier = "medium"
	TierHigh   ResourceTier = "high"
)

// Verification constants (research consolidated numbers).
const (
	MinAttempts          = 3  // flap tolerance per candidate
	BurstCount           = 10 // durability-burst probes
	TailRunLimit         = 3  // >=3 unanswered tail => torn-down
	FastReverifyBudget   = 5 * time.Second
	Cooldown             = 300 * time.Second // after CooldownStrikes consecutive fails
	CooldownStrikes      = 2
	PerProbeTimeoutLimit = 2 * time.Second // design v2 global per-probe ceiling
	DefaultLossBudget    = 0.2             // <=20% loss still ranks healthy
)

// DefaultBurstInterval is the durability-burst pacing (warpscout 200ms).
const DefaultBurstInterval = 200 * time.Millisecond

// strategyShape mirrors the Aether prober table (targets/budget/early-exit).
type strategyShape struct {
	maxTargets int
	budget     time.Duration
	earlyExit  bool
}

func shapeFor(s ScanStrategy) (strategyShape, error) {
	switch s {
	case StrategyTurbo:
		return strategyShape{maxTargets: 2, budget: 45 * time.Second, earlyExit: true}, nil
	case "", StrategyBalanced:
		return strategyShape{maxTargets: 12, budget: 120 * time.Second, earlyExit: false}, nil
	case StrategyThorough:
		return strategyShape{maxTargets: 4096, budget: 300 * time.Second, earlyExit: false}, nil
	default:
		return strategyShape{}, fmt.Errorf("transportwarp: unknown scan strategy %q", s)
	}
}

func tierConcurrency(t ResourceTier) int {
	switch t {
	case TierLow:
		return 4
	case TierHigh:
		return 16
	default:
		return 10
	}
}

// VerifyClass is the measured outcome class of one candidate.
type VerifyClass string

const (
	VerifiedHealthy  VerifyClass = "healthy"   // burst passed within loss budget
	VerifiedLossy    VerifyClass = "lossy"     // passed but above loss budget
	VerifiedTornDown VerifyClass = "torn-down" // mid-stream silent teardown
	VerifiedDead     VerifyClass = "dead"      // never validated
)

// EndpointScore is one candidate's measured result.
type EndpointScore struct {
	Endpoint netip.AddrPort
	Class    VerifyClass
	Attempts int           // connect+validate rounds consumed
	Loss     float64       // unanswered / sent during the burst
	RTT      time.Duration // time to the SECOND echo (in-tunnel proxy)
	Colo     string        // cf-warp-colo of the winning connection
	TailRun  int           // final consecutive unanswered probes
	Sent     int
	Answered int
	// Transport names the carrier the score was measured with
	// ("h2"/"h3"; "" on pre-H3 producers).
	Transport string
}

// DiscoveryResult summarizes one Discover() run.
type DiscoveryResult struct {
	Source string // "last-good" | "scan"
	Winner EndpointScore
	Ranked []EndpointScore // verified only, best first
}

var ErrNoCandidates = errors.New("transportwarp: discovery produced no verified endpoint")

// H3VerifyConfig enables the QUIC branch of the scan (E-H3 continuation,
// EH3). When non-nil, QUIC-kind candidates are verified with the H3 carrier
// after a fast UDP-reachability probe whose outcome distinguishes an edge
// that SPOKE from a fast network refusal from egress-block silence.
type H3VerifyConfig struct {
	// ProbeBudget bounds the reachability pre-probe per candidate.
	ProbeBudget time.Duration // DefaultReachabilityProbeBudget when zero

	// QuicCandidatesOverride replaces the catalog-built QUIC list. TESTS
	// ONLY (same discipline as CandidatesOverride): production MUST leave
	// it nil so every QUIC candidate comes from the versioned map.
	QuicCandidatesOverride []netip.AddrPort
}

// DiscovererConfig configures Discoverer. Zero fields fall back to defaults.
type DiscovererConfig struct {
	// Template must carry identity key material (ClientKey/Pin) and static
	// session parameters. Its ValidateWindow also bounds each burst-echo
	// wait (capped by PerProbeTimeoutLimit).
	Template SessionConfig
	Strategy ScanStrategy
	Tier     ResourceTier
	// LastGoodPath persists the winner cache; empty disables persistence.
	LastGoodPath string

	BurstInterval time.Duration // DefaultBurstInterval

	// CandidatesOverride replaces the catalog-built candidate list. TESTS
	// ONLY: production MUST leave nil so every candidate comes from the
	// versioned map (addendum §34 gate).
	CandidatesOverride []netip.AddrPort

	// H3 enables the QUIC branch; nil keeps pure-H2 discovery.
	H3 *H3VerifyConfig

	Now func() time.Time
	// Sleep paces the durability burst; tests make it instant/fast.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (c *DiscovererConfig) fillDefaults() {
	if c.Strategy == "" {
		c.Strategy = StrategyBalanced
	}
	if c.Tier == "" {
		c.Tier = TierMedium
	}
	if c.BurstInterval <= 0 {
		c.BurstInterval = DefaultBurstInterval
	}
}

func (c *DiscovererConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *DiscovererConfig) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Discoverer ranks candidates and maintains last-good/cooldown state.
type Discoverer struct {
	cfg DiscovererConfig

	mu       sync.Mutex
	strikes  map[netip.AddrPort]int
	excluded map[netip.AddrPort]time.Time // valid until
}

func NewDiscoverer(cfg DiscovererConfig) (*Discoverer, error) {
	if _, err := shapeFor(cfg.Strategy); err != nil {
		return nil, err
	}
	cfg.fillDefaults()
	return &Discoverer{
		cfg:      cfg,
		strikes:  map[netip.AddrPort]int{},
		excluded: map[netip.AddrPort]time.Time{},
	}, nil
}

// Discover returns the best verified endpoint. Flow: fast last-good
// re-verify -> full scan over strategy-selected candidates -> rank.
func (d *Discoverer) Discover(ctx context.Context) (DiscoveryResult, error) {
	if ctx.Err() != nil {
		return DiscoveryResult{}, ctx.Err()
	}

	// --- fast last-good re-verify (5s budget) ---
	if ep, ok := d.loadLastGood(); ok {
		fastCtx, cancel := context.WithTimeout(ctx, FastReverifyBudget)
		score := d.verifyCandidate(fastCtx, scanCandidate{ep: ep}, verifyParams{fastMode: true})
		cancel()
		if score.Class == VerifiedHealthy || score.Class == VerifiedLossy {
			d.clearStrikes(ep)
			d.saveLastGood(ep, score.Colo)
			return DiscoveryResult{
				Source: "last-good",
				Winner: score,
				Ranked: []EndpointScore{score},
			}, nil
		}
		d.strike(ep)
	}

	// --- candidate selection ---
	shape, _ := shapeFor(d.cfg.Strategy) // validated at construction
	cands := d.selectCandidates(shape.maxTargets)
	if len(cands) == 0 {
		return DiscoveryResult{}, ErrNoCandidates
	}

	scanCtx, cancelScan := context.WithTimeout(ctx, shape.budget)
	scores := d.scan(scanCtx, cands, shape.earlyExit)
	cancelScan()

	ranked := make([]EndpointScore, 0, len(scores))
	for _, s := range scores {
		if s.Class == VerifiedHealthy || s.Class == VerifiedLossy {
			ranked = append(ranked, s)
		}
	}
	if len(ranked) == 0 {
		return DiscoveryResult{}, ErrNoCandidates
	}
	sort.SliceStable(ranked, func(i, j int) bool { return better(ranked[i], ranked[j]) })

	winner := ranked[0]
	d.clearStrikes(winner.Endpoint)
	d.saveLastGood(winner.Endpoint, winner.Colo)
	return DiscoveryResult{Source: "scan", Winner: winner, Ranked: ranked}, nil
}

// better implements the ranking metric: class, then loss, then RTT.
func better(a, b EndpointScore) bool {
	rank := func(c VerifyClass) int {
		if c == VerifiedHealthy {
			return 0
		}
		return 1
	}
	if ra, rb := rank(a.Class), rank(b.Class); ra != rb {
		return ra < rb
	}
	if a.Loss != b.Loss {
		return a.Loss < b.Loss
	}
	return a.RTT < b.RTT
}

// scanCandidate is one unit of scan work: an endpoint plus its catalog kind.
type scanCandidate struct {
	ep   netip.AddrPort
	quic bool
}

// selectCandidates builds the strategy list: QUIC candidates first (H3 is
// the preferred carrier; ties in ranking keep this insertion order via the
// stable sort), then H2 — catalog order or test overrides, minus
// cooldown-excluded, capped at maxTargets.
func (d *Discoverer) selectCandidates(maxTargets int) []scanCandidate {
	var h2 []netip.AddrPort
	var quic []netip.AddrPort
	if len(d.cfg.CandidatesOverride) > 0 {
		h2 = append([]netip.AddrPort(nil), d.cfg.CandidatesOverride...)
	} else {
		h2 = CatalogCandidates(KindMasqueH2, d.cfg.Strategy)
	}
	if d.cfg.H3 != nil {
		if len(d.cfg.H3.QuicCandidatesOverride) > 0 {
			quic = append([]netip.AddrPort(nil), d.cfg.H3.QuicCandidatesOverride...)
		} else {
			quic = QuicCatalogCandidates(d.cfg.Strategy)
		}
	}
	now := d.cfg.now()
	out := make([]scanCandidate, 0, len(h2)+len(quic))
	d.mu.Lock()
	defer d.mu.Unlock()
	appendOK := func(ep netip.AddrPort, quicKind bool) bool {
		if len(out) >= maxTargets {
			return false
		}
		if until, bad := d.excluded[ep]; bad && until.After(now) {
			return true // skip but keep filling remaining slots
		}
		out = append(out, scanCandidate{ep: ep, quic: quicKind})
		return true
	}
	for _, ep := range quic {
		if !appendOK(ep, true) {
			return out
		}
	}
	for _, ep := range h2 {
		if !appendOK(ep, false) {
			break
		}
	}
	return out
}

// scan verifies candidates with a tier-sized worker pool; earlyExit stops
// everything at the first verified result and runs SEQUENTIALLY so no dial
// budget is wasted on candidates that would be abandoned mid-flight.
// All goroutines are joined before return (no leaks).
func (d *Discoverer) scan(ctx context.Context, cands []scanCandidate, earlyExit bool) []EndpointScore {
	conc := tierConcurrency(d.cfg.Tier)
	if earlyExit {
		conc = 1
	}
	if conc > len(cands) {
		conc = len(cands)
	}
	jobs := make(chan scanCandidate)
	results := make(chan EndpointScore, len(cands))
	workerCtx, cancelWorkers := context.WithCancel(ctx)

	var wg sync.WaitGroup
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-workerCtx.Done():
					return
				case cand, ok := <-jobs:
					if !ok {
						return
					}
					select {
					case results <- d.verifyCandidate(workerCtx, cand, verifyParams{}):
					case <-workerCtx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, cand := range cands {
			select {
			case jobs <- cand:
			case <-workerCtx.Done():
				return
			}
		}
	}()

	var (
		scores   []EndpointScore
		verified int
	)
	collectDone := make(chan struct{})
	go func() {
		defer close(collectDone)
		for i := 0; i < len(cands); i++ {
			select {
			case s := <-results:
				d.applyOutcome(s)
				scores = append(scores, s)
				if s.Class == VerifiedHealthy || s.Class == VerifiedLossy {
					verified++
					if earlyExit {
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	<-collectDone
	cancelWorkers()
	wg.Wait()
	return scores
}

// applyOutcome updates strike/cooldown bookkeeping.
func (d *Discoverer) applyOutcome(s EndpointScore) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch s.Class {
	case VerifiedHealthy, VerifiedLossy:
		delete(d.strikes, s.Endpoint)
		delete(d.excluded, s.Endpoint)
	default:
		d.strikes[s.Endpoint]++
		if d.strikes[s.Endpoint] >= CooldownStrikes {
			d.excluded[s.Endpoint] = d.cfg.now().Add(Cooldown)
		}
	}
}

func (d *Discoverer) clearStrikes(ep netip.AddrPort) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.strikes, ep)
	delete(d.excluded, ep)
}

func (d *Discoverer) strike(ep netip.AddrPort) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.strikes[ep]++
	if d.strikes[ep] >= CooldownStrikes {
		d.excluded[ep] = d.cfg.now().Add(Cooldown)
	}
}

// verifyParams tunes one verification round.
type verifyParams struct {
	fastMode bool // last-good re-verify: single attempt, shorter burst
}

// verifyCandidate runs connect/validate flap-tolerant rounds plus the
// durability burst, returning the measured score. QUIC-kind candidates go
// through the H3 carrier (probe → dial → validate → burst); the rest keep
// the H2 path unchanged.
func (d *Discoverer) verifyCandidate(ctx context.Context, cand scanCandidate, p verifyParams) EndpointScore {
	if cand.quic {
		return d.verifyQuicCandidate(ctx, cand.ep, p)
	}
	return d.verifyH2Candidate(ctx, cand.ep, p)
}

// probeUDPClass runs the fast reachability pre-probe for one QUIC candidate.
func (d *Discoverer) probeUDPClass(ctx context.Context, ep netip.AddrPort) ReachabilityClass {
	budget := DefaultReachabilityProbeBudget
	if d.cfg.H3 != nil && d.cfg.H3.ProbeBudget > 0 {
		budget = d.cfg.H3.ProbeBudget
	}
	scfg := d.sessionFor(ep)
	class, err := ProbeUDPReachability(ctx, scfg, budget)
	if err != nil && class == "" {
		// Config-level failure (key/cert build): treat as dead-candidate
		// silence — verification cannot proceed on this candidate.
		return ReachBlackhole
	}
	return class
}

// verifyQuicCandidate mirrors the H2 flap-tolerant shape over the H3
// carrier. The reachability probe is PART of verification: blackhole/refused
// verdicts mark the candidate dead without burning full session budgets.
func (d *Discoverer) verifyQuicCandidate(ctx context.Context, ep netip.AddrPort, p verifyParams) EndpointScore {
	score := EndpointScore{Endpoint: ep, Transport: TransportH3}

	switch d.probeUDPClass(ctx, ep) {
	case ReachBlackhole:
		// udp-egress-blocked verdict at probe speed; distinct from a
		// handshake failure by construction.
		score.Class = VerifiedDead
		return score
	case ReachRefused:
		score.Class = VerifiedDead
		return score
	case ReachReachable:
		// fall through to full H3 verification
	default:
		score.Class = VerifiedDead
		return score
	}

	scfg := d.sessionFor(ep)
	attemptsAllowed := MinAttempts
	if p.fastMode {
		attemptsAllowed = 1
	}
	echoWait := PerProbeTimeoutLimit
	if w := scfg.ValidateWindow; w > 0 && w < echoWait {
		echoWait = w
	}

	var sess packetTransport
	var cres ConnectResult
	for score.Attempts < attemptsAllowed {
		score.Attempts++ // every round counts, including the successful one
		s, c, err := DialH3Session(ctx, h3ConfigFromSession(scfg))
		if err != nil {
			continue
		}
		if verr := s.ValidateDataPlane(ctx); verr != nil {
			s.Close()
			continue
		}
		sess, cres = s, c.connectResult()
		break
	}
	if sess == nil {
		score.Class = VerifiedDead
		return score
	}
	defer sess.Close()
	score.Colo = cres.Colo

	d.runBurst(ctx, sess, &score, echoWait, p)
	return score
}

// verifyH2Candidate is the pre-EH3 verification path, byte-for-byte.
func (d *Discoverer) verifyH2Candidate(ctx context.Context, ep netip.AddrPort, p verifyParams) EndpointScore {
	scfg := d.sessionFor(ep)
	attemptsAllowed := MinAttempts
	if p.fastMode {
		attemptsAllowed = 1
	}
	echoWait := PerProbeTimeoutLimit
	if w := scfg.ValidateWindow; w > 0 && w < echoWait {
		echoWait = w
	}

	score := EndpointScore{Endpoint: ep, Transport: TransportH2}
	var sess *Session
	var cres ConnectResult
	for score.Attempts < attemptsAllowed {
		score.Attempts++ // every round counts, including the successful one
		s, c, err := DialSession(ctx, scfg)
		if err != nil {
			continue
		}
		if verr := s.ValidateDataPlane(ctx); verr != nil {
			s.Close()
			continue
		}
		sess, cres = s, c
		break
	}
	if sess == nil {
		score.Class = VerifiedDead
		return score
	}
	defer sess.Close()
	score.Colo = cres.Colo

	d.runBurst(ctx, sess, &score, echoWait, p)
	return score
}

// runBurst executes the durability burst against an established session and
// fills class/loss/RTT fields (shared by both carriers).
func (d *Discoverer) runBurst(ctx context.Context, sess packetTransport, score *EndpointScore, echoWait time.Duration, p verifyParams) {
	burstCount := BurstCount
	if p.fastMode {
		burstCount = 5 // research minimum meaningful burst
	}
	probe, _ := NewDNSProbe(d.cfg.Template.LocalV4, [4]byte{8, 8, 8, 8}, "cloudflare.com")
	reader := newBurstReader(ctx, sess)
	defer reader.close()

	started := d.cfg.now()
	answeredInRow := 0
	for sent := 0; sent < burstCount; sent++ {
		if sent > 0 {
			if err := d.cfg.sleep(ctx, d.cfg.BurstInterval); err != nil {
				break // ctx cancelled mid-burst
			}
		}
		if probe == nil || sess.WritePacket(probe.Packet) != nil {
			score.TailRun++
			continue
		}
		score.Sent++
		if reader.await(echoWait) {
			score.Answered++
			answeredInRow++
			if answeredInRow == 2 {
				score.RTT = d.cfg.now().Sub(started)
			}
			score.TailRun = 0
		} else {
			score.TailRun++
			answeredInRow = 0
		}
	}

	switch {
	case score.TailRun >= TailRunLimit && score.Answered > 0:
		score.Class = VerifiedTornDown
	case score.Sent > 0 && score.Answered == 0:
		score.Class = VerifiedTornDown // validated then fully silent: worst kind
	default:
		loss := 1 - float64(score.Answered)/float64(maxInt(score.Sent, 1))
		score.Loss = loss
		if score.Sent > 0 && loss <= DefaultLossBudget {
			score.Class = VerifiedHealthy
		} else {
			score.Class = VerifiedLossy
		}
	}
}

// sessionFor builds a verification SessionConfig for one endpoint.
func (d *Discoverer) sessionFor(ep netip.AddrPort) SessionConfig {
	out := d.cfg.Template
	out.Endpoint = ep
	if out.ProbeInterval <= 0 {
		out.ProbeInterval = 700 * time.Millisecond
	}
	if out.MTU == 0 {
		out.MTU = DefaultMTU
	}
	return out
}

// burstReader drains session packets on ONE background goroutine for the
// duration of a burst (no goroutine-per-read leaks). close() cancels the
// reader's own context so a ReadPacket parked on a quiet session unwinds
// deterministically instead of depending on session teardown ordering.
type burstReader struct {
	ch     chan packetMsg
	cancel context.CancelFunc
	done   chan struct{}
}

func newBurstReader(parent context.Context, sess packetTransport) *burstReader {
	rctx, cancel := context.WithCancel(parent)
	b := &burstReader{ch: make(chan packetMsg, 8), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(b.done)
		defer close(b.ch)
		for {
			pkt, err := sess.ReadPacket(rctx)
			if err != nil {
				return
			}
			select {
			case b.ch <- packetMsg{data: pkt}:
			case <-rctx.Done():
				return
			}
		}
	}()
	return b
}

// await waits up to d for any inbound packet.
func (b *burstReader) await(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case m, open := <-b.ch:
		return open && m.err == nil
	case <-t.C:
		return false
	}
}

func (b *burstReader) close() {
	b.cancel()
	<-b.done
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---- last-good cache ----

type lastGoodEntry struct {
	Endpoint   string    `json:"endpoint"`
	Colo       string    `json:"colo,omitempty"`
	PinDigest  string    `json:"pin_digest,omitempty"`
	VerifiedAt time.Time `json:"verified_at"`
}

func (d *Discoverer) loadLastGood() (netip.AddrPort, bool) {
	if d.cfg.LastGoodPath == "" {
		return netip.AddrPort{}, false
	}
	blob, err := os.ReadFile(d.cfg.LastGoodPath)
	if err != nil {
		return netip.AddrPort{}, false
	}
	var e lastGoodEntry
	if json.Unmarshal(blob, &e) != nil || e.Endpoint == "" {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(e.Endpoint)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return ap, true
}

func (d *Discoverer) saveLastGood(ep netip.AddrPort, colo string) {
	if d.cfg.LastGoodPath == "" {
		return
	}
	entry := lastGoodEntry{
		Endpoint:   ep.String(),
		Colo:       colo,
		PinDigest:  PinDigest(d.cfg.Template.Pin),
		VerifiedAt: d.cfg.now(),
	}
	blob, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return
	}
	dir := filepath.Dir(d.cfg.LastGoodPath)
	tmp, err := os.CreateTemp(dir, ".lastgood-*.tmp")
	if err != nil {
		return
	}
	name := tmp.Name()
	if err := writeSecretFile(tmp, blob); err != nil {
		_ = os.Remove(name)
		return
	}
	if err := os.Rename(name, d.cfg.LastGoodPath); err != nil {
		_ = os.Remove(name)
	}
}
