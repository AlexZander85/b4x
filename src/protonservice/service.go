// Package protonservice assembles the E-PROTON reserve transport
// (src/transport/proton control plane + the shared transport/wg data-plane
// engine) from the main config — the deliberately-thin "last mile" mirroring
// operaservice/fxvpservice/warpservice.
//
// Integration contract (E-PROTON design §6/§7, patch-plan §6):
//
//   - role: R-reserve with geo-exit, UDP full-scope; priority strictly BELOW
//     AWG-WARP/MASQUE/H3 in every selection tree; never a silent substitute;
//
//   - supervisor discipline: one deterministic tick (30 s + timestamp
//     scheduler against clock jumps); rebuilds capped <=6/hour with a 300 s
//     cooldown; running/listening reported separately; event ring for the
//     GUI feed;
//
//   - registration discipline: at most ONE Proton registration per boot
//     (atomic registeredThisBoot flag; owner's manual Reissue is the
//     explicit exception); refresh instead of re-registration; refresh
//     400/401/422 => re-registration STILL gated by the boot flag;
//
//   - anti-jail: handshake ok + data gate failed twice => proton-jailed =>
//     rotate the profile (next candidate, node strikes 2 => cooldown 300 s);
//
//   - anti-loop: Proton control hosts and DoH resolvers never traverse the
//     proton tunnel itself (BypassSuffixes exported for DIRECT rules);
//
//   - secrets: the seed/tokens live in the identity slot only; everything
//     leaving the runtime is Redacted.
package protonservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/transport/proton"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// DialFunc is the base dial shape shared with the warp/opera/fxvpn engines.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Restart discipline shared across transports.
const (
	MaxRestartsPerHour = 6
	RestartCooldown    = 300 * time.Second
	superviseTick      = 30 * time.Second
	eventsRingCap      = 32

	// certRenewMargin opens the persistent-certificate renew window 30 days
	// before expiry (design §1.6; Nova CERT_RENEW_MARGIN_MS).
	certRenewMargin = 30 * 24 * time.Hour
	// sessionKeepAlive pokes GET /core/v4/users every 12 h (Next
	// SessionRefreshWorker cadence) so the credentialless session survives
	// between certificate re-issues.
	sessionKeepAlive = 12 * time.Hour
	// sessionRefreshMaxAge refreshes the session prophylactically every 7
	// days even without a 401.
	sessionRefreshMaxAge = 7 * 24 * time.Hour
	// sessionRefreshDebounce: refresh answers are debounced 60 s; force
	// (after 401) bypasses the debounce.
	sessionRefreshDebounce = 60 * time.Second
	// ntpWaitBudget bounds the pre-registration clock sanity wait.
	ntpWaitBudget = 120 * time.Second
	// certNotBeforeSlack rejects certificates whose notBefore lies in the
	// future beyond this slack (router without RTC — vanilla lesson).
	certNotBeforeSlack = 5 * time.Minute
	// jailedStrikes is the trust-gate failure count that declares the node
	// jailed (design §6: handshake ok + data gate failed x2).
	jailedStrikes = 2
	// i1AdaptationStep is the minimum step between I1 re-issues of a
	// degraded profile (design §3.4: >= 30 min).
	i1AdaptationStep = 30 * time.Minute
)

// States of the service-level lifecycle canvas (design §6).
const (
	StateIdle        = "idle"
	StateNTPWait     = "ntp-wait"
	StateRegistering = "registering"
	StateNodeSelect  = "node-select"
	StateSeeking     = "seeking"
	StateTrustGate   = "trust-gate"
	StateEstablished = "established"
	StateRenewing    = "renewing"
	StateBackoff     = "backoff"
)

// BypassSuffixes must NEVER traverse the proton tunnel (anti-loop, design
// §7): the control hosts, the alternative-routing zone and the DoH
// resolvers.
var BypassSuffixes = []string{
	"vpn-api.proton.me",
	"api.protonvpn.ch",
	"api.protonmail.ch",
	"protonpro.xyz",
	"dns.google",
	"cloudflare-dns.com",
	"dns11.quad9.net",
}

// IsBypassDomain reports whether host is (a subdomain of) a bypass domain.
func IsBypassDomain(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, s := range BypassSuffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// restartGuard is the fxvpservice canon (service.go:73-113): a rolling
// one-hour window plus a cooldown stamp when the cap is exhausted.
type restartGuard struct {
	mu       sync.Mutex
	now      func() time.Time
	stamps   []time.Time
	cooldown time.Time
	max      int
}

func (g *restartGuard) allowed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if now.Before(g.cooldown) {
		return false
	}
	cutoff := now.Add(-time.Hour)
	kept := g.stamps[:0]
	for _, s := range g.stamps {
		if s.After(cutoff) {
			kept = append(kept, s)
		}
	}
	g.stamps = kept
	return len(g.stamps) < g.max
}

func (g *restartGuard) stamp() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.stamps = append(g.stamps, now)
	if len(g.stamps) >= g.max {
		g.cooldown = now.Add(RestartCooldown)
	}
}

// Options assembles the runtime; zero values are valid.
type Options struct {
	// Carrier is the active base-transport dial (bootstrap-through-carrier).
	Carrier proton.DialFunc
	// Now injects the clock (tests); defaults to time.Now.
	Now func() time.Time
	// ExtraEvents receives every service event (metrics/GUI wiring).
	ExtraEvents func(proton.Event)
	// ExitProbeTLS overrides the exit-probe TLS base (*tls.Config — the
	// fxvpn.ProbeExitTLS canon): production leaves nil and gets the default
	// config pinned to the trace host; tests pin the fake edge certificate.
	ExitProbeTLS any
}

// Event is one service-level taxonomy trace (name + class + detail).
type protonEvent = proton.Event

type Runtime struct {
	cfg      config.ProtonConfig
	opts     Options
	client   *proton.Client
	idStore  *proton.IdentityStore
	list     *proton.ServerlistCache
	strikes  *twg.StrikeState
	lastGood *twg.FileLastGood
	now      func() time.Time

	guard restartGuard

	// registeredThisBoot is the red-line gate: at most ONE registration per
	// boot (Reissue sets it aside explicitly by owner action).
	registeredThisBoot atomic.Bool

	// refresh bookkeeping (mutex + debounce).
	refreshMu        sync.Mutex
	lastRefreshAt    time.Time
	sessionRefreshed time.Time

	mu       sync.Mutex
	running  bool
	stopped  bool
	cancel   context.CancelFunc
	state    string
	sess     *twg.Session
	profiles []proton.ProtonProfile
	profIdx  int
	location config.ProtonLocation

	identity     *proton.Identity
	exit         ExitView
	exitProbing  bool // one exit probe at a time across generations
	lastFailure  string
	events       []proton.Event
	stallStrikes int
	i1LastSwap   time.Time

	lastKeepAlive      time.Time
	sessionRefreshedAt time.Time
	stateSince         time.Time

	dialOK   uint64
	dialFail uint64
}

// ExitView is the last verified exit observation (fxvpn parity).
type ExitView struct {
	IP        string    `json:"ip,omitempty"`
	Country   string    `json:"country,omitempty"`
	OK        bool      `json:"ok"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Build validates system.proton and constructs the runtime WITHOUT starting
// anything or touching the network. Enabled=false still builds (warp/fxvpn
// parity: the daemon gates on config, the wiring skips Start).
func Build(cfg *config.Config, opts Options) (*Runtime, error) {
	pc := cfg.System.Proton
	if opts.Now == nil {
		opts.Now = time.Now
	}
	identityPath := pc.EffectiveIdentityPath()

	client := &proton.Client{
		Carrier:    opts.Carrier,
		UserAgent:  pc.UserAgent,
		AppVersion: pc.AppVersion,
		APIVersion: pc.APIVersion,
	}
	if pc.BootstrapThroughCarrier && opts.Carrier != nil {
		// The carrier dial is spliced under the direct dial inside the
		// pinned client (fxvpn failoverDial canon).
		client.Carrier = opts.Carrier
	}
	pins, err := proton.NewPinStore(proton.SiblingPath(identityPath, "pins.json"))
	if err != nil {
		return nil, fmt.Errorf("protonservice: pin store: %w", err)
	}
	client.Pins = pins
	client.DoH = &proton.DoHResolver{HTTP: client.NewPinnedClient(nil)}

	r := &Runtime{
		cfg:      pc,
		opts:     opts,
		client:   client,
		idStore:  &proton.IdentityStore{Path: identityPath},
		strikes:  twg.NewStrikeState(),
		now:      opts.Now,
		location: pc.Location,
		state:    StateIdle,
	}
	r.guard = restartGuard{now: opts.Now, max: pc.EffectiveMaxRestarts()}
	list, err := proton.NewServerlistCache(client, proton.SiblingPath(identityPath, "serverlist.json"))
	if err != nil {
		return nil, fmt.Errorf("protonservice: serverlist cache: %w", err)
	}
	list.OnEvent = func(event, source string) {
		r.appendEvent(proton.Event{Name: event, Detail: source})
	}
	r.list = list

	if pc.Obfuscation.PreferredProfile != "" {
		// The config head pin is validated in config; unknown ids fall back
		// to the ladder default at seek time.
		_ = pc.Obfuscation.PreferredProfile
	}
	return r, nil
}

// Start launches the supervisor loop (daemon mode only; the config gate
// belongs to the caller, warp/fxvpn parity).
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return errors.New("protonservice: runtime already stopped")
	}
	if r.running {
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.running = true
	go r.loop(runCtx)
	return nil
}

// Stop tears the loop and the live session down (no-op before Start).
func (r *Runtime) Stop() {
	r.mu.Lock()
	if !r.running || r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	cancel := r.cancel
	sess := r.sess
	r.sess = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if sess != nil {
		sess.Stop()
	}
}

// RestartNow forces an immediate supervision cycle (GUI button). It
// bypasses the tick cadence but NOT the restart caps.
func (r *Runtime) RestartNow(ctx context.Context) { r.tick(ctx) }

// SetLocation applies a validated desired location IN MEMORY and retires
// the current session (rebuild on the next ensure).
func (r *Runtime) SetLocation(loc config.ProtonLocation) {
	r.mu.Lock()
	r.location = loc
	old := r.sess
	r.sess = nil
	r.profiles = nil
	r.profIdx = 0
	r.mu.Unlock()
	if old != nil {
		old.Stop()
	}
	r.appendEvent(proton.Event{Name: proton.EventLocationSwitched,
		Detail: strings.ToLower(loc.Mode) + "/" + loc.Country + loc.Host})
}

// ValidateLocation checks a requested location against the cached catalog.
func (r *Runtime) ValidateLocation(ctx context.Context, loc config.ProtonLocation) error {
	nodes, _, err := r.list.Get(ctx, r.controlSession())
	if err != nil {
		return err
	}
	return proton.ValidateLocation(proton.Location{Mode: loc.Mode, Country: loc.Country, Host: loc.Host}, nodes)
}

// Locations serves the dropdown: countries -> cities -> nodes from the
// cached list with load and free marks.
func (r *Runtime) Locations(ctx context.Context) (proton.LocationsView, error) {
	return r.list.Locations(ctx, r.controlSession())
}

// Reissue performs the owner-actioned re-registration: a FRESH key (new
// seed) + new credentialless session, bypassing the once-per-boot gate
// (explicit action). The current session is retired.
func (r *Runtime) Reissue(ctx context.Context) error {
	r.setState(StateRegistering)
	id, err := r.register(ctx, true)
	if err != nil {
		r.noteFailure(proton.Classify(err))
		r.setState(StateBackoff)
		return err
	}
	r.mu.Lock()
	r.identity = id
	r.mu.Unlock()
	r.appendEvent(proton.Event{Name: proton.EventRegistered, Detail: "reissue"})
	r.setState(StateIdle)
	return nil
}

// ---- supervisor loop ---------------------------------------------------------------

func (r *Runtime) loop(ctx context.Context) {
	ticker := time.NewTicker(superviseTick)
	defer ticker.Stop()
	r.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

// tick is one deterministic supervision cycle: identity -> nodes -> session
// -> renew -> health (patch-plan §6.1 steps 1-5). A disabled config is a
// truthful no-op (zero goroutines, zero wire calls).
func (r *Runtime) tick(ctx context.Context) {
	if !r.cfg.Enabled {
		return
	}
	if err := r.ensureIdentity(ctx); err != nil {
		r.noteFailure(proton.Classify(err))
		return // identity gates everything else
	}
	if err := r.ensureSession(ctx); err != nil {
		r.noteFailure(classifyServiceErr(err))
	}
	r.renew(ctx)
	r.exportState()
}

// ensureIdentity loads the stored identity or registers exactly once per
// boot behind the NTP-wait gate.
func (r *Runtime) ensureIdentity(ctx context.Context) error {
	if r.identity != nil {
		return nil
	}
	id, err := r.idStore.Load()
	switch {
	case err == nil:
		r.mu.Lock()
		r.identity = id
		r.mu.Unlock()
		r.registeredThisBoot.Store(true) // the stored key IS registered
		return nil
	case errors.Is(err, proton.ErrIdentityAbsent):
		// fall through to registration
	case errors.Is(err, proton.ErrIdentityCorrupt), errors.Is(err, proton.ErrIdentityInvalid):
		r.appendEvent(proton.Event{Name: "proton_identity_corrupt", Detail: err.Error()})
		// fall through: fresh registration on the clean slot
	default:
		return err
	}

	if !r.registeredThisBoot.CompareAndSwap(false, true) {
		// Already spent this boot's budget; wait for the next boot or an
		// explicit owner Reissue (no loops, red line §10.4).
		return errors.New("protonservice: registration budget spent for this boot")
	}
	r.setState(StateNTPWait)
	if err := r.waitClockFresh(ctx); err != nil {
		// Budget expired: the attempt proceeds anyway; the certificate-side
		// notBefore guard rejects impossible dates (patch-plan §6.3).
		r.appendEvent(proton.Event{Name: "proton_ntpwait_timeout", Detail: err.Error()})
	}
	r.setState(StateRegistering)
	id, err = r.register(ctx, false)
	if err != nil {
		r.noteFailure(proton.Classify(err))
		r.setState(StateBackoff)
		return err
	}
	r.mu.Lock()
	r.identity = id
	r.mu.Unlock()
	r.appendEvent(proton.Event{Name: proton.EventRegistered, Detail: id.SessionSummary()})
	return nil
}

// register performs the full 4-step enrollment and persists the identity.
// fresh=true (owner Reissue) draws a NEW seed; the boot-path registration
// starts from a fresh slot as well (the slot was absent/corrupt).
func (r *Runtime) register(ctx context.Context, fresh bool) (*proton.Identity, error) {
	seed, err := proton.RandomSeed(crandReader{})
	if err != nil {
		return nil, err
	}
	profile, err := proton.GenerateDeviceProfile(crandReader{})
	if err != nil {
		return nil, err
	}
	kp := proton.DeriveKeyPair(seed)
	now := r.now()

	// Credentialless performs BOTH step 1 (its own carrier) and step 2;
	// a separate CreateSession here would double the registration noise.
	sess, err := r.client.Credentialless(ctx, profile.ChallengeBody())
	if err != nil {
		return nil, err
	}
	cert, err := r.client.RegisterClientKey(ctx, sess, kp.Ed25519PubPEM)
	if err != nil {
		return nil, err
	}
	// notBefore guard (router without RTC): a certificate dated in the
	// future beyond the slack means the clock is wrong — refuse and stay.
	if cert.Certificate != "" {
		if nb, ok := parseCertNotBefore(cert.Certificate); ok && nb.After(now.Add(certNotBeforeSlack)) {
			return nil, fmt.Errorf("protonservice: certificate notBefore %s lies in the future (clock not ready)", nb)
		}
	}

	id := &proton.Identity{
		SeedB64:          encodeSeed(seed),
		DeviceProfile:    profile,
		UID:              sess.UID,
		AccessToken:      sess.AccessToken,
		RefreshToken:     sess.RefreshToken,
		RegisteredPubPEM: kp.Ed25519PubPEM,
		CertExpiresAt:    cert.ExpirationTime,
		CertRefreshAt:    certRefreshAt(cert, now),
		VPNIv4:           cert.IPv4,
		VPNIv6:           cert.IPv6,
		VPNDNS:           cert.DNS,
		CreatedAt:        now.Unix(),
		UpdatedAt:        now.Unix(),
	}
	if err := r.idStore.Save(id); err != nil {
		return nil, err
	}
	_ = fresh
	r.exportRegistration()
	return id, nil
}

// waitClockFresh probes the control channel's TLS certificate dates as the
// coarse clock sanity check (patch-plan §6.3: "TLS NotAfter-vs-now already
// gives a rough check"). Bounded by ntpWaitBudget; an unreachable network
// still expires the budget honestly.
func (r *Runtime) waitClockFresh(ctx context.Context) error {
	deadline := time.Now().Add(ntpWaitBudget)
	for {
		if r.clockLooksFresh(ctx) {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("clock-fresh budget expired")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// clockLooksFresh TLS-dials the primary control host and checks that the
// system time sits inside the served certificate's validity window.
func (r *Runtime) clockLooksFresh(ctx context.Context) bool {
	return proton.TimeFresh(ctx, r.client)
}

// ensureServerlist refreshes the node list and is implicit in ensureSession
// (the Locations/cache API handles TTL). Kept as a named step for the tick
// contract.
func (r *Runtime) ensureSession(ctx context.Context) error {
	if !r.cfg.Enabled {
		return nil
	}
	r.mu.Lock()
	sess := r.sess
	alive := sess != nil && sessionAlive(sess)
	r.mu.Unlock()
	if alive {
		return nil
	}
	if !r.guard.allowed() {
		return fmt.Errorf("restart capped (<=%d/hour or cooldown %s)", r.cfg.EffectiveMaxRestarts(), RestartCooldown)
	}

	r.setState(StateNodeSelect)
	nodes, _, err := r.list.Get(ctx, r.controlSession())
	if err != nil {
		return fmt.Errorf("server list: %w", err)
	}
	loc := proton.Location{Mode: r.location.Mode, Country: r.location.Country, Host: r.location.Host}
	queue := proton.NewQueue(nodes, r.cfg.Port)
	cands := queue.Candidates(loc)
	if len(cands) == 0 {
		return fmt.Errorf("%w: mode %q country=%q host=%q", proton.ErrNoNodes, loc.Mode, loc.Country, loc.Host)
	}

	// Seek ladder (design §3.5): last-good first, then the config/optional
	// preferred profile, then the proton ladder.
	ladder := protonLadderIDs(r.cfg.Obfuscation)
	ident, err := r.currentIdentity()
	if err != nil {
		return err
	}
	wgid, err := ident.WGIdentity(cands[0].Node)
	if err != nil {
		return fmt.Errorf("wg identity projection: %w", err)
	}
	base := r.sessionBase()
	base.Ident = wgid
	seek, serr := twg.NewSeeker(twg.SeekerConfig{
		Base:       base,
		Candidates: candidateAddrs(cands),
		Target:     twg.TargetProton,
		LadderIDs:  ladder,
		Store:      r.lastGoodFor(),
		Strikes:    r.strikes,
		Source:     protonNodeSource(cands),
		OnEvent: func(rec twg.AttemptRecord) {
			r.appendEvent(proton.Event{Name: "proton_profile_seek",
				Class: string(rec.Outcome), Detail: rec.Endpoint.String() + " " + rec.Profile})
			r.exportSeek(rec.Profile, string(rec.Outcome))
		},
		// CI budgets ride the tests-only escape; production keeps the
		// 80-120 s band (PATCH-12).
		AllowOutOfCatalog: false,
	})
	if serr != nil {
		r.setState(StateBackoff)
		return fmt.Errorf("seeker: %w", serr)
	}
	r.setState(StateSeeking)
	res, err := seek.Seek(ctx)
	if err != nil {
		r.setState(StateBackoff)
		return fmt.Errorf("seek: %w", err)
	}

	// The winner: rebuild the profile with the runtime I1 and start the
	// long-lived session (MaxGenerations: 1 — the supervisor owns rebuilds).
	winner := res.Winner
	var winProf proton.ProtonProfile
	for _, cand := range cands {
		if cand.AddrPort() == winner.Endpoint {
			sniPool := proton.DefaultSNIPool()
			if len(r.cfg.Obfuscation.SNIPool) > 0 {
				sniPool = r.cfg.Obfuscation.SNIPool
			}
			issued := proton.IssueProfiles([]proton.Candidate{cand},
				[]string{winner.Profile}, sniPool, crandReader{}, &wgLastGoodView{store: r.lastGoodFor()})
			winProf = issued[0]
			break
		}
	}
	s, err := r.buildSession(ident, winProf)
	if err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return err
	}
	r.mu.Lock()
	r.sess = s
	r.profiles = append(r.profiles, winProf)
	r.profIdx = len(r.profiles) - 1
	r.setStateLocked(StateTrustGate)
	r.mu.Unlock()
	return nil
}

// sessionBase is the shared SessionConfig skeleton (identity/endpoint/
// profile overridden per session).
func (r *Runtime) sessionBase() twg.SessionConfig {
	return twg.SessionConfig{
		Tunnel: twg.TunnelConfig{
			Mode: twg.ModeNetstack,
			// The Proton topology constants (design §1.8): the client sits at
			// 10.2.0.2; the gate's DNS probe targets 8.8.8.8 through it.
			Addresses: []netip.Addr{netip.MustParseAddr(proton.ProtonTunnelV4)},
			DNS:       []netip.Addr{netip.MustParseAddr("8.8.8.8")},
			MTU:       r.cfg.EffectiveMTU(),
		},
		MaxGenerations: 1,
	}
}

// buildSession assembles one twg.Session for the issued profile with the
// Proton health posture (keepalive 25 s, gate 2 RTT, watchdog defaults).
func (r *Runtime) buildSession(ident *proton.Identity, prof proton.ProtonProfile) (*twg.Session, error) {
	wgid, err := ident.WGIdentity(prof.Node)
	if err != nil {
		return nil, err
	}
	v4, _, dns := ident.TunnelAddresses()
	tpl, err := twg.LookupProfile(prof.ProfileID)
	if err != nil {
		return nil, err
	}
	profile, err := tpl.Build()
	if err != nil {
		return nil, err
	}
	// Runtime I1 fill (design §3.4): the catalog template stores an empty
	// chain; the issued blob replaces InitPacket[0] before IpcSet.
	if prof.I1 != "" {
		profile.InitPacket[0] = prof.I1
		if err := profile.Validate(); err != nil {
			return nil, err
		}
	}
	v4Addr := netip.MustParseAddr(v4)
	addrs := []netip.Addr{v4Addr}
	var dnsAddrs []netip.Addr
	for _, d := range dns {
		if a, err := netip.ParseAddr(d); err == nil {
			dnsAddrs = append(dnsAddrs, a)
		}
	}

	node := prof.Node
	r.mu.Lock()
	defer r.mu.Unlock()
	// s is captured by the OnEstablished closure; callbacks only fire
	// after Start(), so the variable is always assigned by then.
	var s *twg.Session
	s, err = twg.NewSession(twg.SessionConfig{
		Ident:    wgid,
		Profile:  profile,
		Endpoint: prof.AddrPort().String(),
		SockOpts: twg.SocketOptions{},
		Tunnel: twg.TunnelConfig{
			Mode:      twg.ModeNetstack,
			Addresses: addrs,
			DNS:       dnsAddrs,
			MTU:       r.cfg.EffectiveMTU(),
		},
		Health: twg.HealthConfig{
			KeepaliveSec: 25,
			Gate:         twg.TrustGate{RoundTrips: 2},
		},
		Callbacks: twg.SessionCallbacks{
			OnEstablished: func() {
				r.mu.Lock()
				r.stallStrikes = 0
				r.setStateLocked(StateEstablished)
				r.mu.Unlock()
				r.appendEvent(proton.Event{Name: proton.EventEstablished,
					Detail: node.Name + "@" + prof.AddrPort().String() + " " + prof.ProfileID})
				r.recordHandshake(true)
				// Exit verification (design §5, review P1): the probe rides
				// the fresh data plane OFF the callback goroutine (callbacks
				// stay non-blocking); a geo mismatch strikes the node and
				// retires the session — the next tick re-seeks.
				go r.verifyExit(node, prof, s)
			},
			OnLost: func(f twg.Failure) {
				r.onSessionLost(node, prof, f)
			},
		},
		MaxGenerations: 1,
	})
	return s, err
}

// onSessionLost classifies the death of one generation: trust-gate failures
// accumulate jail strikes; two in a row on an established node declare it
// jailed and rotate (patch-plan §6.1 step 5).
func (r *Runtime) onSessionLost(node proton.Node, prof proton.ProtonProfile, f twg.Failure) {
	r.mu.Lock()
	r.stallStrikes++
	strikes := r.stallStrikes
	r.state = StateBackoff
	r.mu.Unlock()

	r.recordHandshake(false)
	class := string(f.Class)
	switch {
	case f.Class == twg.ClassVersionMismatch:
		class = "awg-version-mismatch" // reuse the wg taxonomy as-is
		r.appendEvent(proton.Event{Name: proton.EventRotated,
			Class: class, Detail: node.Name + " obfuscation mismatch"})
	case f.Class == twg.ClassStallRX && strikes >= jailedStrikes:
		r.appendEvent(proton.Event{Name: proton.EventRotated,
			Class: proton.ClassJailed, Detail: node.Name + " jailed after " +
				jailedStrikesJitter(strikes) + " gate failures"})
		// Node strike: two jailed verdicts cool the node down (design §5).
		r.strikes.Strike(prof.AddrPort(), r.now(), 2, RestartCooldown)
		// I1 adaptation (design §3.4): the degraded profile re-issues with
		// the next pool name, >= 30 min step; a working profile is untouched
		// (the next ensure re-issues through IssueProfiles).
		if r.cfg.Obfuscation.I1Adaptation {
			r.mu.Lock()
			r.i1LastSwap = r.now()
			r.mu.Unlock()
		}
	default:
		r.appendEvent(proton.Event{Name: "proton_session_lost", Class: class, Detail: node.Name})
	}
	// Retire the dead session; the next tick rebuilds (caps apply).
	r.mu.Lock()
	if r.sess != nil {
		r.sess = nil
	}
	r.mu.Unlock()
}

// recordHandshake bumps the handshake counters (runtime + registry).
func (r *Runtime) recordHandshake(ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ok {
		r.dialOK++
	} else {
		r.dialFail++
	}
	r.exportHandshake(ok)
}

func jailedStrikesJitter(n int) string {
	if n < 1 {
		return "1"
	}
	return fmt.Sprintf("%d", n)
}

// renew drives the timestamp-scheduled maintenance (patch-plan §6.1 step 4):
// certificate re-issue, session keep-alive/refresh, node TTL.
func (r *Runtime) renew(ctx context.Context) {
	id := r.currentIdentityPtr()
	if id == nil || !r.cfg.Enabled {
		return
	}
	now := r.now()

	// Certificate: renew window opens cert_refresh_at (server RefreshTime or
	// ExpirationTime - 30 days). The WG tunnel never tears (the key derives
	// from the immutable seed, design §1.5).
	if id.CertRefreshAt > 0 && now.Unix() > id.CertRefreshAt {
		r.setState(StateRenewing)
		if err := r.renewCertificate(ctx, id); err != nil {
			if errors.Is(err, proton.ErrAPIRefused) {
				r.noteFailure(proton.ClassCertExpired)
			}
			r.noteFailure(proton.Classify(err))
		}
	}

	// Keep-alive: GET /core/v4/users every 12 h.
	if r.lastKeepAlive.Add(sessionKeepAlive).Before(now) {
		if err := r.client.UserKeepAlive(ctx, r.controlSessionPtr()); err == nil {
			r.lastKeepAlive = now
		} else if errors.Is(err, proton.ErrAPIRefused) {
			// 401: forced refresh path (debounce bypassed).
			_ = r.refreshSession(ctx, true)
		}
	}

	// Prophylactic refresh every 7 days.
	if r.sessionRefreshedAt.Add(sessionRefreshMaxAge).Before(now) {
		_ = r.refreshSession(ctx, false)
	}
}

// renewCertificate re-issues the certificate for the SAME key in place.
func (r *Runtime) renewCertificate(ctx context.Context, id *proton.Identity) error {
	sess := r.controlSessionPtr()
	cert, err := r.client.RegisterClientKey(ctx, sess, id.RegisteredPubPEM)
	if err != nil {
		// 401 on re-issue: refresh the session first, retry once.
		if errors.Is(err, proton.ErrAPIRefused) {
			if rerr := r.refreshSession(ctx, true); rerr == nil {
				if cert2, err2 := r.client.RegisterClientKey(ctx, r.controlSessionPtr(), id.RegisteredPubPEM); err2 == nil {
					cert = cert2
					err = nil
				}
			}
		}
		if err != nil {
			return err
		}
	}
	r.mu.Lock()
	id.CertExpiresAt = cert.ExpirationTime
	id.CertRefreshAt = certRefreshAt(cert, r.now())
	id.UpdatedAt = r.now().Unix()
	id.UID = sess.UID
	id.AccessToken = sess.AccessToken
	id.RefreshToken = sess.RefreshToken
	r.mu.Unlock()
	if err := r.idStore.Save(id); err != nil {
		return err
	}
	r.appendEvent(proton.Event{Name: proton.EventCertRenewed,
		Detail: fmt.Sprintf("expires %d", cert.ExpirationTime)})
	return nil
}

// refreshSession implements the Next SessionManager discipline (design
// §1.4): mutex + 60 s debounce (force bypasses), refresh token replaced
// only when the server rotated it, 400/401/422 => re-registration (still
// gated once per boot).
func (r *Runtime) refreshSession(ctx context.Context, force bool) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if !force && r.now().Sub(r.lastRefreshAt) < sessionRefreshDebounce {
		return nil
	}
	id := r.currentIdentityPtr()
	if id == nil {
		return proton.ErrIdentityAbsent
	}
	sess, err := r.client.Refresh(ctx, id.UID, id.RefreshToken)
	r.lastRefreshAt = r.now()
	if err != nil {
		var ae *proton.APIError
		if errors.As(err, &ae) && (ae.Status == 400 || ae.Status == 401 || ae.Status == 422) {
			r.noteFailure(proton.ClassSessionRefreshBad)
			r.appendEvent(proton.Event{Name: "proton_session_refresh_failed", Class: proton.ClassSessionRefreshBad})
			// Re-registration: gated by the boot budget (no loops).
			return r.ensureIdentity(ctx)
		}
		return err
	}
	r.mu.Lock()
	id.UID = sess.UID
	id.AccessToken = sess.AccessToken
	if sess.RefreshToken != "" {
		id.RefreshToken = sess.RefreshToken
	}
	id.UpdatedAt = r.now().Unix()
	r.sessionRefreshedAt = r.now()
	r.mu.Unlock()
	_ = r.idStore.Save(id)
	r.appendEvent(proton.Event{Name: proton.EventSessionRefreshed})
	return nil
}

// ---- helpers -----------------------------------------------------------------------

func (r *Runtime) currentIdentity() (*proton.Identity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.identity == nil {
		return nil, proton.ErrIdentityAbsent
	}
	return r.identity, nil
}

func (r *Runtime) currentIdentityPtr() *proton.Identity {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.identity
}

// controlSession returns the live session for control-plane requests
// (nil-safe: the API stand and offline mode tolerate a nil session).
func (r *Runtime) controlSession() *proton.Session {
	if id := r.currentIdentityPtr(); id != nil && id.UID != "" {
		return &proton.Session{UID: id.UID, AccessToken: id.AccessToken, RefreshToken: id.RefreshToken}
	}
	return nil
}

func (r *Runtime) controlSessionPtr() *proton.Session {
	s := r.controlSession()
	if s == nil {
		return &proton.Session{}
	}
	return s
}

func (r *Runtime) lastGoodFor() twg.LastGoodStore {
	if r.lastGood == nil {
		path := proton.SiblingPath(r.cfg.EffectiveIdentityPath(), "lastgood.json")
		r.lastGood = &twg.FileLastGood{Path: path}
	}
	return r.lastGood
}

// protonNodeSource adapts the current candidate list to the seeker's
// CandidateSource seam (patch-plan §5.4: InCatalog for Proton = membership
// of the current node list).
func protonNodeSource(cands []proton.Candidate) twg.CandidateSource {
	set := make(map[netip.AddrPort]bool, len(cands))
	for _, c := range cands {
		set[c.AddrPort()] = true
	}
	return twg.CatalogSourceFunc(func(c netip.AddrPort) bool { return set[c] })
}

// protonLadderIDs resolves the seek ladder from the obfuscation config.
func protonLadderIDs(o config.ProtonObfuscation) []string {
	if !o.Enabled {
		return []string{"proton-vanilla"}
	}
	if o.PreferredProfile != "" {
		return []string{o.PreferredProfile, "proton-quic", "proton-vanilla", "proton-sip", "proton-crlf"}
	}
	return []string{"proton-quic", "proton-vanilla", "proton-sip", "proton-crlf"}
}

func (r *Runtime) setState(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state = s
}

func (r *Runtime) setStateLocked(s string) { r.state = s }

func (r *Runtime) appendEvent(ev proton.Event) {
	if ev.At.IsZero() && r.now != nil {
		ev.At = r.now()
	}
	r.mu.Lock()
	r.events = append(r.events, ev)
	if len(r.events) > eventsRingCap {
		r.events = r.events[len(r.events)-eventsRingCap:]
	}
	r.mu.Unlock()
	if r.opts.ExtraEvents != nil {
		r.opts.ExtraEvents(ev)
	}
}

func (r *Runtime) noteFailure(class string) {
	if class == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastFailure = class
}

// classifyServiceErr maps service errors onto the taxonomy.
func classifyServiceErr(err error) string {
	switch {
	case errors.Is(err, proton.ErrNoNodes):
		return proton.ClassNoNodes
	case errors.Is(err, proton.ErrPinMismatch):
		return proton.ClassAPIPinMismatch
	default:
		return proton.Classify(err)
	}
}

// sessionAlive reports whether the session still runs (its own lifecycle
// goroutine alive, terminal state not reached).
func sessionAlive(s *twg.Session) bool {
	switch s.State() {
	case twg.StateClosed, twg.StateRestarting:
		return false
	}
	return true
}

// certRefreshAt resolves the renew-window stamp: the server RefreshTime
// when present, otherwise ExpirationTime - 30 days (design §1.6).
func certRefreshAt(cert *proton.CertResponse, now time.Time) int64 {
	if cert.RefreshTime > 0 {
		return cert.RefreshTime
	}
	exp := time.Unix(cert.ExpirationTime, 0)
	margin := certRenewMargin
	if exp.Sub(now) < margin {
		margin = exp.Sub(now) / 2
	}
	return exp.Add(-margin).Unix()
}
