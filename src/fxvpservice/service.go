// Package fxvpservice assembles the Firefox VPN reserve transport
// (src/transport/fxvpn: FX1 control plane + FX2 data plane + FX3 account
// pool) from the main config - the deliberately-thin "last mile" mirroring
// operaservice/warpservice.
//
// Integration contract (E-FXVPN design Part I SS5, stage FX4):
//
//   - role kind "fxvpn": a userspace Backend-B style TCP carrier; consumers
//     take Runtime.DialStream (the warp StreamDialer shape);
//
//   - TCP-only by protocol (connect dialect): SupportsUDP() reports false
//     honestly; UDP-scope traffic must never be routed here;
//
//   - anti-loop: Mozilla/Fastly control hosts and the active node hostname
//     must never traverse the fxvpn tunnel itself (zapret-gui lesson,
//     opera parity); BypassSuffixes is exported for DIRECT rules;
//
//   - bootstrap-through-carrier: when enabled, CONTROL-plane TCP legs fall
//     back to the injected base-transport carrier (SPKI pinning stays on);
//
//   - supervisor discipline: session rebuilds capped <=6/hour with 300s
//     cooldown stamps, running/listening reported separately, event ring
//     for the GUI feed.
package fxvpservice

import (
        "context"
        "errors"
        "fmt"
        "net"
        "net/netip"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        "github.com/daniellavrushin/b4/config"
        fxvpn "github.com/daniellavrushin/b4/transport/fxvpn"
)

// DialFunc is the base dial shape shared with the warp/opera engines.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// BypassSuffixes must NEVER traverse the fxvpn tunnel (anti-loop).
var BypassSuffixes = []string{
        "accounts.firefox.com",
        "vpn.mozilla.org",
        "firefox.settings.services.mozilla.com",
        "fastly-masque.net",
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

var (
        ErrFxvpnSelfLoop = errors.New("fxvpservice: refusing self-loop through fxvpn tunnel")
        ErrNotListening  = errors.New("fxvpservice: no serving session yet")
)

// Restart discipline shared across transports.
const (
        MaxRestartsPerHour = 6
        RestartCooldown    = 300 * time.Second
        superviseTick      = 30 * time.Second
        eventsRingCap      = 32

        // defaultQuotaPollInterval is the 15-min X-Quota-* poll of design
        // Ч.I §3 (review F7): cheap FetchProxyPass re-mint that refreshes the
        // rotation triggers' quota view and re-issues the pass early.
        defaultQuotaPollInterval = 15 * time.Minute
)

type restartGuard struct {
        mu       sync.Mutex
        now      func() time.Time
        stamps   []time.Time
        cooldown time.Time
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
        return len(g.stamps) < MaxRestartsPerHour
}

func (g *restartGuard) stamp() {
        g.mu.Lock()
        defer g.mu.Unlock()
        now := g.now()
        g.stamps = append(g.stamps, now)
        if len(g.stamps) >= MaxRestartsPerHour {
                g.cooldown = now.Add(RestartCooldown)
        }
}

// Options assembles the runtime; zero values are valid.
type Options struct {
        // Carrier is the active base-transport dial. When set AND
        // bootstrap_through_carrier is on, control-plane TCP legs fail over to
        // it (direct first, carrier second).
        Carrier DialFunc
        // Now injects the clock (tests); defaults to time.Now.
        Now func() time.Time
        // ExtraEvents receives every pool/supervisor event (metrics wiring).
        ExtraEvents func(fxvpn.PoolEvent)
        // QuotaPollInterval overrides the 15-min X-Quota-* poll cadence
        // (tests). <=0 keeps the default.
        QuotaPollInterval time.Duration
}

// ExitView is the last verified exit observation.
type ExitView struct {
        IP        string    `json:"ip,omitempty"`
        Country   string    `json:"country,omitempty"`
        OK        bool      `json:"ok"`
        CheckedAt time.Time `json:"checked_at,omitempty"`
        Error     string    `json:"error,omitempty"`
}

// Runtime owns one assembled fxvpn transport for a config generation.
type Runtime struct {
        cfg      config.FxVPNConfig
        pool     *fxvpn.Pool
        cp       *fxvpn.ControlPlane
        sl       *fxvpn.ServerlistCache
        preferH3 atomic.Bool

        guard restartGuard

        mu          sync.Mutex
        session     fxvpn.TunnelOpener
        sessionHost string
        carrier     string
        running     bool
        stopped     bool
        cancel      context.CancelFunc

        exit        ExitView
        lastFailure string
        events      []fxvpn.PoolEvent
        dialOK      uint64
        dialFail    uint64

        quotaPollInterval time.Duration
        lastQuotaPoll     time.Time
}

// Build validates system.fxvpn and constructs the runtime WITHOUT starting
// anything or touching the network. Enabled=false still builds (daemon gates
// on config, warpservice parity). A corrupt accounts store fails the build
// deliberately (fxvpn-account-store-corrupt).
func Build(cfg *config.Config, opts Options) (*Runtime, error) {
        fc := cfg.System.FxVPN
        if fc.AccountsPath == "" {
                fc.AccountsPath = config.DefaultFxvpnAccountsPath
        }
        if opts.Now == nil {
                opts.Now = time.Now
        }
        if opts.QuotaPollInterval <= 0 {
                opts.QuotaPollInterval = defaultQuotaPollInterval
        }

        cp, err := fxvpn.NewControlPlane(pinPathFor(fc.AccountsPath))
        if err != nil {
                return nil, fmt.Errorf("fxvpservice: control plane: %w", err)
        }
        if fc.BootstrapThroughCarrier && opts.Carrier != nil {
                cp.SetBaseDial(failoverDial(directDial(), opts.Carrier))
        }

        store := fxvpn.NewAccountStore(fc.AccountsPath)
        r := &Runtime{cfg: fc, cp: cp, quotaPollInterval: opts.QuotaPollInterval}
        r.preferH3.Store(fc.PreferH3)
        r.guard.now = opts.Now

        poolCfg := fxvpn.PoolConfig{
                RotateThresholdPct: fc.EffectiveRotateThreshold(),
                Now:                opts.Now,
        }
        poolCfg.Events = func(ev fxvpn.PoolEvent) {
                r.appendEvent(ev)
                r.exportPoolMetrics()
                if opts.ExtraEvents != nil {
                        opts.ExtraEvents(ev)
                }
        }
        pool, perr := fxvpn.NewPool(store, &fxvpn.FXA{CP: cp}, &fxvpn.Guardian{CP: cp}, poolCfg)
        if perr != nil {
                return nil, fmt.Errorf("fxvpservice: account pool: %w", perr)
        }
        r.pool = pool
        return r, nil
}

func failoverDial(direct, carrier DialFunc) DialFunc {
        return func(ctx context.Context, network, addr string) (net.Conn, error) {
                conn, err := direct(ctx, network, addr)
                if err == nil {
                        return conn, nil
                }
                cconn, cerr := carrier(ctx, network, addr)
                if cerr != nil {
                        return nil, fmt.Errorf("direct: %v; carrier: %w", err, cerr)
                }
                return cconn, nil
        }
}

func directDial() DialFunc {
        d := &net.Dialer{}
        return d.DialContext
}

func pinPathFor(accountsPath string) string {
        if i := strings.LastIndex(accountsPath, "/"); i > 0 {
                return accountsPath[:i+1] + "pins.json"
        }
        return "pins.json"
}

func siblingPath(base, name string) string {
        if i := strings.LastIndex(base, "/"); i > 0 {
                return base[:i+1] + name
        }
        return name
}

// Start launches the supervisor loop (daemon mode only). The config gate
// (system.fxvpn.enabled) belongs to the caller, like warpservice.
func (r *Runtime) Start(ctx context.Context) error {
        r.mu.Lock()
        defer r.mu.Unlock()
        if r.stopped {
                return errors.New("fxvpservice: runtime already stopped")
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

// Stop tears the loop down (no-op before Start).
func (r *Runtime) Stop() {
        r.mu.Lock()
        defer r.mu.Unlock()
        if !r.running || r.stopped {
                return
        }
        r.stopped = true
        if r.cancel != nil {
                r.cancel()
        }
}

// SupportsUDP is a protocol constant for the connect dialect.
func (r *Runtime) SupportsUDP() bool { return false }

// RestartNow forces an immediate supervision cycle (GUI button). It bypasses
// the tick cadence but NOT the restart caps.
func (r *Runtime) RestartNow(ctx context.Context) { r.tick(ctx) }

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

// tick is one deterministic supervision cycle: recycle -> renew ->
// quota-poll -> pre-emptive rotate (review F3: UNCONDITIONALLY, i.e. while
// the session is alive — that is the only window the <15% / reset-lead
// triggers exist for) -> rebuild-if-dead, then refresh the /metrics gauges.
func (r *Runtime) tick(ctx context.Context) {
        r.pool.RecycleDue()
        if _, err := r.pool.RenewActivePassIfNeeded(ctx); err != nil {
                r.noteFailure(fxvpn.Classify(err))
        }
        r.pollQuotaIfDue(ctx)
        swapped, err := r.pool.RotateIfDue(ctx)
        if err != nil && !errors.Is(err, fxvpn.ErrPoolBlocked) {
                r.noteFailure(classifyServiceErr(err))
        }
        if swapped {
                r.applySoftSwap()
        }
        if err := r.ensureSession(ctx); err != nil {
                r.noteFailure(classifyServiceErr(err))
        }
        r.exportPoolMetrics()
}

// pollQuotaIfDue runs the 15-min X-Quota-* poll (review F7a) so the
// pre-emptive rotation below reads fresh quota numbers, not hours-old ones.
func (r *Runtime) pollQuotaIfDue(ctx context.Context) {
        r.mu.Lock()
        due := time.Since(r.lastQuotaPoll) >= r.quotaPollInterval
        if due {
                r.lastQuotaPoll = time.Now()
        }
        r.mu.Unlock()
        if !due {
                return
        }
        if _, err := r.pool.PollActiveQuota(ctx); err != nil {
                r.noteFailure(fxvpn.Classify(err))
        }
}

// applySoftSwap applies a pre-emptive pool rotation to a LIVE session
// (review F3 soft swap): open streams keep their old relay (they ride the
// old account's already-opened tunnels and die naturally), NEW tunnels get
// the new account's bearer via the in-place UpdateToken seam, and the
// session object itself is rebuilt by the next natural ensureSession cycle
// when it dies. The old session is deliberately NOT closed here — a hard
// close would break exactly the streams the pre-emptive rotation exists to
// protect.
func (r *Runtime) applySoftSwap() {
        r.mu.Lock()
        s := r.session
        alive := s != nil && s.IsAlive()
        r.mu.Unlock()
        if !alive {
                return // dead session: ensureSession rebuilds with the new bearer
        }
        bearerRaw, ok := r.pool.ActiveBearer()
        if !ok {
                return
        }
        if err := s.UpdateToken(bearerRaw); err != nil {
                r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_session_bearer_rotate_failed", Detail: short(err)})
                return
        }
        r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_session_bearer_rotated",
                Detail: "pre-emptive rotation applied in place; session rebuilds on next natural cycle"})
}

// ensureSession rebuilds the data-plane session when absent/dead. Pool
// rotation runs first so an exhausted/rejected seat moves before dialing.
func (r *Runtime) ensureSession(ctx context.Context) error {
        r.mu.Lock()
        s := r.session
        alive := s != nil && s.IsAlive()
        r.mu.Unlock()
        if alive {
                return nil
        }

        if _, err := r.pool.RotateIfDue(ctx); err != nil && !errors.Is(err, fxvpn.ErrPoolBlocked) {
                return fmt.Errorf("rotate: %w", err)
        }
        bearerRaw, ok := r.pool.ActiveBearer()
        if !ok {
                return errors.New("no active account bearer")
        }
        if !r.guard.allowed() {
                return fmt.Errorf("restart capped (<=%d/hour or cooldown %s)", MaxRestartsPerHour, RestartCooldown)
        }

        host, port, lerr := r.resolveLocation(ctx)
        if lerr != nil {
                return lerr
        }

        r.guard.stamp()
        sess, carrier, serr := dialSession(ctx, r.cp, host, port, bearerRaw, r.preferH3.Load())
        if serr != nil {
                return serr
        }

        r.mu.Lock()
        old := r.session
        r.session = sess
        r.sessionHost = net.JoinHostPort(host, strconv.Itoa(port))
        r.carrier = carrier
        r.mu.Unlock()
        if old != nil {
                _ = old.Close() // swap already atomic; old streams die naturally
        }

        r.verifyExit(ctx, sess)
        return nil
}

// resolveLocation picks host/port from the cached server list per mode.
func (r *Runtime) resolveLocation(ctx context.Context) (string, int, error) {
        sl, err := r.serverlist()
        if err != nil {
                return "", 0, fmt.Errorf("server list cache: %w", err)
        }
        countries, _, gerr := sl.Get(ctx)
        if gerr != nil {
                return "", 0, fmt.Errorf("server list: %w", gerr)
        }
        loc := r.cfg.Location
        var cands []fxvpn.ConnectCandidate
        switch strings.ToLower(loc.Mode) {
        case "", "auto":
                cands = fxvpn.ConnectCandidates(countries, "", "", "")
        case "country":
                cands = fxvpn.ConnectCandidates(countries, loc.Country, loc.City, "")
        case "host":
                cands = fxvpn.ConnectCandidates(countries, "", "", loc.Host)
        default:
                return "", 0, fmt.Errorf("location.mode %q invalid", loc.Mode)
        }
        if len(cands) == 0 {
                return "", 0, fmt.Errorf("%w: mode %q country=%q city=%q host=%q",
                        fxvpn.ErrNoServers, loc.Mode, loc.Country, loc.City, loc.Host)
        }
        return cands[0].Hostname, cands[0].Port, nil
}

// dialSession establishes the carrier per ladder preference: H3 first when
// configured with exactly one confirmed-class fallback to H2; otherwise H2.
func dialSession(ctx context.Context, cp *fxvpn.ControlPlane, host string, port int, bearerRaw string, preferH3 bool) (fxvpn.TunnelOpener, string, error) {
        cfg := fxvpn.TunnelConfig{Host: host, Port: port, Token: bearerRaw}
        ladder := fxvpn.NewLadder(fxvpn.LadderConfig{PreferH3: preferH3})
        pick := ladder.Preferred()
        for attempt := 0; attempt < 2; attempt++ {
                switch pick {
                case fxvpn.CarrierH3:
                        s, err := fxvpn.DialH3(ctx, cfg)
                        if err == nil {
                                return s, fxvpn.CarrierH3, nil
                        }
                        next, switched := ladder.ObserveDialFailure(pick, err)
                        if !switched {
                                return nil, "", err
                        }
                        pick = next
                default:
                        s, err := fxvpn.DialH2(ctx, cfg)
                        if err == nil {
                                return s, fxvpn.CarrierH2, nil
                        }
                        return nil, "", err
                }
        }
        return nil, "", errors.New("carrier ladder exhausted")
}

// verifyExit probes the verified exit through the fresh session; a mismatch
// is recorded AND announced (supervisor answers via next rotation cycle).
func (r *Runtime) verifyExit(ctx context.Context, sess fxvpn.TunnelOpener) {
        info, err := fxvpn.ProbeExit(ctx, sess)
        r.mu.Lock()
        r.exit = ExitView{IP: info.IP, Country: info.Country, CheckedAt: r.now()}
        if err != nil {
                r.exit.Error = err.Error()
        } else {
                r.exit.OK = true
        }
        want := strings.ToUpper(strings.TrimSpace(r.cfg.Location.Country))
        mismatch := err == nil && want != "" && want != "AUTO" && !strings.EqualFold(info.Country, want)
        r.mu.Unlock()

        if err != nil {
                r.noteFailure(fxvpn.ClassExitMismatch)
                r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_exit_probe_failed", Detail: short(err)})
                return
        }
        if mismatch {
                r.noteFailure(fxvpn.ClassExitMismatch)
                r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_exit_mismatch",
                        Label: info.IP, Detail: "got " + info.Country + " want " + want})
        }
}

// DialStream dials ONE TCP stream to addr THROUGH the serving session.
// Self-loop targets are refused; failures feed metrics/failure class.
func (r *Runtime) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
        host := addr.Addr().String()
        if IsBypassDomain(host) {
                r.recordDial(false)
                return nil, ErrFxvpnSelfLoop
        }
        if err := r.ensureSession(ctx); err != nil {
                r.recordDial(false)
                r.noteFailure(classifyServiceErr(err))
                return nil, err
        }
        r.mu.Lock()
        sess := r.session
        nodeHost := hostOf(r.sessionHost)
        r.mu.Unlock()
        if sess == nil {
                r.recordDial(false)
                return nil, ErrNotListening
        }
        if nodeHost != "" && strings.EqualFold(host, nodeHost) {
                r.recordDial(false)
                return nil, ErrFxvpnSelfLoop
        }
        conn, err := sess.OpenTunnel(ctx, net.JoinHostPort(host, strconv.Itoa(int(addr.Port()))))
        if err != nil {
                r.recordDial(false)
                r.noteFailure(classifyServiceErr(err))
                return nil, err
        }
        r.atomicOK()
        return conn, nil
}

// Status snapshots runtime state for the GUI/API (Дополнение 3 shapes).
type Status struct {
        Enabled       bool                 `json:"enabled"`
        Running       bool                 `json:"running"`
        Listening     bool                 `json:"listening"`
        Transport     string               `json:"transport"`
        Carrier       string               `json:"carrier,omitempty"`
        SessionNode   string               `json:"session_node,omitempty"`
        Location      config.FxVPNLocation `json:"location"`
        PreferH3      bool                 `json:"prefer_h3"`
        Pool          fxvpn.PoolStatus     `json:"pool"`
        VerifiedExit  ExitView             `json:"verified_exit"`
        LastFailure   string               `json:"last_failure,omitempty"`
        DialOK        uint64               `json:"dial_ok"`
        DialFail      uint64               `json:"dial_fail"`
        RestartCapHit bool                 `json:"restart_cap_hit"`
        Events        []fxvpn.PoolEvent    `json:"events,omitempty"`
}

// Status implements the honest running/listening split:
//   - running: supervisor loop alive;
//   - listening: live session AND exit verified (or not yet probed).
func (r *Runtime) Status() Status {
        r.mu.Lock()
        defer r.mu.Unlock()
        st := Status{
                Enabled:      r.cfg.Enabled,
                Running:      r.running && !r.stopped,
                Transport:    "tcp-only",
                Carrier:      r.carrier,
                SessionNode:  r.sessionHost,
                Location:     r.cfg.Location,
                PreferH3:     r.preferH3.Load(),
                Pool:         r.pool.Status(),
                VerifiedExit: r.exit,
                LastFailure:  r.lastFailure,
                DialOK:       atomic.LoadUint64(&r.dialOK),
                DialFail:     atomic.LoadUint64(&r.dialFail),
                Events:       append([]fxvpn.PoolEvent(nil), r.events...),
        }
        listening := false
        if s := r.session; s != nil && s.IsAlive() {
                listening = st.VerifiedExit.OK || st.VerifiedExit.CheckedAt.IsZero()
        }
        st.Listening = listening
        st.RestartCapHit = !r.guard.allowed()
        return st
}

// LocationsView normalizes the cached server list for the GUI dropdown
// (Дополнение 3): quarantined excluded upstream, REC/CatchAll included.
type LocationsView struct {
        FetchedAt time.Time     `json:"fetched_at"`
        Countries []CountryView `json:"countries"`
}

type CountryView struct {
        Code   string     `json:"code"`
        Name   string     `json:"name"`
        Cities []CityView `json:"cities"`
}

type CityView struct {
        Code  string     `json:"code"`
        Name  string     `json:"name"`
        Hosts []HostView `json:"hosts"`
}

type HostView struct {
        Hostname    string `json:"hostname"`
        Port        int    `json:"port"`
        Quarantined bool   `json:"quarantined,omitempty"`
}

// Locations serves the dropdown; the raw cache stays authoritative.
func (r *Runtime) Locations(ctx context.Context) (LocationsView, error) {
        sl, err := r.serverlist()
        if err != nil {
                return LocationsView{}, err
        }
        countries, fromCache, gerr := sl.Get(ctx)
        if gerr != nil {
                return LocationsView{}, gerr
        }
        _ = fromCache
        view := LocationsView{}
        for _, c := range countries {
                cv := CountryView{Code: c.Code, Name: c.Name}
                for _, city := range c.Cities {
                        cityV := CityView{Code: city.Code, Name: city.Name}
                        for _, srv := range city.Servers {
                                cityV.Hosts = append(cityV.Hosts, HostView{
                                        Hostname:    srv.Hostname,
                                        Port:        srv.Port,
                                        Quarantined: srv.Quarantined,
                                })
                        }
                        cv.Cities = append(cv.Cities, cityV)
                }
                view.Countries = append(view.Countries, cv)
        }
        r.mu.Lock()
        if r.sl != nil {
                view.FetchedAt = time.Time{} // filled below from cache snapshot
        }
        r.mu.Unlock()
        return view, nil
}

// SetLocation applies a validated desired location IN MEMORY and kicks one
// supervision cycle. Persistence of b4.json belongs to the generic config
// API (the GUI saves it there); this endpoint answers with the fresh status.
func (r *Runtime) SetLocation(loc config.FxVPNLocation) {
        r.mu.Lock()
        r.cfg.Location = loc
        // Force rebuild on next ensure: retire current session descriptor.
        if s := r.session; s != nil {
                _ = s.Close()
        }
        r.session = nil
        r.mu.Unlock()
}

// ValidateLocation checks a requested location against the cached list.
func (r *Runtime) ValidateLocation(ctx context.Context, loc config.FxVPNLocation) error {
        switch strings.ToLower(loc.Mode) {
        case "", "auto":
                return nil
        case "country":
                if strings.TrimSpace(loc.Country) == "" {
                        return errors.New("country required for mode=country")
                }
        case "host":
                if strings.TrimSpace(loc.Host) == "" {
                        return errors.New("host required for mode=host")
                }
        default:
                return fmt.Errorf("mode %q invalid (auto|country|host)", loc.Mode)
        }
        sl, err := r.serverlist()
        if err != nil {
                return err
        }
        countries, _, gerr := sl.Get(ctx)
        if gerr != nil {
                return gerr
        }
        switch strings.ToLower(loc.Mode) {
        case "country":
                for _, c := range countries {
                        if strings.EqualFold(c.Code, loc.Country) {
                                if loc.City == "" {
                                        return nil
                                }
                                for _, city := range c.Cities {
                                        if strings.EqualFold(city.Code, loc.City) {
                                                return nil
                                        }
                                }
                                return fmt.Errorf("city %q not found in %s", loc.City, loc.Country)
                        }
                }
                return fmt.Errorf("country %q not in cached list", loc.Country)
        case "host":
                if _, ok := fxvpn.FindHost(countries, loc.Host); !ok {
                        return fmt.Errorf("host %q not in cached list", loc.Host)
                }
        }
        return nil
}

// TestAccountInput is the accounts/test payload (Дополнение 3).
type TestAccountInput struct {
        Email        string `json:"email"`
        Password     string `json:"password,omitempty"`
        RefreshToken string `json:"refresh_token,omitempty"`
        Label        string `json:"label,omitempty"`
}

// TestAccountResult reports the credential check WITHOUT touching tunnels.
type TestAccountResult struct {
        OK         bool   `json:"ok"`
        NeedsCode  bool   `json:"needs_code,omitempty"`
        Error      string `json:"error,omitempty"`
        Class      string `json:"class,omitempty"`
        QuotaLeft  string `json:"quota_left,omitempty"`
        QuotaMax   string `json:"quota_max,omitempty"`
        QuotaReset string `json:"quota_reset,omitempty"`
        Subscribed *bool  `json:"subscribed,omitempty"`
}

// TestAccount checks credentials end-to-end through the RUNTIME control
// plane (same pins/jar/exit - challenge discipline) but never opens a
// data-plane session. Password-only logins that demand the emailed code
// answer needs_code=true instead of failing.
func (r *Runtime) TestAccount(ctx context.Context, in TestAccountInput) TestAccountResult {
        res := TestAccountResult{}
        var access string
        switch {
        case strings.TrimSpace(in.RefreshToken) != "":
                tok, err := r.poolRefreshForTest(ctx, in.RefreshToken)
                if err != nil {
                        res.Error, res.Class = short(err), fxvpn.Classify(err)
                        return res
                }
                access = tok
        case strings.TrimSpace(in.Password) != "":
                fxa := &fxvpn.FXA{CP: r.cp}
                login, err := fxa.Login(ctx, in.Email, in.Password)
                if err != nil {
                        res.Error, res.Class = short(err), fxvpn.Classify(err)
                        return res
                }
                if !login.Verified {
                        res.NeedsCode = true
                        res.OK = true // credentials accepted; code pending
                        return res
                }
                tok, terr := fxa.OAuthToken(ctx, login.SessionToken)
                if terr != nil {
                        res.Error, res.Class = short(terr), fxvpn.Classify(terr)
                        return res
                }
                access = tok.AccessToken
        default:
                res.Error = "either refresh_token or password required"
                return res
        }

        g := &fxvpn.Guardian{CP: r.cp}
        pass, perr := g.FetchProxyPass(ctx, access)
        if perr != nil {
                var ti *fxvpn.TokenInvalidError
                if errors.As(perr, &ti) {
                        if _, aerr := g.Activate(ctx, access); aerr == nil {
                                pass, perr = g.FetchProxyPass(ctx, access)
                        }
                }
                if perr != nil {
                        res.Error, res.Class = short(perr), fxvpn.Classify(perr)
                        return res
                }
        }
        res.OK = true
        res.QuotaLeft, res.QuotaMax, res.QuotaReset = pass.QuotaLeft, pass.QuotaMax, pass.QuotaReset
        if ent, serr := g.FetchUserInfo(ctx, access); serr == nil {
                res.Subscribed = &ent.Subscribed
        }
        return res
}

func (r *Runtime) poolRefreshForTest(ctx context.Context, rt string) (string, error) {
        tok, err := (&fxvpn.FXA{CP: r.cp}).RefreshToken(ctx, rt)
        if err != nil {
                return "", err
        }
        return tok.AccessToken, nil
}

// ---- supervisor + dial internals -------------------------------------------------

func (r *Runtime) now() time.Time { return time.Now() }

func (r *Runtime) serverlist() (*fxvpn.ServerlistCache, error) {
        r.mu.Lock()
        defer r.mu.Unlock()
        if r.sl == nil {
                sl, err := fxvpn.NewServerlistCache(r.cp, siblingPath(r.cfg.AccountsPath, "serverlist.json"))
                if err != nil {
                        return nil, err
                }
                r.sl = sl
        }
        return r.sl, nil
}

func (r *Runtime) appendEvent(ev fxvpn.PoolEvent) {
        r.mu.Lock()
        defer r.mu.Unlock()
        r.events = append(r.events, ev)
        if len(r.events) > eventsRingCap {
                r.events = r.events[len(r.events)-eventsRingCap:]
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

func (r *Runtime) atomicOK()   { r.recordDial(true) }
func (r *Runtime) atomicFail() { r.recordDial(false) }

// ---- small helpers ---------------------------------------------------------------

// classifyServiceErr maps service-level errors onto taxonomy classes.
func classifyServiceErr(err error) string {
        switch {
        case errors.Is(err, fxvpn.ErrPoolBlocked):
                return fxvpn.ClassQuotaExhausted
        case errors.Is(err, fxvpn.ErrNoServers):
                return fxvpn.ClassNoServerForLocation
        case errors.Is(err, fxvpn.ErrPinMismatch):
                return fxvpn.ClassAPIPinMismatch
        default:
                return fxvpn.Classify(err)
        }
}

func hostOf(hostport string) string {
        h, _, err := net.SplitHostPort(hostport)
        if err != nil {
                return ""
        }
        return h
}

func short(err error) string {
        s := err.Error()
        if len(s) > 200 {
                return s[:200]
        }
        return s
}
