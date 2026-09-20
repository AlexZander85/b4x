// Field harness for the E-FXVPN reserve transport (E-FXVPN field prompt,
// phase F0). These subcommands extend fxvpnctl (the FX5 L0 CLI) instead of
// creating a parallel tool, per the prompt's merge rule.
//
//	fxvpnctl serverlist [-store PATH] [-cache FILE]
//	fxvpnctl account-test [-store PATH] [--email E] [--code N] [--save-rt]
//	fxvpnctl harvest [--store PATH] --signed-in PATH [--label L] [--check]
//	fxvpnctl serve   [-store PATH] [-listen H:P] [location/transport flags]
//	fxvpnctl status  [-store PATH] [location/transport flags]
//	fxvpnctl exit    [-store PATH] [location/transport flags]
//
// SECRETS (red line 2 / prompt): passwords, session tokens and refresh
// tokens are never printed; only Redacted() shapes, quota numbers and
// entitlement surface. harvest writes the refresh token straight into the
// store (0600 atomic) without echoing it.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/awgwarpservice"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fxvpservice"
	"github.com/daniellavrushin/b4/operaservice"
	"github.com/daniellavrushin/b4/reserve"
	fxvpn "github.com/daniellavrushin/b4/transport/fxvpn"
	"golang.org/x/net/proxy"
)

// fieldRuntimeOpts are the transport/location knobs shared by every
// network-touching subcommand (serve/status/exit/serverlist).
type fieldRuntimeOpts struct {
	store      string
	country    string
	city       string
	host       string
	preferH3   bool
	rotatePct  int
	preflight  bool
	fakeTTL    int
	fakeCount  int
	padInitial int
	socks5     string
	wait       time.Duration

	// Base carrier (carrier-nesting, design §7.5): an in-process WARP/AWG
	// session that the fxvpn edge is dialed THROUGH, so the DPI sees only
	// the base tunnel. "awg" builds its own CF device from the given slot.
	base         string
	baseIdentity string
	baseEndpoint string
	baseProfile  string
}

func (o *fieldRuntimeOpts) register(fs *flag.FlagSet) {
	fs.StringVar(&o.store, "store", config.DefaultFxvpnAccountsPath, "path to accounts.json (also anchors pins/serverlist siblings)")
	fs.StringVar(&o.country, "country", "", "location country code (e.g. DE)")
	fs.StringVar(&o.city, "city", "", "location city code (optional)")
	fs.StringVar(&o.host, "host", "", "exact node hostname (overrides country/city)")
	fs.BoolVar(&o.preferH3, "prefer-h3", false, "start the carrier ladder at QUIC/H3")
	fs.IntVar(&o.rotatePct, "rotate-pct", 0, "pre-emptive rotation threshold percent (0=engine default 15; 99 forces rotation)")
	fs.BoolVar(&o.preflight, "preflight-fake", false, "enable the QUIC preflight TTL bait (requires calibrated --fake-ttl)")
	fs.IntVar(&o.fakeTTL, "fake-ttl", 0, "preflight bait hop limit (0=engine default)")
	fs.IntVar(&o.fakeCount, "fake-count", 0, "preflight bait datagram count (0=engine default)")
	fs.IntVar(&o.padInitial, "initial-padding", 0, "QUIC InitialPacketSize (0=engine default 1250)")
	fs.StringVar(&o.socks5, "socks5", "", "route the control plane through SOCKS5 host:port (bootstrap-through-carrier stand-in)")
	fs.DurationVar(&o.wait, "wait", 120*time.Second, "max wait for a serving session")
	fs.StringVar(&o.base, "base", "", "in-process base carrier to nest through: \"awg\" (empty = direct)")
	fs.StringVar(&o.baseIdentity, "base-identity", "", "base carrier AWG identity slot (default chain-awg+awg-outer.json)")
	fs.StringVar(&o.baseEndpoint, "base-endpoint", "", "base carrier WG endpoint ip:port (default 8.39.204.9:7103)")
	fs.StringVar(&o.baseProfile, "base-profile", "", "base carrier AWG profile (default cf-field-i1)")
}

func (o *fieldRuntimeOpts) location() config.FxVPNLocation {
	switch {
	case strings.TrimSpace(o.host) != "":
		return config.FxVPNLocation{Mode: "host", Host: strings.TrimSpace(o.host)}
	case strings.TrimSpace(o.country) != "":
		return config.FxVPNLocation{Mode: "country", Country: strings.ToUpper(strings.TrimSpace(o.country)), City: strings.TrimSpace(o.city)}
	default:
		return config.FxVPNLocation{Mode: "auto"}
	}
}

// newFieldRuntime builds the fxvpservice runtime from CLI knobs. When
// --base is set it first brings up an in-process base carrier and returns it
// for the caller to Stop; the fxvpn control plane bootstraps through it and
// the data plane is FORCED nested (last-good ladder state) so the edge dial
// rides the carrier (design §7.5).
func newFieldRuntime(o *fieldRuntimeOpts) (*fxvpservice.Runtime, *awgwarpservice.Runtime, error) {
	var base *awgwarpservice.Runtime
	opts := fxvpservice.Options{}
	carrierSet := false
	if strings.TrimSpace(o.base) != "" {
		if !strings.EqualFold(strings.TrimSpace(o.base), "awg") {
			return nil, nil, fmt.Errorf("--base %q unsupported (want \"awg\")", o.base)
		}
		b, err := startBaseAWG(context.Background(), o)
		if err != nil {
			return nil, nil, err
		}
		base = b
		bd := operaservice.BaseCarrierDial()
		opts.Carrier = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return bd(ctx, network, addr)
		}
		carrierSet = true
		seedLadderNested(o.store)
	}
	if strings.TrimSpace(o.socks5) != "" {
		d, err := socks5Dial(o.socks5)
		if err != nil {
			if base != nil {
				base.Stop()
			}
			return nil, nil, err
		}
		opts.Carrier = d
		carrierSet = true
	}

	fc := config.FxVPNConfig{
		Enabled:                 true,
		AccountsPath:            o.store,
		Location:                o.location(),
		PreferH3:                o.preferH3,
		RotateThresholdPct:      o.rotatePct,
		BootstrapThroughCarrier: carrierSet,
		Masquerade: config.FxVPNMasqueradeConfig{
			Profile:         "firefox",
			PreflightFake:   o.preflight,
			FakeTTL:         o.fakeTTL,
			FakeCount:       o.fakeCount,
			InitialPadding:  o.padInitial,
			NestOnPortBlock: carrierSet,
		},
	}
	cfg := &config.Config{}
	cfg.System.FxVPN = fc
	rt, err := fxvpservice.Build(cfg, opts)
	if err != nil && base != nil {
		base.Stop()
	}
	return rt, base, err
}

// startBaseAWG brings up a standalone AWG-WARP carrier (its own CF device
// from the given identity slot), waits until it can serve streams and
// registers it as the base transport the fxvpn carrier dial resolves.
func startBaseAWG(ctx context.Context, o *fieldRuntimeOpts) (*awgwarpservice.Runtime, error) {
	idPath := strings.TrimSpace(o.baseIdentity)
	if idPath == "" {
		idPath = "/opt/etc/b4/warp/chain-awg+awg-outer.json"
	}
	ep := strings.TrimSpace(o.baseEndpoint)
	if ep == "" {
		ep = "8.39.204.9:7103"
	}
	prof := strings.TrimSpace(o.baseProfile)
	if prof == "" {
		prof = "cf-field-i1"
	}
	cfg := &config.Config{}
	cfg.System.Warp.AWG = config.WarpAWGConfig{
		Enabled:      true,
		Mode:         config.WarpAWGModeNetstack,
		IdentityPath: idPath,
		Endpoint:     ep,
		Profile:      prof,
		MTU:          1280,
	}
	rt, err := awgwarpservice.Build(cfg, awgwarpservice.Options{})
	if err != nil {
		return nil, fmt.Errorf("base awg build: %w", err)
	}
	if err := rt.Start(ctx); err != nil {
		return nil, fmt.Errorf("base awg start: %w", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		st := rt.Status()
		if st.Listening {
			break
		}
		if time.Now().After(deadline) {
			rt.Stop()
			return nil, fmt.Errorf("base awg not listening after 60s (state=%s last_failure=%q)", st.State, st.LastFailure)
		}
		select {
		case <-ctx.Done():
			rt.Stop()
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	reserve.Register(rt)
	st := rt.Status()
	logf("base carrier: kind=warp endpoint=%s state=%s assigned=%s", st.Endpoint, st.State, st.AssignedV4)
	return rt, nil
}

// seedLadderNested marks the last-good ladder rung nested so fxvpservice.Build
// starts carrier-nested instead of walking into the (blocked) direct edge.
func seedLadderNested(accountsPath string) {
	type ladderState struct {
		Version int       `json:"version"`
		Nested  bool      `json:"nested"`
		SavedAt time.Time `json:"saved_at"`
	}
	blob, _ := json.MarshalIndent(ladderState{Version: 1, Nested: true, SavedAt: time.Now().UTC()}, "", "  ")
	_ = os.WriteFile(siblingPath(accountsPath, "masquerade-ladder.json"), blob, 0600)
}

// socks5Dial adapts a SOCKS5 proxy to the base-carrier DialFunc shape used
// by fxvpservice.Options.Carrier (field stand-in for the daemon's active
// base tunnel; the router has no live SOCKS5 listener configured today).
func socks5Dial(addr string) (fxvpservice.DialFunc, error) {
	host := strings.TrimSpace(addr)
	var auth *proxy.Auth
	if strings.Contains(host, "://") {
		u, err := parseSocksURL(host)
		if err != nil {
			return nil, err
		}
		host = u.host
		auth = u.auth
	}
	if host == "" {
		return nil, errors.New("empty socks5 address")
	}
	d, err := proxy.SOCKS5("tcp", host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	ctxDialer, ok := d.(proxy.ContextDialer)
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, fmt.Errorf("fxvpnctl: socks5 carries tcp only, got %q", network)
		}
		if ok {
			return ctxDialer.DialContext(ctx, network, target)
		}
		return d.Dial(network, target)
	}, nil
}

type socksURL struct {
	host string
	auth *proxy.Auth
}

func parseSocksURL(raw string) (socksURL, error) {
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	var out socksURL
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		cred := rest[:at]
		rest = rest[at+1:]
		user, pw, _ := strings.Cut(cred, ":")
		out.auth = &proxy.Auth{User: user, Password: pw}
	}
	out.host = rest
	if out.host == "" {
		return socksURL{}, fmt.Errorf("parse %q: empty host", raw)
	}
	return out, nil
}

// waitSession blocks until the runtime reports an established session node
// or the deadline passes.
func waitSession(ctx context.Context, rt *fxvpservice.Runtime, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st := rt.Status()
		if st.SessionNode != "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for a session (last failure=%q pool_blocked=%v)", timeout, st.LastFailure, st.Pool.Blocked)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// ---- serverlist ------------------------------------------------------------------

type pinHex struct {
	Host   string `json:"host"`
	Hex8   string `json:"hex8"`
	Seeded bool   `json:"seeded,omitempty"`
}

func cmdServerlist(args []string) error {
	var o fieldRuntimeOpts
	fs := flag.NewFlagSet("serverlist", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	o.register(fs)
	cache := fs.String("cache", "", "serverlist cache path (default: sibling serverlist.json of --store)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	pinPath := pinPathFor(o.store)
	cp, err := fxvpn.NewControlPlane(pinPath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(o.socks5) != "" {
		d, derr := socks5Dial(o.socks5)
		if derr != nil {
			return derr
		}
		cp.SetBaseDial(d)
	}
	cachePath := strings.TrimSpace(*cache)
	if cachePath == "" {
		cachePath = siblingPath(o.store, "serverlist.json")
	}
	sc, err := fxvpn.NewServerlistCache(cp, cachePath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	countries, fromCache, gerr := sc.Get(ctx)
	if gerr != nil {
		return fmt.Errorf("class=%s: %w", fxvpn.Classify(gerr), gerr)
	}

	type hostView struct {
		Hostname    string `json:"hostname"`
		Port        int    `json:"port"`
		Quarantined bool   `json:"quarantined,omitempty"`
	}
	type cityView struct {
		Code    string     `json:"code"`
		Name    string     `json:"name"`
		Servers []hostView `json:"servers"`
	}
	type countryView struct {
		Code   string     `json:"code"`
		Name   string     `json:"name"`
		Cities []cityView `json:"cities"`
	}
	out := struct {
		FetchedAt   time.Time     `json:"fetched_at"`
		FromCache   bool          `json:"from_cache"`
		Countries   int           `json:"countries"`
		Cities      int           `json:"cities"`
		Hosts       int           `json:"hosts"`
		Quarantined int           `json:"quarantined_excluded"`
		Codes       []string      `json:"codes"`
		List        []countryView `json:"list"`
		Pins        []pinHex      `json:"pins"`
	}{FetchedAt: sc.FetchedAt(), FromCache: fromCache}
	for _, c := range countries {
		cv := countryView{Code: c.Code, Name: c.Name}
		out.Codes = append(out.Codes, c.Code)
		out.Countries++
		for _, city := range c.Cities {
			out.Cities++
			cityV := cityView{Code: city.Code, Name: city.Name}
			for _, srv := range city.Servers {
				out.Hosts++
				if srv.Quarantined {
					out.Quarantined++
				}
				cityV.Servers = append(cityV.Servers, hostView{Hostname: srv.Hostname, Port: srv.Port, Quarantined: srv.Quarantined})
			}
			cv.Cities = append(cv.Cities, cityV)
		}
		out.List = append(out.List, cv)
	}
	if ps, perr := fxvpn.LoadPinStore(pinPath); perr == nil {
		for h, v := range ps.Snapshot() {
			p := pinHex{Host: h, Hex8: hex8(v)}
			out.Pins = append(out.Pins, p)
		}
	}
	printJSON(out)
	return nil
}

func hex8(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// ---- harvest (trusted-machine one-shot onboarding) -------------------------------

type signedInUserFile struct {
	AccountData struct {
		Email        string `json:"email"`
		SessionToken string `json:"sessionToken"`
		Verified     bool   `json:"verified"`
	} `json:"accountData"`
}

// cmdHarvest reads the owner's live Firefox profile (signedInUser.json), mints
// an OAuth refresh token from the FxA session token and stores it WITHOUT ever
// printing it (red line II.4.8: trusted machine only, separate CLI).
func cmdHarvest(args []string) error {
	fs := flag.NewFlagSet("harvest", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	storePath := fs.String("store", config.DefaultFxvpnAccountsPath, "path to accounts.json")
	signedIn := fs.String("signed-in", "", "path to Firefox profile signedInUser.json (required)")
	label := fs.String("label", "", "free-form account label")
	check := fs.Bool("check", true, "also fetch the Guardian proxy pass (quota/entitlement)")
	socks := fs.String("socks5", "", "route control plane through SOCKS5 host:port")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if strings.TrimSpace(*signedIn) == "" {
		fmt.Fprintln(os.Stderr, "--signed-in is required")
		os.Exit(2)
	}
	blob, err := os.ReadFile(*signedIn)
	if err != nil {
		return fmt.Errorf("reading signedInUser.json: %w", err)
	}
	var si signedInUserFile
	if jerr := json.Unmarshal(blob, &si); jerr != nil {
		return fmt.Errorf("parsing signedInUser.json: %w", jerr)
	}
	email := strings.TrimSpace(si.AccountData.Email)
	token := strings.TrimSpace(si.AccountData.SessionToken)
	if email == "" || token == "" {
		return errors.New("signedInUser.json carries no FxA session (sign in to Firefox first)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cp, err := fxvpn.NewControlPlane(pinPathFor(*storePath))
	if err != nil {
		return err
	}
	if strings.TrimSpace(*socks) != "" {
		d, derr := socks5Dial(*socks)
		if derr != nil {
			return derr
		}
		cp.SetBaseDial(d)
	}
	fxa := &fxvpn.FXA{CP: cp}
	tok, err := fxa.OAuthToken(ctx, token)
	if err != nil {
		return fmt.Errorf("class=%s: %w", fxvpn.Classify(err), err)
	}
	res := checkResult{OK: true}
	if *check {
		pass, perr := (&fxvpn.Guardian{CP: cp}).FetchProxyPass(ctx, tok.AccessToken)
		if perr != nil {
			res.OK = false
			res.Error, res.Class = perr.Error(), fxvpn.Classify(perr)
		} else {
			res.QuotaLeft, res.QuotaMax, res.QuotaReset = pass.QuotaLeft, pass.QuotaMax, pass.QuotaReset
		}
	}
	store, file, err := loadOrCreate(*storePath)
	if err != nil {
		return err
	}
	acct := fxvpn.Account{Email: email, Label: *label, RefreshToken: tok.RefreshToken}
	if acct.RefreshToken == "" {
		return errors.New("FxA returned no refresh token (access_type=offline expected)")
	}
	upsert(file, acct)
	if err := store.Save(file); err != nil {
		return err
	}
	res.RefreshSaved = true
	type harvestOut struct {
		Account  string      `json:"account"`
		Verified bool        `json:"verified"`
		Result   checkResult `json:"result"`
	}
	printJSON(harvestOut{Account: acct.Redacted(), Verified: si.AccountData.Verified, Result: res})
	return nil
}

// ---- account-test ----------------------------------------------------------------

func cmdAccountTest(args []string) error {
	fs := flag.NewFlagSet("account-test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	storePath := fs.String("store", config.DefaultFxvpnAccountsPath, "path to accounts.json")
	email := fs.String("email", "", "test only this account (default: all)")
	code := fs.String("code", "", "email verification code for password-only accounts")
	saveRT := fs.Bool("save-rt", false, "persist a minted/rotated refresh token back to the store")
	socks := fs.String("socks5", "", "route control plane through SOCKS5 host:port")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	store, file, err := loadOrCreate(*storePath)
	if err != nil {
		return err
	}
	if len(file.Accounts) == 0 {
		return errors.New("no accounts in store: run `fxvpnctl harvest` / `import` first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cp, err := fxvpn.NewControlPlane(pinPathFor(*storePath))
	if err != nil {
		return err
	}
	if strings.TrimSpace(*socks) != "" {
		d, derr := socks5Dial(*socks)
		if derr != nil {
			return derr
		}
		cp.SetBaseDial(d)
	}

	type row struct {
		Account      string      `json:"account"`
		Result       checkResult `json:"result"`
		RefreshSaved bool        `json:"refresh_token_saved,omitempty"`
	}
	var rows []row
	needsCode := false
	changed := false
	for i := range file.Accounts {
		acct := file.Accounts[i]
		if strings.TrimSpace(*email) != "" && !strings.EqualFold(strings.TrimSpace(*email), acct.Email) {
			continue
		}
		newRT, res := verifyCredentials(ctx, cp, creds{
			email: acct.Email, password: acct.Password, refreshToken: acct.RefreshToken, code: *code,
		})
		r := row{Account: acct.Redacted(), Result: res}
		if res.NeedsCode {
			needsCode = true
		}
		if *saveRT && newRT != "" && newRT != acct.RefreshToken {
			file.Accounts[i].RefreshToken = newRT
			changed = true
			r.RefreshSaved = true
		}
		rows = append(rows, r)
	}
	if *saveRT && changed {
		if err := store.Save(file); err != nil {
			return err
		}
	}
	printJSON(rows)
	if needsCode {
		return &needsCodeError{"account-test needs the emailed verification code"}
	}
	return nil
}

// ---- serve (local HTTP/1.1 CONNECT proxy over the fxvpn tunnel) -------------------

func cmdServe(args []string) error {
	var o fieldRuntimeOpts
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	o.register(fs)
	listen := fs.String("listen", "127.0.0.1:18080", "local CONNECT proxy listen address")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rt, base, err := newFieldRuntime(&o)
	if err != nil {
		return err
	}
	if base != nil {
		defer base.Stop()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		return err
	}
	defer rt.Stop()
	if err := waitSession(ctx, rt, o.wait); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	logf("fxvpnctl serve: listening on %s (node=%s carrier=%s)", *listen, rt.Status().SessionNode, rt.Status().Carrier)
	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return aerr
		}
		go handleConnect(ctx, rt, conn)
	}
}

func logf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

func handleConnect(ctx context.Context, rt *fxvpservice.Runtime, raw net.Conn) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(raw)
	host, port, err := parseConnectRequest(br)
	if err != nil {
		writeStatus(raw, 400)
		logf("connect: bad request: %v", err)
		return
	}
	if fxvpservice.IsBypassDomain(host) {
		writeStatus(raw, 502)
		logf("connect %s:%d: refused self-loop (bypass domain)", host, port)
		return
	}
	ip, rerr := resolveHostIP(ctx, host)
	if rerr != nil {
		writeStatus(raw, 502)
		logf("connect %s:%d: resolve: %v", host, port, rerr)
		return
	}
	dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	up, derr := rt.DialStream(dctx, netip.AddrPortFrom(ip, uint16(port)))
	if derr != nil {
		writeStatus(raw, 502)
		logf("connect %s:%d (ip=%s): dial: %v", host, port, ip, derr)
		return
	}
	_ = raw.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	writeStatus(raw, 200)
	relay(raw, br, up)
}

// parseConnectRequest reads the RFC 7231 CONNECT request line + headers.
func parseConnectRequest(br *bufio.Reader) (string, int, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", 0, err
	}
	line = strings.TrimRight(line, "\r\n")
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.EqualFold(fields[0], "CONNECT") {
		return "", 0, fmt.Errorf("expected `CONNECT host:port HTTP/1.1`, got %q", line)
	}
	host, portStr, err := net.SplitHostPort(fields[1])
	if err != nil {
		return "", 0, fmt.Errorf("bad authority %q: %w", fields[1], err)
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", portStr)
	}
	for {
		h, herr := br.ReadString('\n')
		if herr != nil {
			return "", 0, herr
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	return strings.Trim(host, "[]"), port, nil
}

func writeStatus(w io.Writer, code int) {
	text := "OK"
	switch code {
	case 200:
		text = "Connection Established"
	case 400:
		text = "Bad Request"
	case 502:
		text = "Bad Gateway"
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n\r\n", code, text)
}

func resolveHostIP(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		return a.Unmap(), nil
	}
	return netip.Addr{}, fmt.Errorf("no A record for %s", host)
}

func relay(client net.Conn, clientBuf *bufio.Reader, upstream net.Conn) {
	defer upstream.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, clientBuf)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(client, upstream)
	<-done
}

// ---- status / exit ---------------------------------------------------------------

func cmdStatus(args []string) error {
	var o fieldRuntimeOpts
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	o.register(fs)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rt, base, err := newFieldRuntime(&o)
	if err != nil {
		return err
	}
	if base != nil {
		defer base.Stop()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		return err
	}
	defer rt.Stop()
	_ = waitSession(ctx, rt, o.wait)
	printJSON(rt.Status())
	return nil
}

func cmdExit(args []string) error {
	var o fieldRuntimeOpts
	fs := flag.NewFlagSet("exit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	o.register(fs)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rt, base, err := newFieldRuntime(&o)
	if err != nil {
		return err
	}
	if base != nil {
		defer base.Stop()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		return err
	}
	defer rt.Stop()
	if err := waitSession(ctx, rt, o.wait); err != nil {
		return err
	}
	pctx, pcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer pcancel()
	info, perr := rt.ProbeExit(pctx)
	if perr != nil {
		return fmt.Errorf("exit probe: %w", perr)
	}
	printJSON(info)
	return nil
}

// siblingPath returns name next to base's directory (serverlist/pins layout).
func siblingPath(base, name string) string {
	dir := filepath.Dir(base)
	if dir == "." {
		return name
	}
	return filepath.Join(dir, name)
}
