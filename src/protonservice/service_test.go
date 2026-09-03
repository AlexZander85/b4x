package protonservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/transport/proton"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// ---- fake Proton API stand (the proton apiStand pattern re-hosted) ------------------

type recordedCall struct {
	Method        string
	Path          string
	Authorization string
	UID           string
	Body          string
	Header        http.Header
}

type apiStand struct {
	mu      sync.Mutex
	calls   []recordedCall
	respond func(rc recordedCall) (int, string)
	client  *http.Client // routes every request onto the stand
}

func newFakeAPI(t *testing.T, respond func(rc recordedCall) (int, string)) *apiStand {
	t.Helper()
	st := &apiStand{respond: respond}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		st.mu.Lock()
		st.calls = append(st.calls, recordedCall{
			Method:        r.Method,
			Path:          r.URL.RequestURI(),
			Authorization: r.Header.Get("Authorization"),
			UID:           r.Header.Get("x-pm-uid"),
			Body:          string(body),
			Header:        r.Header.Clone(),
		})
		respond := st.respond
		st.mu.Unlock()
		if respond == nil {
			respond = func(rc recordedCall) (int, string) { return http.StatusOK, `{"Code":1000}` }
		}
		status, payload := respond(st.calls[len(st.calls)-1])
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(payload))
	})
	srv := newTestServer(t, mux)
	st.client = &http.Client{Transport: rewriteTransport{base: srv.URL}}
	return st
}

func (s *apiStand) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *apiStand) journal() []recordedCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedCall(nil), s.calls...)
}

// rewriteTransport forces every request onto the stand listener (the ladder
// still walks the real host names; everything lands here).
type rewriteTransport struct{ base string }

func (t rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	u := r.URL
	u.Scheme, u.Host = "http", strings.TrimPrefix(t.base, "http://")
	return http.DefaultTransport.RoundTrip(r)
}

func sessionJSON(uid, access, refresh string, scopes ...string) string {
	sc := "[\"vpn\",\"user\"]"
	if len(scopes) > 0 {
		b, _ := json.Marshal(scopes)
		sc = string(b)
	}
	return fmt.Sprintf(`{"Code":1000,"UID":%q,"AccessToken":%q,"RefreshToken":%q,"Scopes":%s}`,
		uid, access, refresh, sc)
}

// logicalsFor builds the v2 answer pointing the single free node at the
// loopback edge with the peer key the edge was configured with. The port
// rides the config override (rt.cfg.Port), not the answer.
func logicalsFor(peerKey string, _ uint16) string {
	return fmt.Sprintf(`{"Code":1000,"LogicalServers":[{"Name":"NL-FREE#1","Tier":0,"Status":1,`+
		`"ExitCountry":"NL","City":"Amsterdam","Load":10,"Score":1.0,`+
		`"Servers":[{"EntryIP":"127.0.0.1","X25519PublicKey":"%s","Status":1}]}]}`, peerKey)
}

// buildRuntime assembles a Runtime wired to the fake API; the caller
// provides the identity slot content (pre-seeded or empty) and the logicals
// responder.
func buildRuntime(t *testing.T, identityPath string, respond func(rc recordedCall) (int, string)) (*Runtime, *apiStand) {
	t.Helper()
	st := newFakeAPI(t, respond)

	cfg := &config.Config{}
	cfg.System.Proton = config.ProtonConfig{
		Enabled:      true,
		IdentityPath: identityPath,
	}
	rt, err := Build(cfg, Options{Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	// Re-route the control plane onto the stand.
	rt.client.HTTP = st.client
	rt.client.Pins = mustPinsMemory(t)
	rt.client.DoH = nil // no mirrors in unit tests
	rt.list = mustListCache(t, rt.client, proton.SiblingPath(identityPath, "serverlist.json"))
	rt.list.OnEvent = func(event, source string) {
		rt.appendEvent(proton.Event{Name: event, Detail: source})
	}
	return rt, st
}

func mustPinsMemory(t *testing.T) *proton.PinStore {
	t.Helper()
	pins, err := proton.NewPinStore("")
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

func mustListCache(t *testing.T, c *proton.Client, path string) *proton.ServerlistCache {
	t.Helper()
	sc, err := proton.NewServerlistCache(c, path)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

// knownIdentity derives a deterministic identity so the mini edge can be
// configured with the client's public key BEFORE the session starts.
func knownIdentity(t *testing.T, path string) *proton.Identity {
	t.Helper()
	seed := [32]byte{}
	for i := range seed {
		seed[i] = byte(0xC0 + i)
	}
	kp := proton.DeriveKeyPair(seed)
	id := &proton.Identity{
		SeedB64:          encodeSeed(seed),
		UID:              "uid-vpn",
		AccessToken:      "tok-vpn",
		RefreshToken:     "rf-vpn",
		RegisteredPubPEM: kp.Ed25519PubPEM,
	}
	id.Format = proton.IdentityFormatVersion
	if err := (&proton.IdentityStore{Path: path}).Save(id); err != nil {
		t.Fatal(err)
	}
	return id
}

func clientPubKeyOf(id *proton.Identity) (twg.Key, error) {
	seed, err := id.Seed()
	if err != nil {
		return twg.Key{}, err
	}
	kp := proton.DeriveKeyPair(seed)
	raw, err := base64.StdEncoding.DecodeString(kp.WGPubKeyB64)
	if err != nil {
		return twg.Key{}, err
	}
	return twg.Key(raw), nil
}

// ---- scenarios ---------------------------------------------------------------------

// Happy path: stored identity -> node list -> REAL seek against the mini
// edge -> session established -> listening. No registration call may happen
// (the stored key IS registered — the once-per-boot gate stamps it).
func TestServiceHappyEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	id := knownIdentity(t, path)

	edge := newMiniEdge(t)
	clientPub, err := clientPubKeyOf(id)
	if err != nil {
		t.Fatal(err)
	}
	edgePubB64, err := edge.configure(clientPub)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder()

	port := edge.port
	rt, st := buildRuntime(t, path, func(rc recordedCall) (int, string) {
		switch {
		case strings.HasPrefix(rc.Path, "/vpn/v2/logicals"):
			return http.StatusOK, logicalsFor(edgePubB64, uint16(port))
		default:
			return http.StatusOK, `{"Code":1000}`
		}
	})
	rt.cfg.Port = uint16(port)
	rt.location = config.ProtonLocation{Mode: "auto"}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rt.tick(ctx)

	// The session completes its gate asynchronously: wait for established.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if stS := rt.Status(); stS.Listening {
			break
		}
		if time.Now().After(deadline) {
			stS := rt.Status()
			t.Fatalf("session did not establish: state=%s last=%q events=%v",
				stS.State, stS.LastFailure, stS.Events)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// NOTE: Start() is not called in this unit test (the tick is driven
	// manually), so "running" (the loop flag) stays false — the honest
	// running/listening split distinguishes them.
	stS := rt.Status()
	if !stS.Enabled || !stS.Listening {
		t.Fatalf("status: %+v", stS)
	}
	if stS.State != StateEstablished {
		t.Fatalf("state = %q", stS.State)
	}
	if stS.ActiveNode != "NL-FREE#1" || stS.ActiveProfile == "" {
		t.Fatalf("active view: %+v", stS)
	}
	if stS.Identity.PubkeyPrefix == "" || !stS.Identity.HasSeed {
		t.Fatalf("identity projection broken: %+v", stS.Identity)
	}

	// Zero registration calls: the stored identity gates the API noise.
	for _, rc := range st.journal() {
		if rc.Path == "/auth/v4/sessions" || rc.Path == "/auth/v4/credentialless" {
			t.Fatalf("unexpected registration call %s", rc.Path)
		}
	}
}

// Registration-once: a fresh boot registers exactly once (1 carrier + 1
// credentialless + 1 certificate); the second tick adds nothing.
func TestServiceRegistrationOncePerBoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	rt, st := buildRuntime(t, path, func(rc recordedCall) (int, string) {
		switch {
		case rc.Path == "/auth/v4/sessions":
			return http.StatusOK, sessionJSON("uid-c", "tok-c", "rf-c", "user")
		case rc.Path == "/auth/v4/credentialless":
			return http.StatusOK, sessionJSON("uid-vpn", "tok-vpn", "rf-vpn", "vpn")
		case rc.Path == "/vpn/v1/certificate":
			return http.StatusOK, fmt.Sprintf(`{"Code":1000,"ExpirationTime":%d}`,
				time.Now().Add(365*24*time.Hour).Unix())
		case strings.HasPrefix(rc.Path, "/vpn/v2/logicals"):
			return http.StatusOK, logicalsFor("pk", 443)
		default:
			return http.StatusOK, `{"Code":1000}`
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rt.tick(ctx)

	creates, credless := 0, 0
	for _, rc := range st.journal() {
		switch rc.Path {
		case "/auth/v4/sessions":
			creates++
		case "/auth/v4/credentialless":
			credless++
		}
	}
	if creates != 1 || credless != 1 {
		t.Fatalf("registration noise: creates=%d credentialless=%d (want 1/1)", creates, credless)
	}
	if id := rt.currentIdentityPtr(); id == nil {
		t.Fatal("identity not registered")
	}

	// Second tick: no new registration (budget spent; no loops).
	rt.tick(ctx)
	creates = 0
	for _, rc := range st.journal() {
		if rc.Path == "/auth/v4/sessions" {
			creates++
		}
	}
	if creates != 1 {
		t.Fatalf("second tick re-registered (creates=%d)", creates)
	}
}

// Jail: two consecutive data-gate failures on established => proton-jailed.
func TestServiceJailDetectionRotates(t *testing.T) {
	dir := t.TempDir()
	rt, _ := buildRuntime(t, filepath.Join(dir, "identity.json"), nil)
	rt.cfg.Enabled = true

	node := proton.Node{Name: "NL-FREE#1", EntryIP: "127.0.0.1", PeerPubKey: "pk"}
	prof := proton.ProtonProfile{Node: node, Port: 443, ProfileID: "proton-vanilla"}

	rt.onSessionLost(node, prof, twg.Failure{Class: twg.ClassStallRX, Reason: "gate"})
	if got := rt.Status().LastFailure; got == proton.ClassJailed {
		t.Fatal("jailed after one strike")
	}
	rt.onSessionLost(node, prof, twg.Failure{Class: twg.ClassStallRX, Reason: "gate"})
	sawJail := false
	for _, ev := range rt.Status().Events {
		if ev.Class == proton.ClassJailed {
			sawJail = true
		}
	}
	if !sawJail {
		t.Fatal("proton-jailed event missing after two strikes")
	}
	if rt.Status().State != StateBackoff {
		t.Fatalf("state = %q", rt.Status().State)
	}
}

// Session refresh matrix: success rotates tokens; 400 marks the class.
func TestServiceRefreshMatrix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	knownIdentity(t, path)
	refreshMode := 0
	rt, st := buildRuntime(t, path, func(rc recordedCall) (int, string) {
		if rc.Path == "/auth/v4/refresh" {
			if refreshMode == 0 {
				return http.StatusOK, `{"Code":1000,"UID":"uid-vpn","AccessToken":"tok-new","RefreshToken":"rf-new"}`
			}
			return http.StatusBadRequest, `{"Code":10013,"Error":"invalid"}`
		}
		return http.StatusOK, `{"Code":1000}`
	})
	// The runtime loaded its own identity at Build; re-point at our slot.
	rt.idStore = &proton.IdentityStore{Path: path}
	if id, err := rt.idStore.Load(); err != nil {
		t.Fatal(err)
	} else {
		rt.mu.Lock()
		rt.identity = id
		r2 := id
		r2.UID = id.UID
		rt.mu.Unlock()
	}

	// Success: tokens rotate, the store updates.
	if err := rt.refreshSession(context.Background(), true); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	reloaded, err := rt.idStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.AccessToken != "tok-new" || reloaded.RefreshToken != "rf-new" {
		t.Fatalf("tokens not persisted: %+v", reloaded.Redacted())
	}
	if st.count() != 1 {
		t.Fatalf("refresh calls = %d", st.count())
	}

	// 400: classified; re-registration stays gated by the boot budget.
	refreshMode = 1
	rt.refreshMu.Lock()
	rt.lastRefreshAt = time.Now().Add(-time.Hour)
	rt.refreshMu.Unlock()
	_ = rt.refreshSession(context.Background(), true)
	if rt.Status().LastFailure != proton.ClassSessionRefreshBad {
		t.Fatalf("last failure = %q", rt.Status().LastFailure)
	}
	// The refresh debounce bypass flag is force=true; a NON-forced call right
	// after a success is debounced away.
	refreshMode = 0
	rt.refreshMu.Lock()
	rt.lastRefreshAt = time.Now()
	rt.refreshMu.Unlock()
	before := st.count()
	_ = rt.refreshSession(context.Background(), false)
	if st.count() != before {
		t.Fatal("debounced call hit the wire")
	}
}

// Locations + ValidateLocation against the cached catalog.
func TestServiceLocationsAndValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	knownIdentity(t, path)
	rt, _ := buildRuntime(t, path, func(rc recordedCall) (int, string) {
		if strings.HasPrefix(rc.Path, "/vpn/v2/logicals") {
			return http.StatusOK, logicalsFor("pk", 443)
		}
		return http.StatusOK, `{"Code":1000}`
	})
	view, err := rt.Locations(context.Background())
	if err != nil {
		t.Fatalf("locations: %v", err)
	}
	if len(view.Countries) != 1 || view.Countries[0].Code != "NL" {
		t.Fatalf("view: %+v", view)
	}
	if err := rt.ValidateLocation(context.Background(), config.ProtonLocation{Mode: "country", Country: "NL"}); err != nil {
		t.Fatalf("valid country rejected: %v", err)
	}
	if err := rt.ValidateLocation(context.Background(), config.ProtonLocation{Mode: "country", Country: "ZZ"}); err == nil {
		t.Fatal("unknown country accepted")
	}
}

// The restart cap: six rebuild stamps exhaust the budget -> cooldown.
func TestServiceRestartCap(t *testing.T) {
	dir := t.TempDir()
	rt, _ := buildRuntime(t, filepath.Join(dir, "identity.json"), nil)
	base := time.Unix(1_700_000_000, 0)
	n := 0
	rt.guard.now = func() time.Time { return base.Add(time.Duration(n) * time.Minute) }
	for i := 0; i < 6; i++ {
		if !rt.guard.allowed() {
			t.Fatalf("rebuild %d capped early", i)
		}
		rt.guard.stamp()
		n++
	}
	if rt.guard.allowed() {
		t.Fatal("budget must be exhausted after 6 rebuilds")
	}
}

// Disabled config: the runtime builds but the tick does nothing.
func TestServiceDisabledHonestIdle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	rt, st := buildRuntime(t, path, nil)
	rt.cfg.Enabled = false
	rt.tick(context.Background())
	if stS := rt.Status(); stS.Listening || stS.State != StateIdle {
		t.Fatalf("disabled tick moved the state: %+v", stS)
	}
	if st.count() != 0 {
		t.Fatal("disabled runtime touched the wire")
	}
}

// ---- key material helpers ----------------------------------------------------------

func mustSeedB64(t *testing.T) string {
	t.Helper()
	seed, err := proton.RandomSeed(crandReader{})
	if err != nil {
		t.Fatal(err)
	}
	return encodeSeed(seed)
}

func mustPubPEM(t *testing.T) string {
	t.Helper()
	seed, err := proton.RandomSeed(crandReader{})
	if err != nil {
		t.Fatal(err)
	}
	return proton.DeriveKeyPair(seed).Ed25519PubPEM
}

// ---- review P7 / L1 ------------------------------------------------------------------

// P7: Reissue retires the LIVE session (SetLocation semantics): a full
// happy e2e establishes against the mini edge, then the owner Reissue
// re-registers and drops the session immediately — no silent serving on
// the old key.
func TestReissueRetiresLiveSession(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	id := knownIdentity(t, path)

	edge := newMiniEdge(t)
	clientPub, err := clientPubKeyOf(id)
	if err != nil {
		t.Fatal(err)
	}
	edgePubB64, err := edge.configure(clientPub)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder()

	port := edge.port
	rt, st := buildRuntime(t, path, func(rc recordedCall) (int, string) {
		switch {
		case strings.HasPrefix(rc.Path, "/vpn/v2/logicals"):
			return http.StatusOK, logicalsFor(edgePubB64, uint16(port))
		case rc.Path == "/auth/v4/sessions":
			// Step 1 of the enrollment ladder (user-scoped, pre-VPN).
			return http.StatusOK, sessionJSON("uid-base", "tok-base", "rf-base", "user")
		case rc.Path == "/auth/v4/credentialless":
			return http.StatusOK, sessionJSON("uid-re", "tok-re", "rf-re", "vpn")
		case rc.Path == "/vpn/v1/certificate":
			return http.StatusOK, fmt.Sprintf(`{"Code":1000,"ExpirationTime":%d}`,
				time.Now().Add(365*24*time.Hour).Unix())
		default:
			return http.StatusOK, `{"Code":1000}`
		}
	})
	rt.cfg.Port = uint16(port)
	rt.location = config.ProtonLocation{Mode: "auto"}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rt.tick(ctx)

	deadline := time.Now().Add(15 * time.Second)
	for {
		if stS := rt.Status(); stS.Listening {
			break
		}
		if time.Now().After(deadline) {
			stS := rt.Status()
			t.Fatalf("session did not establish: state=%s last=%q", stS.State, stS.LastFailure)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := rt.Reissue(ctx); err != nil {
		t.Fatalf("reissue: %v", err)
	}

	rt.mu.Lock()
	sessAlive := rt.sess != nil
	profiles := len(rt.profiles)
	profIdx := rt.profIdx
	rt.mu.Unlock()
	if sessAlive {
		t.Fatal("the live session survived Reissue (review P7 regression)")
	}
	if profiles != 0 || profIdx != 0 {
		t.Fatalf("profiles not reset: n=%d idx=%d", profiles, profIdx)
	}
	retired := false
	for _, ev := range rt.Status().Events {
		if ev.Name == "proton_session_retired" {
			retired = true
		}
	}
	if !retired {
		t.Fatal("proton_session_retired event missing")
	}
	// The re-registration actually happened (credentialless + certificate).
	sawCredless, sawCert := false, false
	for _, rc := range st.journal() {
		switch rc.Path {
		case "/auth/v4/credentialless":
			sawCredless = true
		case "/vpn/v1/certificate":
			sawCert = true
		}
	}
	if !sawCredless || !sawCert {
		t.Fatalf("reissue registration incomplete: credless=%t cert=%t", sawCredless, sawCert)
	}
}

// L1: the SNI pool of a re-issue respects the >= 30 min adaptation step —
// inside the window the CURRENT name is kept, outside it the full pool
// returns (a fresh name is drawn), and the flag off keeps the pool always.
func TestSNIPoolForIssueAdaptationGate(t *testing.T) {
	dir := t.TempDir()
	rt, _ := buildRuntime(t, filepath.Join(dir, "identity.json"), nil)
	rt.cfg.Obfuscation = config.ProtonObfuscation{
		Enabled:      true,
		I1Adaptation: true,
		SNIPool:      []string{"a.example", "b.example", "c.example"},
	}
	rt.mu.Lock()
	rt.profiles = []proton.ProtonProfile{{SNI: "keep.me", ProfileID: "proton-quic"}}
	rt.profIdx = 0
	rt.mu.Unlock()

	// Degraded just now: keep the current name.
	rt.mu.Lock()
	rt.i1LastSwap = rt.now()
	rt.mu.Unlock()
	if got := rt.sniPoolForIssue(); len(got) != 1 || got[0] != "keep.me" {
		t.Fatalf("inside the step window pool = %v, want [keep.me]", got)
	}

	// Degraded 31 min ago: the window is over, a fresh name is drawn.
	rt.mu.Lock()
	rt.i1LastSwap = rt.now().Add(-31 * time.Minute)
	rt.mu.Unlock()
	if got := rt.sniPoolForIssue(); len(got) != 3 {
		t.Fatalf("after the step window pool = %v, want the full pool", got)
	}

	// Adaptation off: always the full pool.
	rt.cfg.Obfuscation.I1Adaptation = false
	rt.mu.Lock()
	rt.i1LastSwap = rt.now()
	rt.mu.Unlock()
	if got := rt.sniPoolForIssue(); len(got) != 3 {
		t.Fatalf("adaptation off pool = %v, want the full pool", got)
	}
}
