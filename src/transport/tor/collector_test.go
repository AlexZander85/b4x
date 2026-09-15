package tor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TT4 DoD (patch-plan §5): mirror race (first NON-EMPTY wins; an empty
// 200 never wins), Moat failure falls back, total failure keeps the old
// list + last_error, trim keeps rare kinds, freshness/pause decisions,
// webtunnel probe strictly HTTP/1.1 (h2 answer = dead), G202 snowflake
// set choice. Everything rides httptest/local listeners (consent rule).

const obfs4Line = "obfs4 45.66.35.35:443 " + fp1 + " cert=abcDEF123 iat-mode=0"
const vanillaLine = "vanilla 5.6.7.8:9001 " + fp1

func lineFile(lines ...string) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// wsStand is a local TLS stand that answers:
//   - raw TCP connects (obfs4/vanilla liveness) with silence+close,
//   - HTTP/1.1 WebSocket upgrade requests (webtunnel liveness) with 101.
type wsStand struct {
	srv *httptest.Server
}

func newWSStand(t *testing.T) *wsStand {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Upgrade", "websocket")
			w.WriteHeader(101)
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	return &wsStand{srv: srv}
}

// dialAll routes every probe dial to the stand (webtunnel targets its URL
// host:port, obfs4/vanilla targets their endpoints — all land here).
func (s *wsStand) dial() ProbeDial {
	return func(ctx context.Context, class ConnClass, host string, port uint16) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", s.srv.Listener.Addr().String())
	}
}

// webtunnelLine builds a webtunnel line whose url= points at the stand.
func (s *wsStand) webtunnelLine() string {
	return "webtunnel 2001:db8::1:443 " + fp1 + " url=" + s.srv.URL + "/secret cert=QUJD"
}

// tlsProbeClient trusts the stand's self-signed certificate for the
// webtunnel upgrade probes (InsecureSkipVerify already in the probe).
func (s *wsStand) probeClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func newTestCollector(t *testing.T, client *http.Client, dial ProbeDial, store *BridgesStore, moatURL string, mirrorURLs []string) *Collector {
	t.Helper()
	return NewCollector(CollectorOptions{
		Store:      store,
		Client:     client,
		Dial:       dial,
		Now:        time.Now,
		MoatURL:    moatURL,
		MirrorURLs: mirrorURLs,
		// consent rule: the injected httptest mirrors are the WHOLE race,
		// the built-in OnionHop list never leaves the sandbox from a test.
		NoDefaultMirrors: true,
	})
}

func TestCollectorMirrorRaceFirstNonEmptyWins(t *testing.T) {
	stand := newWSStand(t)
	// mirror A: empty 200 (never wins); mirror B: dead 500; mirror C: lines.
	var emptyHits, fullHits atomic.Int64
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		emptyHits.Add(1)
		w.WriteHeader(200)
	}))
	defer empty.Close()
	full := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fullHits.Add(1)
		fmt.Fprint(w, lineFile(obfs4Line, stand.webtunnelLine(), vanillaLine))
	}))
	defer full.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer dead.Close()

	dir := t.TempDir()
	store := NewBridgesStore(dir)
	c := newTestCollector(t, &http.Client{Timeout: MirrorRaceCap}, stand.dial(), store, dead.URL, []string{
		empty.URL + "/{file}", dead.URL + "/{file}", full.URL + "/{file}",
	})
	got, err := c.Collect(context.Background(), false, nil, "ru", nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if emptyHits.Load() == 0 {
		t.Fatal("the empty mirror was never queried — race not exercised")
	}
	found := map[string]bool{}
	for _, b := range got.Bridges {
		found[b.Transport] = true
	}
	if !found["obfs4"] || !found["webtunnel"] || !found["vanilla"] {
		t.Fatalf("winning mirror lines missing: %v", found)
	}
	if got.Source != SourceMirror {
		t.Fatalf("source = %q, want %q", got.Source, SourceMirror)
	}
}

func TestCollectorEmptyMirrorsNeverWin(t *testing.T) {
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer empty.Close()
	deadMoat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer deadMoat.Close()

	dir := t.TempDir()
	store := NewBridgesStore(dir)
	c := newTestCollector(t, empty.Client(), deadDial(), store, deadMoat.URL, []string{empty.URL + "/{file}"})
	_, err := c.Collect(context.Background(), false, nil, "ru", nil)
	if err == nil {
		t.Fatal("empty mirrors (200 + empty body never win) + dead moat must fail the conveyor")
	}
	if !strings.Contains(err.Error(), "no live network bridge") {
		t.Fatalf("err = %v", err)
	}
}

func TestCollectorMoatFallbackAndSuccess(t *testing.T) {
	stand := newWSStand(t)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer dead.Close()
	moat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		fmt.Fprint(w, `{"settings":[{"bridges":{"type":"webtunnel","source":"moat","bridge_strings":["`+stand.webtunnelLine()+`"]}},{"bridges":{"type":"obfs4","source":"moat","bridge_strings":["`+obfs4Line+`"]}}]}`)
	}))
	defer moat.Close()

	dir := t.TempDir()
	store := NewBridgesStore(dir)
	c := newTestCollector(t, moat.Client(), stand.dial(), store, moat.URL, []string{dead.URL + "/{file}"})
	got, err := c.Collect(context.Background(), false, nil, "ru", nil)
	if err != nil {
		t.Fatalf("moat fallback: %v", err)
	}
	if got.Source != SourceMoat {
		t.Fatalf("source = %q, want moat", got.Source)
	}
	if len(got.Bridges) != 2 {
		t.Fatalf("bridges = %d, want 2 (webtunnel+obfs4)", len(got.Bridges))
	}
	f, err := store.Load()
	if err != nil || len(f.Bridges) != 2 || f.Source != SourceMoat {
		t.Fatalf("store = %+v err=%v", f, err)
	}
}

func TestCollectorFailureKeepsOldList(t *testing.T) {
	stand := newWSStand(t)
	moat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"settings":[{"bridges":{"type":"obfs4","source":"moat","bridge_strings":["`+obfs4Line+`"]}}]}`)
	}))
	defer moat.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer dead.Close()

	dir := t.TempDir()
	store := NewBridgesStore(dir)
	c := newTestCollector(t, moat.Client(), stand.dial(), store, moat.URL, nil)
	if _, err := c.Collect(context.Background(), false, nil, "ru", nil); err != nil {
		t.Fatalf("first run: %v", err)
	}

	c2 := newTestCollector(t, dead.Client(), deadDial(), store, dead.URL, []string{dead.URL + "/{file}"})
	_, err := c2.Collect(context.Background(), false, nil, "ru", nil)
	if err == nil {
		t.Fatal("dead run must fail")
	}
	f, lerr := store.Load()
	if lerr != nil {
		t.Fatalf("load: %v", lerr)
	}
	if len(f.Bridges) == 0 {
		t.Fatal("failed run must keep the previous list")
	}
	if !strings.Contains(f.LastError, "no live network bridge") {
		t.Fatalf("last_error = %q", f.LastError)
	}
}

func TestCollectorFreshnessAndPause(t *testing.T) {
	dir := t.TempDir()
	store := NewBridgesStore(dir)
	now := time.Now()
	c := NewCollector(CollectorOptions{Store: store, Now: func() time.Time { return now }})

	if !c.ShouldCollect(nil) {
		t.Fatal("fresh collector with pause elapsed must collect")
	}

	// freshness: a recent successful on-disk run suppresses collection
	if err := store.Save(BridgesFile{Schema: BridgesFileSchema, UpdatedAt: now.UnixMilli(), Bridges: []StoredBridge{{Transport: "obfs4", Line: obfs4Line}}}); err != nil {
		t.Fatal(err)
	}
	if c.ShouldCollect(nil) {
		t.Fatal("fresh on-disk bridges must suppress collection (24h freshness)")
	}

	// stale on disk (25h for the later clock), pause elapsed → collect
	later := now.Add(25 * time.Hour)
	stale := NewCollector(CollectorOptions{Store: store, Now: func() time.Time { return later }})
	stale.lastRun = now.Add(-10 * time.Minute)
	if !stale.ShouldCollect(nil) {
		t.Fatal("stale bridges with pause elapsed must collect")
	}

	// pause holds: the last attempt is 2m before the later collector's now
	stale.lastRun = later.Add(-2 * time.Minute)
	if stale.ShouldCollect(nil) {
		t.Fatal("re-collect pause (5m) must hold between attempts")
	}
}

func TestCollectorTrimKeepsRareKinds(t *testing.T) {
	stand := newWSStand(t)
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, fmt.Sprintf("obfs4 45.66.%d.%d:443 %s cert=x%d", i/255, i%255, fp1, i))
	}
	lines = append(lines, stand.webtunnelLine())
	body := `{"settings":[{"bridges":{"type":"obfs4","source":"moat","bridge_strings":[` + quoteList(lines) + `]}}]}`
	moat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer moat.Close()

	dir := t.TempDir()
	store := NewBridgesStore(dir)
	c := newTestCollector(t, moat.Client(), stand.dial(), store, moat.URL, nil)
	got, err := c.Collect(context.Background(), false, nil, "ru", nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	kinds := map[string]int{}
	for _, b := range got.Bridges {
		kinds[b.Transport]++
	}
	if kinds["webtunnel"] != 1 {
		t.Fatalf("rare webtunnel crowded out: %+v", kinds)
	}
	if kinds["obfs4"] > MaxBridgesPerKindCap {
		t.Fatalf("obfs4 over cap: %d", kinds["obfs4"])
	}
}

func TestCollectorSnowflakeSetChoiceG202(t *testing.T) {
	var cdnHits, ampHits atomic.Int64
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Host, "cdn77") {
			cdnHits.Add(1)
			return nil, fmt.Errorf("silent")
		}
		ampHits.Add(1)
		return &http.Response{StatusCode: 404, Body: http.NoBody, Header: http.Header{}}, nil
	})
	dir := t.TempDir()
	store := NewBridgesStore(dir)
	c := newTestCollector(t, &http.Client{Transport: rt}, deadDial(), store, "https://moat.invalid", nil)

	if set := c.chooseSnowflakeSet(context.Background()); set != "amp" {
		t.Fatalf("set = %q, want amp (cdn77 silent, amp answered)", set)
	}
	if cdnHits.Load() == 0 || ampHits.Load() == 0 {
		t.Fatalf("probe counts cdn=%d amp=%d — both must be exercised", cdnHits.Load(), ampHits.Load())
	}

	// both silent: forced cdn77 (G202)
	rt2 := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("silent")
	})
	c2 := newTestCollector(t, &http.Client{Transport: rt2}, deadDial(), store, "https://moat.invalid", nil)
	if set := c2.chooseSnowflakeSet(context.Background()); set != "cdn77" {
		t.Fatalf("both silent: set = %q, want forced cdn77 (G202)", set)
	}
}

func TestCollectorBuiltinNeverCountsAsNetwork(t *testing.T) {
	// builtin snowflake + zero network bridges → conveyor fails (TOR-1).
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer dead.Close()
	dir := t.TempDir()
	store := NewBridgesStore(dir)
	silentClient := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("consent rule: no live rendezvous from tests")
	})}
	c := newTestCollector(t, silentClient, deadDial(), store, dead.URL, []string{dead.URL + "/{file}"})
	_, err := c.Collect(context.Background(), true, nil, "ru", nil)
	if err == nil {
		t.Fatal("builtin-only conveyor must fail the success rule (TOR-1)")
	}
}

func TestCollectorOwnerLinesJoin(t *testing.T) {
	stand := newWSStand(t)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer dead.Close()
	dir := t.TempDir()
	store := NewBridgesStore(dir)
	c := newTestCollector(t, dead.Client(), stand.dial(), store, dead.URL, []string{dead.URL + "/{file}"})
	got, err := c.Collect(context.Background(), false, []string{obfs4Line, vanillaLine}, "ru", nil)
	if err != nil {
		t.Fatalf("owner lines must carry the conveyor: %v", err)
	}
	if got.Source != SourceOwner {
		t.Fatalf("source = %q, want owner", got.Source)
	}
	if len(got.Bridges) != 2 {
		t.Fatalf("bridges = %d, want 2", len(got.Bridges))
	}
}

// --- webtunnel probe: strictly HTTP/1.1 ---

func TestProbeWebtunnelStrictHTTP11(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "websocket")
		w.WriteHeader(101)
	}))
	defer ok.Close()

	h2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		_, _ = conn.Write([]byte("HTTP/2.0 200 OK\r\n\r\n"))
		_ = conn.Close()
	}))
	defer h2.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", 302)
	}))
	defer redirect.Close()

	plainDial := func(ctx context.Context, class ConnClass, host string, port uint16) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	}

	if !ProbeWebtunnel(context.Background(), plainDial, "http://"+ok.Listener.Addr().String()+"/ws") {
		t.Fatal("HTTP/1.1 101 must be alive")
	}
	if ProbeWebtunnel(context.Background(), plainDial, "http://"+h2.Listener.Addr().String()+"/ws") {
		t.Fatal("h2 answer must be dead (no 101 over h2)")
	}
	if ProbeWebtunnel(context.Background(), plainDial, "http://"+redirect.Listener.Addr().String()+"/ws") {
		t.Fatal("redirect must be dead (no redirect following)")
	}
}

func TestProbeRendezvousAnyCodeCounts(t *testing.T) {
	// 404 and 502 both count as alive (G165/G202 canon).
	for _, code := range []int{200, 404, 502} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		if !ProbeRendezvous(context.Background(), srv.Client(), srv.URL) {
			t.Fatalf("status %d must count as rendezvous-alive", code)
		}
		srv.Close()
	}
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := dead.URL
	dead.Close()
	if ProbeRendezvous(context.Background(), (&http.Client{Timeout: time.Second}), url) {
		t.Fatal("connection failure must be rendezvous-dead")
	}
}

// --- helpers ---

// deadDial fails every dial.
func deadDial() ProbeDial {
	return func(ctx context.Context, class ConnClass, host string, port uint16) (net.Conn, error) {
		return nil, fmt.Errorf("dead dial")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func quoteList(lines []string) string {
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + l + `"`)
	}
	return b.String()
}
