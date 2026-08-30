package proton

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// freeLogical builds one live logical server JSON entry. When status != 1
// the Servers array is empty (offline logical); a valid one carries TWO
// physicals to exercise the one-physical-per-logical rule.
func freeLogical(name, country, city, ip, key string, load, status, tier int) string {
	head := `{"Name":"` + name + `","Tier":` + strconv.Itoa(tier) + `,"Status":` + strconv.Itoa(status) +
		`,"ExitCountry":"` + country + `","City":"` + city + `","Load":` + strconv.Itoa(load) + `,"Score":1.0,`
	if status != 1 {
		return head + `"Servers":[]}`
	}
	return head + `"Servers":[` +
		`{"EntryIP":"` + ip + `","X25519PublicKey":"` + key + `","Status":1},` +
		`{"EntryIP":"9.9.9.9","X25519PublicKey":"dup-` + name + `","Status":1}]}`
}

func logicalsBody(entries ...string) string {
	return `{"Code":1000,"LogicalServers":[` + strings.Join(entries, ",") + `]}`
}

func standLogicalClient(t *testing.T, respond func(rc recordedCall) (int, string)) (*Client, *apiStand) {
	t.Helper()
	st := newAPIStand(t, respond)
	return st.client(), st
}

// routeToStand rewrites every request onto the plain-HTTP stand listener.
func routeToStand(st *apiStand) http.RoundTripper {
	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		u, err := url.Parse(st.srv.URL)
		if err != nil {
			return nil, err
		}
		r.URL.Scheme = u.Scheme
		r.URL.Host = u.Host
		return http.DefaultTransport.RoundTrip(r)
	})
}

var (
	testNodeA = freeLogical("NL-FREE#1", "NL", "Amsterdam", "1.2.3.4", "peerNL", 10, 1, 0)
	testNodeB = freeLogical("US-FREE#2", "US", "New York", "5.6.7.8", "peerUS", 20, 1, 0)
	testNodeC = freeLogical("NO-FREE#3", "NO", "Oslo", "9.10.11.12", "peerNO", 30, 1, 0)
)

func TestServerlistFetchAndCache(t *testing.T) {
	c, _ := standLogicalClient(t, func(rc recordedCall) (int, string) {
		return http.StatusOK, logicalsBody(testNodeA, testNodeB, testNodeC)
	})
	dir := t.TempDir()
	sc, err := NewServerlistCache(c, filepath.Join(dir, "serverlist.json"))
	if err != nil {
		t.Fatal(err)
	}
	sess := &Session{UID: "u", AccessToken: "a"}

	nodes, fromCache, err := sc.Get(context.Background(), sess)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fromCache {
		t.Fatal("first fetch must not report cache")
	}
	// One physical per logical (Nova rule): 3 logicals -> 3 nodes even though
	// each logical carried a second valid physical.
	if len(nodes) != 3 {
		t.Fatalf("nodes = %d, want 3 (one physical per logical)", len(nodes))
	}
	if sc.Snapshot() != SourceLiveV2 {
		t.Fatalf("source = %q", sc.Snapshot())
	}

	// Persisted: a second cache instance sees the snapshot from disk.
	sc2, err := NewServerlistCache(c, filepath.Join(dir, "serverlist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := sc2.Get(context.Background(), sess); err != nil || !ok {
		t.Fatalf("reload: cache=%v err=%v", ok, err)
	}
}

func TestServerlist304Reuse(t *testing.T) {
	c, st := standLogicalClient(t, func(rc recordedCall) (int, string) {
		if rc.Header.Get("If-Modified-Since") != "" {
			return http.StatusNotModified, ""
		}
		return http.StatusOK, logicalsBody(testNodeA, testNodeB)
	})
	// The stand responder cannot set response headers; a wrapping transport
	// stamps Last-Modified on the 200 logicals answers (the conditional
	// request hint of the next round).
	prev := c.HTTP.Transport
	c.HTTP.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := prev.RoundTrip(r)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Header.Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		}
		return resp, err
	})
	sc, _ := NewServerlistCache(c, "")
	sc.TTL = time.Hour
	sess := &Session{UID: "u", AccessToken: "a"}

	base := time.Unix(1_700_000_000, 0)
	sc.Now = func() time.Time { return base }
	if _, _, err := sc.Get(context.Background(), sess); err != nil {
		t.Fatalf("first: %v", err)
	}
	if st.count() != 1 {
		t.Fatalf("calls = %d", st.count())
	}
	// Ten minutes later: TTL (1h) still fresh -> no call.
	sc.Now = func() time.Time { return base.Add(10 * time.Minute) }
	_, fromCache, err := sc.Get(context.Background(), sess)
	if err != nil || !fromCache {
		t.Fatalf("fresh window: cache=%v err=%v", fromCache, err)
	}
	if st.count() != 1 {
		t.Fatal("fresh window must not hit the wire")
	}
	// Two hours later: expired -> conditional request -> 304 -> reuse.
	sc.Now = func() time.Time { return base.Add(2 * time.Hour) }
	nodes, fromCache, err := sc.Get(context.Background(), sess)
	if err != nil {
		t.Fatalf("304: %v", err)
	}
	if !fromCache || len(nodes) != 2 {
		t.Fatalf("304 reuse: cache=%v nodes=%d", fromCache, len(nodes))
	}
	if st.count() != 2 {
		t.Fatalf("conditional fetch missing (calls=%d)", st.count())
	}
	if st.journal()[1].Header.Get("If-Modified-Since") == "" {
		t.Fatal("second fetch must carry If-Modified-Since")
	}
}

func TestServerlistEmptyFreeTierFallsBackToAsset(t *testing.T) {
	c, _ := standLogicalClient(t, func(rc recordedCall) (int, string) {
		// Paid-only tier (Tier 2) — the free filter yields nothing.
		return http.StatusOK, logicalsBody(freeLogical("NL-PAID#1", "NL", "Amsterdam", "1.2.3.4", "k", 10, 1, 2))
	})
	sc, _ := NewServerlistCache(c, "")
	var events []string
	sc.OnEvent = func(event, source string) { events = append(events, event) }
	nodes, _, err := sc.Get(context.Background(), &Session{UID: "u", AccessToken: "a"})
	if err != nil {
		t.Fatalf("asset fallback failed: %v", err)
	}
	seenNoNodes := false
	for _, ev := range events {
		if ev == ClassNoNodes {
			seenNoNodes = true
		}
	}
	if !seenNoNodes {
		t.Fatalf("events %v miss proton-no-nodes", events)
	}
	if len(nodes) == 0 || sc.Snapshot() != SourceAsset {
		t.Fatalf("source = %q nodes = %d", sc.Snapshot(), len(nodes))
	}
}

func TestServerlistCorruptFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serverlist.json")
	if err := os.WriteFile(path, []byte("{broken json"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := standLogicalClient(t, func(rc recordedCall) (int, string) {
		return http.StatusOK, logicalsBody(testNodeA)
	})
	sc, err := NewServerlistCache(c, path)
	if err == nil {
		t.Fatal("corrupt store must be reported")
	}
	if !errors.Is(err, ErrIdentityCorrupt) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatal("quarantine file missing")
	}
	// The next Get recovers: live fetch over the (now empty) cache.
	nodes, _, gerr := sc.Get(context.Background(), &Session{UID: "u", AccessToken: "a"})
	if gerr != nil || len(nodes) != 1 {
		t.Fatalf("recovery: nodes=%d err=%v", len(nodes), gerr)
	}
}

func TestServerlistOfflineStaleButPresent(t *testing.T) {
	phase := 0 // 0: live, 1+: dead
	c, st := standLogicalClient(t, func(rc recordedCall) (int, string) {
		return http.StatusOK, logicalsBody(testNodeA, testNodeB)
	})
	c.HTTP.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if phase > 0 {
			return nil, errors.New("network down")
		}
		return routeToStand(st).RoundTrip(r)
	})
	dir := t.TempDir()
	sc, _ := NewServerlistCache(c, filepath.Join(dir, "sl.json"))
	base := time.Unix(1_700_000_000, 0)
	sc.Now = func() time.Time { return base }
	sess := &Session{UID: "u", AccessToken: "a"}

	// Phase 0: live fetch fills the cache.
	if _, _, err := sc.Get(context.Background(), sess); err != nil {
		t.Fatalf("live: %v", err)
	}
	// Phase 1: network dead, TTL expired -> stale-but-present.
	phase = 1
	sc.Now = func() time.Time { return base.Add(2 * time.Hour) }
	staleSeen := false
	sc.OnEvent = func(event, source string) {
		if source == SourceStale {
			staleSeen = true
		}
	}
	nodes, fromCache, err := sc.Get(context.Background(), sess)
	if err != nil || !fromCache || len(nodes) != 2 {
		t.Fatalf("stale: cache=%v nodes=%d err=%v", fromCache, len(nodes), err)
	}
	if !staleSeen {
		t.Fatal("stale-but-present must be announced")
	}
}

func TestServerlistOfflineNoCacheUsesAsset(t *testing.T) {
	// No client wired at all (offline mode).
	sc, _ := NewServerlistCache(nil, "")
	nodes, _, err := sc.Get(context.Background(), nil)
	if err != nil {
		t.Fatalf("asset: %v", err)
	}
	if len(nodes) < 40 || sc.Snapshot() != SourceAsset {
		t.Fatalf("source=%q nodes=%d", sc.Snapshot(), len(nodes))
	}
}

// ---- queue -------------------------------------------------------------------------

func TestQueueCountryInterleaveAndPorts(t *testing.T) {
	// Live ranking: NL load 10, US 20, NO 30 — the interleave spreads the
	// head across the three countries.
	nodes := []Node{
		{Name: "NL-1", Country: "NL", EntryIP: "1.1.1.1", Load: 10},
		{Name: "NL-2", Country: "NL", EntryIP: "1.1.1.2", Load: 11},
		{Name: "US-1", Country: "US", EntryIP: "2.2.2.1", Load: 20},
		{Name: "NO-1", Country: "NO", EntryIP: "3.3.3.1", Load: 30},
	}
	q := NewQueue(nodes, 0)
	cands := q.Candidates(Location{Mode: "auto"})
	if len(cands) != 4 {
		t.Fatalf("candidates = %d", len(cands))
	}
	// Head of the queue: no two consecutive candidates from one country.
	for i := 1; i < len(cands); i++ {
		if cands[i].Node.Country == cands[i-1].Node.Country {
			t.Fatalf("consecutive same-country candidates at %d", i)
		}
	}
	// Ports rotate round-robin across the catalog.
	want := []uint16{443, 88, 1224, 51820, 500, 4500}
	for i, c := range cands {
		if c.Port != want[i%len(want)] {
			t.Fatalf("candidate %d port = %d, want round-robin", i, c.Port)
		}
	}
	// The next call rotates the port window by one step.
	cands2 := q.Candidates(Location{Mode: "auto"})
	if cands2[0].Port == cands[0].Port {
		t.Fatal("port rotation did not advance between calls")
	}
}

func TestQueuePortOverride(t *testing.T) {
	q := NewQueue([]Node{{Name: "NL-1", Country: "NL", EntryIP: "1.1.1.1"}}, 51820)
	cands := q.Candidates(Location{Mode: "auto"})
	if len(cands) != 1 || cands[0].Port != 51820 {
		t.Fatalf("override: %+v", cands)
	}
}

func TestQueueLocationFilters(t *testing.T) {
	nodes := []Node{
		{Name: "NL-FREE#1", Country: "NL", EntryIP: "1.1.1.1", Load: 10},
		{Name: "US-FREE#2", Country: "US", EntryIP: "2.2.2.2", Load: 20},
	}
	q := NewQueue(nodes, 0)
	if got := q.Candidates(Location{Mode: "country", Country: "us"}); len(got) != 1 || got[0].Node.Country != "US" {
		t.Fatalf("country filter: %+v", got)
	}
	if got := q.Candidates(Location{Mode: "host", Host: "nl-free#1"}); len(got) != 1 {
		t.Fatalf("host filter: %+v", got)
	}
	if got := q.Candidates(Location{Mode: "host", Host: "2.2.2.2"}); len(got) != 1 {
		t.Fatalf("host-by-ip filter: %+v", got)
	}
	if got := q.Candidates(Location{Mode: "country", Country: "XX"}); len(got) != 0 {
		t.Fatalf("unknown country must yield nothing: %+v", got)
	}
}

func TestValidateLocation(t *testing.T) {
	nodes := []Node{
		{Name: "NL-FREE#1", Country: "NL", EntryIP: "1.1.1.1"},
		{Name: "US-FREE#2", Country: "US", EntryIP: "2.2.2.2"},
	}
	if err := ValidateLocation(Location{Mode: "auto"}, nodes); err != nil {
		t.Fatalf("auto: %v", err)
	}
	if err := ValidateLocation(Location{Mode: "country"}, nodes); err == nil {
		t.Fatal("country without code must fail")
	}
	if err := ValidateLocation(Location{Mode: "country", Country: "NL"}, nodes); err != nil {
		t.Fatalf("valid country: %v", err)
	}
	if err := ValidateLocation(Location{Mode: "country", Country: "XX"}, nodes); err == nil {
		t.Fatal("unknown country must fail")
	}
	if err := ValidateLocation(Location{Mode: "host", Host: "1.1.1.1"}, nodes); err != nil {
		t.Fatalf("host by ip: %v", err)
	}
	if err := ValidateLocation(Location{Mode: "host", Host: "nope"}, nodes); err == nil {
		t.Fatal("unknown host must fail")
	}
	if err := ValidateLocation(Location{Mode: "bogus"}, nodes); err == nil {
		t.Fatal("bogus mode must fail")
	}
}

func TestFreeNodesFiltering(t *testing.T) {
	body := `{"Code":1000,"LogicalServers":[` +
		// free + online + valid physical + one extra physical (deduped)
		`{"Name":"NL-1","Tier":0,"Status":1,"ExitCountry":"NL","Load":5,"Servers":[` +
		`{"EntryIP":"1.1.1.1","X25519PublicKey":"k1","Status":1},{"EntryIP":"1.1.1.2","X25519PublicKey":"k2","Status":1}]},` +
		// paid -> filtered
		`{"Name":"PAID","Tier":2,"Status":1,"Servers":[{"EntryIP":"2.2.2.2","X25519PublicKey":"k3","Status":1}]},` +
		// offline logical -> filtered
		`{"Name":"DEAD","Tier":0,"Status":0,"Servers":[{"EntryIP":"3.3.3.3","X25519PublicKey":"k4","Status":1}]},` +
		// free but physical offline -> filtered
		`{"Name":"NOPHY","Tier":0,"Status":1,"Servers":[{"EntryIP":"","X25519PublicKey":"","Status":0}]}` +
		`]}`
	var resp LogicalsResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	nodes := FreeNodes(&resp)
	if len(nodes) != 1 || nodes[0].Name != "NL-1" || nodes[0].EntryIP != "1.1.1.1" {
		t.Fatalf("free filter: %+v", nodes)
	}
}
