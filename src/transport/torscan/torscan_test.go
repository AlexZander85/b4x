package torscan

// TT9 DoD (patch-plan §10): httptest onionoo (all fallbacks in order;
// offline cache), the fake-TLS relay stand answering the deep probe
// (correct AND incorrect replies), bandwidth ranking, budgets/goal early
// stop, all-or-addresses candidates (the juev bug fix), country filters,
// bridge-line conversion.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func onionooBody(relays ...Relay) string {
	b, _ := json.Marshal(map[string]any{"relays": relays})
	return string(b)
}

func fetchFromURLs(map_ map[string]string) Fetcher {
	return func(ctx context.Context, url string) ([]byte, error) {
		if body, ok := map_[url]; ok {
			return []byte(body), nil
		}
		return nil, fmt.Errorf("source %q unavailable", url)
	}
}

func TestOnionooPrimaryWins(t *testing.T) {
	relays := []Relay{{Fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", OrAddresses: []string{"1.2.3.4:443"}}}
	got, src, err := Onionoo(context.Background(), fetchFromURLs(map[string]string{
		DefaultOnionooURL: onionooBody(relays...),
	}), nil, "")
	if err != nil {
		t.Fatalf("onionoo: %v", err)
	}
	if len(got) != 1 || got[0].Fingerprint != relays[0].Fingerprint {
		t.Fatalf("relays = %+v", got)
	}
	if src != DefaultOnionooURL {
		t.Fatalf("source = %q", src)
	}
}

func TestOnionooFallbackChain(t *testing.T) {
	// primary + CORS dead; the GitHub mirror carries the list; the
	// fallback templates expand {url} — provide both forms.
	relays := []Relay{{Fingerprint: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", OrAddresses: []string{"5.6.7.8:9001"}}}
	httpsURL := strings.ReplaceAll(DefaultOnionooURL, "&", "%26")
	cors := "https://icors.vercel.app/?url=" + httpsURL
	github := "https://raw.githubusercontent.com/ValdikSS/tor-onionoo-mirror/main/details.json"
	got, src, err := Onionoo(context.Background(), fetchFromURLs(map[string]string{
		github: onionooBody(relays...),
	}), nil, "")
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("relays = %+v", got)
	}
	if src != github {
		t.Fatalf("source = %q", src)
	}
	_ = cors
}

func TestOnionooCacheOfflineFallback(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache.json")
	relays := []Relay{{Fingerprint: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", OrAddresses: []string{"9.9.9.9:443"}}}
	// first: a live source populates the cache
	if _, _, err := Onionoo(context.Background(), fetchFromURLs(map[string]string{
		DefaultOnionooURL: onionooBody(relays...),
	}), nil, cache); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	// then: everything dead → the cache answers
	got, src, err := Onionoo(context.Background(), fetchFromURLs(map[string]string{}), nil, cache)
	if err != nil {
		t.Fatalf("offline: %v", err)
	}
	if len(got) != 1 || got[0].Fingerprint != relays[0].Fingerprint {
		t.Fatalf("cached relays = %+v", got)
	}
	if src != "cache" {
		t.Fatalf("source = %q", src)
	}
}

func TestOnionooEmptyAnswerSkipped(t *testing.T) {
	// a 200 with an EMPTY relay list never wins; the next source does.
	relays := []Relay{{Fingerprint: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", OrAddresses: []string{"1.1.1.1:443"}}}
	github := "https://raw.githubusercontent.com/ValdikSS/tor-onionoo-mirror/main/details.json"
	got, _, err := Onionoo(context.Background(), fetchFromURLs(map[string]string{
		DefaultOnionooURL: onionooBody(), // empty
		github:            onionooBody(relays...),
	}), nil, "")
	if err != nil || len(got) != 1 {
		t.Fatalf("empty-first: relays=%+v err=%v", got, err)
	}
}

func TestAddrCandidatesAllAddresses(t *testing.T) {
	r := Relay{
		Fingerprint: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
		OrAddresses: []string{"1.2.3.4:443", "1.2.3.4:9001", "[2620:106:3003:4b::1]:443", "1.2.3.4:8080"},
	}
	got := AddrCandidates(r, []int{443, 9001})
	if len(got) != 3 {
		t.Fatalf("candidates = %v (ALL matching or_addresses, both families — juev [0]-bug fixed)", got)
	}
	sawV6 := false
	for _, c := range got {
		if strings.HasPrefix(c, "[2620:") {
			sawV6 = true
		}
	}
	if !sawV6 {
		t.Fatalf("IPv6 candidate missing: %v", got)
	}
	// no port filter: every address
	all := AddrCandidates(r, nil)
	if len(all) != 4 {
		t.Fatalf("unfiltered = %v", all)
	}
}

func TestBandwidthRankAndShuffle(t *testing.T) {
	relays := []Relay{
		{Fingerprint: "A", ObservedBandwidth: 100},
		{Fingerprint: "B", ObservedBandwidth: 900},
		{Fingerprint: "C", ObservedBandwidth: 500},
	}
	ranked := BandwidthRank(relays)
	if ranked[0].Fingerprint != "B" || ranked[1].Fingerprint != "C" || ranked[2].Fingerprint != "A" {
		t.Fatalf("rank = %+v", ranked)
	}
	shuffled := Shuffle(relays, 42)
	if len(shuffled) != 3 {
		t.Fatalf("shuffle lost entries: %+v", shuffled)
	}
	// deterministic seed → same order twice
	again := Shuffle(relays, 42)
	for i := range shuffled {
		if shuffled[i].Fingerprint != again[i].Fingerprint {
			t.Fatal("shuffle must be deterministic for a fixed seed")
		}
	}
}

func TestFilterCountries(t *testing.T) {
	relays := []Relay{
		{Fingerprint: "A", Country: "RU"},
		{Fingerprint: "B", Country: "SE"},
		{Fingerprint: "C", Country: "NL"},
		{Fingerprint: "D", Country: "TR"},
	}
	// exclude
	got := filterCountries(relays, []string{"-ru", "-tr"})
	if len(got) != 2 || got[0].Fingerprint != "B" || got[1].Fingerprint != "C" {
		t.Fatalf("exclude = %+v", got)
	}
	// only
	got = filterCountries(relays, []string{"!se"})
	if len(got) != 1 || got[0].Fingerprint != "B" {
		t.Fatalf("only = %+v", got)
	}
	// priority ordering
	got = filterCountries(relays, []string{"nl", "se"})
	if len(got) != 4 || got[0].Fingerprint != "C" || got[1].Fingerprint != "B" {
		t.Fatalf("priority = %+v", got)
	}
	// no filter: unchanged
	if len(filterCountries(relays, nil)) != 4 {
		t.Fatal("nil filter must keep everything")
	}
}

// --- the fake TLS relay stand ---

// fakeRelay answers the deep probe correctly (VERSIONS → CREATED).
type fakeRelay struct {
	ln      net.Listener
	tlsConf *tls.Config
	probes  atomic.Int64
	badMode int // 1: wrong VERSIONS answer, 2: no CREATED, 3: tls handshake fail
}

func newFakeRelay(t *testing.T, badMode int) *fakeRelay {
	t.Helper()
	cert, err := tls.X509KeyPair(selfSignedCert(t), selfSignedKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fr := &fakeRelay{ln: ln, tlsConf: &tls.Config{Certificates: []tls.Certificate{cert}}, badMode: badMode}
	go fr.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return fr
}

func (f *fakeRelay) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			f.probes.Add(1)
			if f.badMode == 3 {
				return // dead TLS: never handshake
			}
			tc := tls.Server(c, f.tlsConf)
			if err := tc.Handshake(); err != nil {
				return
			}
			// read the VERSIONS cell: circid(4) cmd(1) len(2) = 7 bytes
			head := make([]byte, 7)
			if _, err := readFull(tc, head); err != nil {
				return
			}
			if f.badMode == 1 {
				_, _ = tc.Write([]byte{0x00, 0x00, 0x08, 0x00, 0x00}) // wrong cmd
				return
			}
			// answer VERSIONS: 00 00 07 | len | versions (00 04 00 05)
			_, _ = tc.Write([]byte{0x00, 0x00, 0x07, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05})
			// consume NETINFO (9 bytes: 4+1+4) then answer, then CREATEs
			netinfo := make([]byte, 9)
			if _, err := readFull(tc, netinfo); err != nil {
				return
			}
			if f.badMode == 2 {
				// read one CREATE cell then answer DESTROY (wrong cmd)
				create := make([]byte, 514)
				_, _ = readFull(tc, create)
				_, _ = tc.Write([]byte{0x00, 0x00, 0x00, 0x05, 0x06})
				return
			}
			// consume each CREATE (514 bytes) and answer CREATED per cell
			for {
				create := make([]byte, 514)
				if _, err := readFull(tc, create); err != nil {
					return
				}
				_, _ = tc.Write([]byte{0x00, 0x00, 0x00, 0x05, 0x04}) // CREATED
			}
		}(conn)
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestDeepProbeGoodRelay(t *testing.T) {
	fr := newFakeRelay(t, 0)
	err := DeepProbe(context.Background(), PlainDial, fr.ln.Addr().String(), 2)
	if err != nil {
		t.Fatalf("good relay probe: %v", err)
	}
}

func TestDeepProbeWrongVersions(t *testing.T) {
	fr := newFakeRelay(t, 1)
	if err := DeepProbe(context.Background(), PlainDial, fr.ln.Addr().String(), 1); err == nil {
		t.Fatal("wrong VERSIONS answer must fail the probe")
	}
}

func TestDeepProbeNoCreated(t *testing.T) {
	fr := newFakeRelay(t, 2)
	if err := DeepProbe(context.Background(), PlainDial, fr.ln.Addr().String(), 1); err == nil {
		t.Fatal("missing CREATED must fail the probe")
	}
}

func TestDeepProbeDeadTLS(t *testing.T) {
	fr := newFakeRelay(t, 3)
	if err := DeepProbe(context.Background(), PlainDial, fr.ln.Addr().String(), 1); err == nil {
		t.Fatal("a TLS-refusing endpoint must fail the probe")
	}
}

func TestRandomSNI(t *testing.T) {
	sni := RandomSNI()
	if !strings.HasPrefix(sni, "www.") || !strings.HasSuffix(sni, ".org") {
		t.Fatalf("sni = %q", sni)
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(sni, "www."), ".org")
	if len(mid) < 4 || len(mid) > 25 {
		t.Fatalf("mid len = %d", len(mid))
	}
	if RandomSNI() == sni {
		// 1-in-many chance of collision with 4-25 random chars — retry once
		if RandomSNI() == sni {
			t.Fatal("SNI must be random")
		}
	}
}

// --- scanner driver ---

func TestScannerGoalDrivenEarlyStop(t *testing.T) {
	fr := newFakeRelay(t, 0)
	fp := strings.Repeat("F", 40)
	relays := []Relay{{Fingerprint: fp, OrAddresses: []string{fr.ln.Addr().String()}}}
	// the stand listens on an EPHEMERAL port: the port filter must
	// include it explicitly
	_, portStr, _ := net.SplitHostPort(fr.ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	fetch := fetchFromURLs(map[string]string{DefaultOnionooURL: onionooBody(relays...)})

	s := NewScanner(fetch, PlainDial)
	res, err := s.Scan(context.Background(), ScanConfig{Goal: 1, Timeout: 10 * time.Second, PoolSize: 4, Ports: []int{port}}, nil, "")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Relays) != 1 {
		t.Fatalf("relays = %+v", res.Relays)
	}
	if res.Relays[0].Addr != fr.ln.Addr().String() {
		t.Fatalf("addr = %q", res.Relays[0].Addr)
	}
	lines := res.BridgeLines()
	if len(lines) != 1 || !strings.HasPrefix(lines[0], fr.ln.Addr().String()) || !strings.HasSuffix(lines[0], fp) {
		t.Fatalf("bridge lines = %v", lines)
	}
}

func TestScannerNoVerifiedFailsHonestly(t *testing.T) {
	// only dead relays: the scan fails with the probe count
	fr := newFakeRelay(t, 3)
	relays := []Relay{{Fingerprint: strings.Repeat("E", 40), OrAddresses: []string{fr.ln.Addr().String()}}}
	fetch := fetchFromURLs(map[string]string{DefaultOnionooURL: onionooBody(relays...)})
	s := NewScanner(fetch, PlainDial)
	_, err := s.Scan(context.Background(), ScanConfig{Goal: 1, Timeout: 5 * time.Second}, nil, "")
	if err == nil {
		t.Fatal("no verified relays must fail")
	}
	if !strings.Contains(err.Error(), "deep probe") {
		t.Fatalf("err = %v", err)
	}
}

func TestScannerSourcesDead(t *testing.T) {
	s := NewScanner(fetchFromURLs(map[string]string{}), PlainDial)
	_, err := s.Scan(context.Background(), ScanConfig{Goal: 1, Timeout: 3 * time.Second}, nil, "")
	if err == nil {
		t.Fatal("all sources dead must fail")
	}
}

// httptest-shaped integration: the fetcher rides a real HTTP server.
func TestOnionooViaHTTPTestServer(t *testing.T) {
	relays := []Relay{{Fingerprint: strings.Repeat("1", 40), OrAddresses: []string{"127.0.0.1:443"}, ObservedBandwidth: 12345}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"relays": relays})
	}))
	defer srv.Close()

	got, src, err := Onionoo(context.Background(), HTTPFetcher(srv.Client()), []string{srv.URL}, "")
	if err != nil {
		t.Fatalf("httptest onionoo: %v", err)
	}
	if len(got) != 1 || got[0].ObservedBandwidth != 12345 {
		t.Fatalf("relays = %+v", got)
	}
	if src != srv.URL {
		t.Fatalf("src = %q", src)
	}
}

// selfSignedCert/Key generate a throwaway TLS identity for the stands.
func selfSignedCert(t *testing.T) []byte { return tlsTestCertPEM }
func selfSignedKey(t *testing.T) []byte  { return tlsTestKeyPEM }
