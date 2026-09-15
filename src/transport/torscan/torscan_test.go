package torscan

import (
	"context"
	"crypto/tls"
	"encoding/binary"
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

func fetchFromURLs(m map[string]string) Fetcher {
	return func(ctx context.Context, url string) ([]byte, error) {
		if body, ok := m[url]; ok {
			return []byte(body), nil
		}
		return nil, fmt.Errorf("source %q unavailable", url)
	}
}

func TestOnionooPrimaryWins(t *testing.T) {
	relays := []Relay{{Fingerprint: strings.Repeat("A", 40), OrAddresses: []string{"1.2.3.4:443"}}}
	got, src, err := Onionoo(context.Background(), fetchFromURLs(map[string]string{DefaultOnionooURL: onionooBody(relays...)}), nil, "")
	if err != nil || len(got) != 1 || src != DefaultOnionooURL {
		t.Fatalf("got=%+v src=%q err=%v", got, src, err)
	}
}

func TestOnionooFallbackChain(t *testing.T) {
	relays := []Relay{{Fingerprint: strings.Repeat("B", 40), OrAddresses: []string{"5.6.7.8:9001"}}}
	github := "https://raw.githubusercontent.com/ValdikSS/tor-onionoo-mirror/main/details.json"
	got, src, err := Onionoo(context.Background(), fetchFromURLs(map[string]string{github: onionooBody(relays...)}), nil, "")
	if err != nil || len(got) != 1 || src != github {
		t.Fatalf("got=%+v src=%q err=%v", got, src, err)
	}
}

func TestOnionooCacheOfflineFallback(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "cache.json")
	relays := []Relay{{Fingerprint: strings.Repeat("C", 40), OrAddresses: []string{"9.9.9.9:443"}}}
	if _, _, err := Onionoo(context.Background(), fetchFromURLs(map[string]string{DefaultOnionooURL: onionooBody(relays...)}), nil, cache); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	got, src, err := Onionoo(context.Background(), fetchFromURLs(map[string]string{}), nil, cache)
	if err != nil || len(got) != 1 || src != "cache" {
		t.Fatalf("got=%+v src=%q err=%v", got, src, err)
	}
}

func TestOnionooEmptyAnswerSkipped(t *testing.T) {
	relays := []Relay{{Fingerprint: strings.Repeat("D", 40), OrAddresses: []string{"1.1.1.1:443"}}}
	github := "https://raw.githubusercontent.com/ValdikSS/tor-onionoo-mirror/main/details.json"
	got, _, err := Onionoo(context.Background(), fetchFromURLs(map[string]string{
		DefaultOnionooURL: onionooBody(), github: onionooBody(relays...),
	}), nil, "")
	if err != nil || len(got) != 1 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestAddrCandidatesAllAddresses(t *testing.T) {
	r := Relay{Fingerprint: strings.Repeat("E", 40), OrAddresses: []string{
		"1.2.3.4:443", "1.2.3.4:9001", "[2620:106:3003:4b::1]:443", "1.2.3.4:8080",
	}}
	got := AddrCandidates(r, []int{443, 9001})
	if len(got) != 3 {
		t.Fatalf("candidates=%v", got)
	}
	if len(AddrCandidates(r, nil)) != 4 {
		t.Fatal("nil port filter must keep every OR address")
	}
}

func TestBandwidthRankAndShuffle(t *testing.T) {
	relays := []Relay{{Fingerprint: "A", ObservedBandwidth: 100}, {Fingerprint: "B", ObservedBandwidth: 900}, {Fingerprint: "C", ObservedBandwidth: 500}}
	ranked := BandwidthRank(relays)
	if ranked[0].Fingerprint != "B" || ranked[1].Fingerprint != "C" {
		t.Fatalf("rank=%+v", ranked)
	}
	a, b := Shuffle(relays, 42), Shuffle(relays, 42)
	for i := range a {
		if a[i].Fingerprint != b[i].Fingerprint {
			t.Fatal("fixed seed must be deterministic")
		}
	}
}

func TestFilterCountries(t *testing.T) {
	relays := []Relay{{Fingerprint: "A", Country: "RU"}, {Fingerprint: "B", Country: "SE"}, {Fingerprint: "C", Country: "NL"}, {Fingerprint: "D", Country: "TR"}}
	got := filterCountries(relays, []string{"-ru", "-tr"})
	if len(got) != 2 || got[0].Fingerprint != "B" || got[1].Fingerprint != "C" {
		t.Fatalf("exclude=%+v", got)
	}
	got = filterCountries(relays, []string{"!se"})
	if len(got) != 1 || got[0].Fingerprint != "B" {
		t.Fatalf("only=%+v", got)
	}
	got = filterCountries(relays, []string{"nl", "se"})
	if len(got) != 4 || got[0].Fingerprint != "C" || got[1].Fingerprint != "B" {
		t.Fatalf("priority=%+v", got)
	}
}

// fakeRelay speaks the modern in-protocol channel handshake after TLS.
// badMode: 1 wrong VERSIONS; 2 no AUTH_CHALLENGE; 3 TLS dead; 4 malformed CERTS.
type fakeRelay struct {
	ln      net.Listener
	tlsConf *tls.Config
	probes  atomic.Int64
	badMode int
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
		go f.handle(conn)
	}
}

func (f *fakeRelay) handle(c net.Conn) {
	defer c.Close()
	f.probes.Add(1)
	if f.badMode == 3 {
		return
	}
	tc := tls.Server(c, f.tlsConf)
	if err := tc.Handshake(); err != nil {
		return
	}
	clientVersions := make([]byte, len(versionsCell))
	if _, err := readFull(tc, clientVersions); err != nil {
		return
	}
	if f.badMode == 1 {
		_, _ = tc.Write([]byte{0, 0, cmdNetinfo, 0, 0})
		return
	}
	_, _ = tc.Write([]byte{0, 0, cmdVersions, 0, 4, 0, 4, 0, 5})

	certBody := []byte{1, 4, 0, 1, 0x42}
	if f.badMode == 4 {
		certBody = []byte{1, 4, 0, 9, 0x42}
	}
	writeVariable(tc, cmdCerts, certBody)
	if f.badMode != 2 {
		challenge := make([]byte, 34)
		binary.BigEndian.PutUint16(challenge[32:34], 0)
		writeVariable(tc, cmdAuthChallenge, challenge)
	}
	writeNetinfo(tc)
	if f.badMode == 0 {
		// A correct client finishes with its fixed NETINFO cell.
		buf := make([]byte, 4+1+cellBodyLen)
		_, _ = readFull(tc, buf)
	}
}

func writeVariable(c net.Conn, cmd byte, body []byte) {
	header := make([]byte, 7) // v4/5: CircID(4), cmd, len(2)
	header[4] = cmd
	binary.BigEndian.PutUint16(header[5:7], uint16(len(body)))
	_, _ = c.Write(append(header, body...))
}

func writeNetinfo(c net.Conn) {
	cell := make([]byte, 4+1+cellBodyLen)
	cell[4] = cmdNetinfo
	body := cell[5:]
	binary.BigEndian.PutUint32(body[:4], uint32(time.Now().Unix()))
	body[4], body[5] = 4, 4
	copy(body[6:10], []byte{127, 0, 0, 1})
	body[10] = 0
	_, _ = c.Write(cell)
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
	if err := DeepProbe(context.Background(), PlainDial, fr.ln.Addr().String(), 0); err != nil {
		t.Fatalf("good modern relay probe: %v", err)
	}
}

func TestDeepProbeWrongVersions(t *testing.T) {
	fr := newFakeRelay(t, 1)
	if err := DeepProbe(context.Background(), PlainDial, fr.ln.Addr().String(), 0); err == nil {
		t.Fatal("wrong VERSIONS must fail")
	}
}

func TestDeepProbeIncompleteHandshake(t *testing.T) {
	fr := newFakeRelay(t, 2)
	if err := DeepProbe(context.Background(), PlainDial, fr.ln.Addr().String(), 0); err == nil {
		t.Fatal("missing AUTH_CHALLENGE must fail")
	}
}

func TestDeepProbeMalformedCerts(t *testing.T) {
	fr := newFakeRelay(t, 4)
	if err := DeepProbe(context.Background(), PlainDial, fr.ln.Addr().String(), 0); err == nil {
		t.Fatal("malformed CERTS must fail")
	}
}

func TestDeepProbeDeadTLS(t *testing.T) {
	fr := newFakeRelay(t, 3)
	if err := DeepProbe(context.Background(), PlainDial, fr.ln.Addr().String(), 0); err == nil {
		t.Fatal("TLS-refusing endpoint must fail")
	}
}

func TestRandomSNI(t *testing.T) {
	sni := RandomSNI()
	if !strings.HasPrefix(sni, "www.") || !strings.HasSuffix(sni, ".org") {
		t.Fatalf("sni=%q", sni)
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(sni, "www."), ".org")
	if len(mid) < 4 || len(mid) > 25 {
		t.Fatalf("mid len=%d", len(mid))
	}
}

func relayPort(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

func TestScannerGoalDrivenEarlyStop(t *testing.T) {
	fr := newFakeRelay(t, 0)
	fp := strings.Repeat("F", 40)
	relays := []Relay{{Fingerprint: fp, OrAddresses: []string{fr.ln.Addr().String()}, ObservedBandwidth: 1000}}
	fetch := fetchFromURLs(map[string]string{DefaultOnionooURL: onionooBody(relays...)})
	s := NewScanner(fetch, PlainDial)
	res, err := s.Scan(context.Background(), ScanConfig{Goal: 1, Timeout: 10 * time.Second, PoolSize: 4, Ports: []int{relayPort(t, fr.ln.Addr().String())}}, nil, "")
	if err != nil || len(res.Relays) != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	lines := res.BridgeLines()
	if len(lines) != 1 || !strings.HasSuffix(lines[0], fp) {
		t.Fatalf("bridge lines=%v", lines)
	}
}

func TestScannerPersistentCooldown(t *testing.T) {
	fr := newFakeRelay(t, 0)
	fp := strings.Repeat("9", 40)
	relays := []Relay{{Fingerprint: fp, OrAddresses: []string{fr.ln.Addr().String()}, ObservedBandwidth: 999}}
	fetch := fetchFromURLs(map[string]string{DefaultOnionooURL: onionooBody(relays...)})
	cache := filepath.Join(t.TempDir(), "onionoo.json")
	base := time.Unix(1_800_000_000, 0)
	s := NewScanner(fetch, PlainDial)
	s.SetNow(func() time.Time { return base })
	cfg := ScanConfig{Goal: 1, Timeout: 5 * time.Second, Ports: []int{relayPort(t, fr.ln.Addr().String())}}
	if _, err := s.Scan(context.Background(), cfg, nil, cache); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	res, err := s.Scan(context.Background(), cfg, nil, cache)
	if err == nil || res.SkippedCooldown != 1 {
		t.Fatalf("second scan must cooldown-skip: res=%+v err=%v", res, err)
	}
	s.SetNow(func() time.Time { return base.Add(7 * time.Hour) })
	if _, err := s.Scan(context.Background(), cfg, nil, cache); err != nil {
		t.Fatalf("post-cooldown scan: %v", err)
	}
}

func TestScannerNoVerifiedFailsHonestly(t *testing.T) {
	fr := newFakeRelay(t, 3)
	relays := []Relay{{Fingerprint: strings.Repeat("E", 40), OrAddresses: []string{fr.ln.Addr().String()}}}
	fetch := fetchFromURLs(map[string]string{DefaultOnionooURL: onionooBody(relays...)})
	s := NewScanner(fetch, PlainDial)
	_, err := s.Scan(context.Background(), ScanConfig{Goal: 1, Timeout: 5 * time.Second, Ports: []int{relayPort(t, fr.ln.Addr().String())}}, nil, "")
	if err == nil || !strings.Contains(err.Error(), "modern channel probe") {
		t.Fatalf("err=%v", err)
	}
}

func TestScannerSourcesDead(t *testing.T) {
	s := NewScanner(fetchFromURLs(map[string]string{}), PlainDial)
	if _, err := s.Scan(context.Background(), ScanConfig{Goal: 1, Timeout: 3 * time.Second}, nil, ""); err == nil {
		t.Fatal("all sources dead must fail")
	}
}

func TestOnionooViaHTTPTestServer(t *testing.T) {
	relays := []Relay{{Fingerprint: strings.Repeat("1", 40), OrAddresses: []string{"127.0.0.1:443"}, ObservedBandwidth: 12345}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"relays": relays})
	}))
	defer srv.Close()
	got, src, err := Onionoo(context.Background(), HTTPFetcher(srv.Client()), []string{srv.URL}, "")
	if err != nil || len(got) != 1 || got[0].ObservedBandwidth != 12345 || src != srv.URL {
		t.Fatalf("got=%+v src=%q err=%v", got, src, err)
	}
}

func selfSignedCert(t *testing.T) []byte { return tlsTestCertPEM }
func selfSignedKey(t *testing.T) []byte  { return tlsTestKeyPEM }
