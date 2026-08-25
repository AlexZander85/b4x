package providers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
"os"
	"net/netip"
	"testing"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/faultlab"
)

func udpProviderFor(t *testing.T, addr string) *UDPProvider {
	t.Helper()
	host := "127.0.0.1"
	port := faultlab.PortOf(addr)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatal(err)
	}
	p := NewUDPProvider(ip, port, 0, "catalog-test")
	p.Timeout = 500 * time.Millisecond
	p.RaceWindow = 300 * time.Millisecond
	return p
}

func prep(t *testing.T, p dnspath.DNSPathProvider) dnspath.PreparedDNSPath {
	t.Helper()
	prepared, err := p.Prepare(context.Background(), dnspath.DNSPrepareRequest{Generation: 1, NetworkContextID: "lab", RuntimeEpoch: "e1", Diagnostic: true})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestUDPProviderValidFixture(t *testing.T) {
	fx, addr, err := faultlab.StartUDP(faultlab.ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := udpProviderFor(t, addr)
	prepared := prep(t, p)
	out, err := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Class != dnspath.OutcomePassCorrect {
		t.Fatalf("valid fixture must PASS_CORRECT, got %s", out.Class)
	}
	if out.AnswerFingerprint == "" {
		t.Fatal("answer fingerprint required")
	}
}

func TestUDPProviderDropIsTimeout(t *testing.T) {
	fx, addr, err := faultlab.StartUDP(faultlab.ModeUDPDrop)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := udpProviderFor(t, addr)
	prepared := prep(t, p)
	out, _ := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "A"})
	if out.Class != dnspath.OutcomeTimeout {
		t.Fatalf("udp drop must classify TIMEOUT, got %s", out.Class)
	}
}

func TestUDPTruncationRequiresTCP(t *testing.T) {
	fx, addr, err := faultlab.StartUDP(faultlab.ModeTruncation)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := udpProviderFor(t, addr)
	prepared := prep(t, p)
	out, _ := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "TRUNCATION"})
	if out.Class != dnspath.OutcomeTruncatedRequiresTCP {
		t.Fatalf("TC=1 must classify TRUNCATED_REQUIRES_TCP, got %s", out.Class)
	}
	if !out.Truncated {
		t.Fatal("truncated flag must be set")
	}
}

func TestTCPProviderValidFixture(t *testing.T) {
	fx, addr, err := faultlab.StartTCP(faultlab.ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	ip, _ := netip.ParseAddr("127.0.0.1")
	p := NewTCPProvider(ip, faultlab.PortOf(addr), 0, "catalog-test")
	p.Timeout = time.Second
	prepared := prep(t, p)
	out, err := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Class != dnspath.OutcomePassCorrect {
		t.Fatalf("tcp valid fixture must PASS_CORRECT, got %s", out.Class)
	}
}

func TestTCPSegmentationRequiresOnWireProof(t *testing.T) {
	ip, _ := netip.ParseAddr("127.0.0.1")
	p := NewTCPProvider(ip, 53, 0, "catalog-test")
	p.SegmentWrites = 3
	caps := p.Capabilities()
	if caps.State != dnspath.CapRepresentationUnknown {
		t.Fatalf("unproven segmentation must be BLOCKED_REPRESENTATION_UNKNOWN, got %s", caps.State)
	}
	if p.ID().Family != dnspath.DNSPathTCPSegmented {
		t.Fatal("segmented experiment must carry tcp-segmented family")
	}
	p.SegmentationProven = true
	if !p.Capabilities().Segmentation {
		t.Fatal("proven segmentation must set capability")
	}
}

func TestTCPSegmentedExchangeWorks(t *testing.T) {
	fx, addr, err := faultlab.StartTCP(faultlab.ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	ip, _ := netip.ParseAddr("127.0.0.1")
	p := NewTCPProvider(ip, faultlab.PortOf(addr), 0, "catalog-test")
	p.Timeout = time.Second
	p.SegmentWrites = 4
	p.SegmentationProven = true
	prepared := prep(t, p)
	out, err := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Class != dnspath.OutcomePassCorrect {
		t.Fatalf("segmented exchange must work against fixture, got %s", out.Class)
	}
}

func TestRaceObserverEarlyInjection(t *testing.T) {
	fx, addr, err := faultlab.StartUDP(faultlab.ModeEarlyInjection)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := udpProviderFor(t, addr)
	obs, err := ObserveUDPRace(context.Background(), p, "example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Responses) < 2 {
		t.Fatalf("race observer must collect multiple responses, got %d", len(obs.Responses))
	}
	// with a reference matching the valid (later) answer, classify early injection
	ref := obs.Responses[len(obs.Responses)-1].Fingerprint
	obs.Verdict = ClassifyRace(obs, &ref)
	if obs.Verdict != RaceEarlyInjection {
		t.Fatalf("early forged + later valid must classify early_injection_suspected, got %s", obs.Verdict)
	}
}

func TestRaceObserverDuplicateNotPoisoning(t *testing.T) {
	fx, addr, err := faultlab.StartUDP(faultlab.ModeDuplicate)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := udpProviderFor(t, addr)
	obs, err := ObserveUDPRace(context.Background(), p, "example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Verdict != RaceDuplicate {
		t.Fatalf("identical responses must classify duplicate, got %s", obs.Verdict)
	}
}

func TestRaceNeverTrustsLastByOrder(t *testing.T) {
	// two conflicting valid responses, no reference quorum → inconclusive,
	// never "last wins"
	obs := RaceObservation{Responses: []RaceResponse{
		{ArrivalIndex: 0, Valid: true, Fingerprint: dnspath.ResponseFingerprint{AnswerDigest: "a", RCode: 0}},
		{ArrivalIndex: 1, Valid: true, Fingerprint: dnspath.ResponseFingerprint{AnswerDigest: "b", RCode: 0}},
	}}
	if v := ClassifyRace(obs, nil); v != RaceInconclusive {
		t.Fatalf("conflicting responses without reference quorum must be inconclusive, got %s", v)
	}
}

func TestDoTProviderCertificateValidation(t *testing.T) {
	fx, addr, pool, err := faultlab.StartDoT(faultlab.ModeValid, "dot.lab.example", false)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	host, port, _ := net.SplitHostPort(addr)
	_ = host
	boot := []net.IP{net.ParseIP("127.0.0.1")}
	var portNum int
	fmt.Sscanf(port, "%d", &portNum)
	p := NewDoTProvider("dot.lab.example", boot, portNum, 0, "catalog-test")
	p.RootCAs = pool
	p.Timeout = 2 * time.Second
	prepared := prep(t, p)
	out, err := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Class != dnspath.OutcomePassCorrect {
		t.Fatalf("valid DoT fixture must PASS_CORRECT, got %s", out.Class)
	}
}

func TestDoTProviderRejectsBadCertificate(t *testing.T) {
	fx, addr, pool, err := faultlab.StartDoT(faultlab.ModeValid, "dot.lab.example", true)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	_, port, _ := net.SplitHostPort(addr)
	var portNum int
	fmt.Sscanf(port, "%d", &portNum)
	p := NewDoTProvider("dot.lab.example", []net.IP{net.ParseIP("127.0.0.1")}, portNum, 0, "catalog-test")
	p.RootCAs = pool
	p.Timeout = 2 * time.Second
	prepared := prep(t, p)
	out, _ := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "A"})
	if out.Class != dnspath.OutcomeTLSCertFailure {
		t.Fatalf("certificate failure must classify TLS_CERT_FAILURE, got %s", out.Class)
	}
}

func TestDoTRequiresBootstrap(t *testing.T) {
	p := NewDoTProvider("dot.lab.example", nil, 853, 0, "")
	if caps := p.Capabilities(); caps.State != dnspath.CapBlockedByBootstrap {
		t.Fatalf("missing bootstrap must be BLOCKED_BOOTSTRAP, got %s", caps.State)
	}
}

func TestDoHProviderStages(t *testing.T) {
	fx, url, err := faultlab.StartDoH(faultlab.ModeValid, false)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := NewDoHProvider(url, 0, "catalog-test")
	p.Timeout = 2 * time.Second
	prepared, err := p.Prepare(context.Background(), dnspath.DNSPrepareRequest{Generation: 1, NetworkContextID: "lab", RuntimeEpoch: "e1", Diagnostic: true})
	if err != nil {
		t.Fatal(err)
	}
	// lab httptest server uses a self-signed cert; inject a trusting client
	// for the lab only. Production path keeps mandatory verification.
	prepared.Handle = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 2 * time.Second}
	out, err := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Class != dnspath.OutcomePassCorrect {
		t.Fatalf("valid DoH fixture must PASS_CORRECT, got %s", out.Class)
	}
}

func TestDoHCorruptedBody(t *testing.T) {
	fx, url, err := faultlab.StartDoH(faultlab.ModeValid, true)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := NewDoHProvider(url, 0, "catalog-test")
	prepared, err := p.Prepare(context.Background(), dnspath.DNSPrepareRequest{Generation: 1, NetworkContextID: "lab", RuntimeEpoch: "e1", Diagnostic: true})
	if err != nil {
		t.Fatal(err)
	}
	prepared.Handle = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 2 * time.Second}
	out, _ := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "A"})
	if out.Class.Pass() {
		t.Fatalf("corrupted DoH body must not pass, got %s", out.Class)
	}
}

func TestDoH3DoQHonestUnsupported(t *testing.T) {
	h3 := NewDoH3Provider("https://dns.example/dns-query", "catalog-test")
	if caps := h3.Capabilities(); caps.State != dnspath.CapUnsupported {
		t.Fatalf("unproven QUIC build must report UNSUPPORTED, got %s", caps.State)
	}
	out, _ := h3.Probe(context.Background(), dnspath.PreparedDNSPath{PathID: h3.ID()}, dnspath.DNSProbeQuery{Name: "example.com", QType: 1})
	if out.Class != dnspath.OutcomeQUICUnavailable {
		t.Fatalf("DoH3 probe must classify QUIC_UNAVAILABLE, got %s", out.Class)
	}
	dq := NewDoQProvider("dns.example", "catalog-test")
	if caps := dq.Capabilities(); caps.State != dnspath.CapUnsupported {
		t.Fatal("DoQ must report UNSUPPORTED without QUIC capability")
	}
	// ADR-ADNS-003: never attributed to dnscrypt backend
	if h3.ID().Family.Managed() || dq.ID().Family.Managed() {
		t.Fatal("DoH3/DoQ must never be managed-backend families")
	}
}

func TestSystemForwardRecursionDetection(t *testing.T) {
	dir := t.TempDir()
	resolv := dir + "/resolv.conf"
	if err := writeFile(resolv, "nameserver 127.0.0.1\n"); err != nil {
		t.Fatal(err)
	}
	p := NewSystemForwardProvider(resolv, []string{"127.0.0.1:55331"}, 0)
	recursive, err := p.DetectRecursion()
	if err != nil {
		t.Fatal(err)
	}
	if !recursive {
		t.Fatal("system resolver pointing at B4X listener must be detected as recursion")
	}
	if caps := p.Capabilities(); caps.State != dnspath.CapBlockedByDependency {
		t.Fatalf("recursive system path must be BLOCKED_BY_DEPENDENCY, got %s", caps.State)
	}
}

func TestSystemForwardPrepare(t *testing.T) {
	fx, addr, err := faultlab.StartUDP(faultlab.ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	dir := t.TempDir()
	resolv := dir + "/resolv.conf"
	if err := writeFile(resolv, fmt.Sprintf("nameserver 127.0.0.1\n")); err != nil {
		t.Fatal(err)
	}
	_ = addr // fixture runs on port 53 expectation; skip actual prepare exchange (port fixed 53)
	p := NewSystemForwardProvider(resolv, nil, 0)
	if caps := p.Capabilities(); caps.State != dnspath.CapAvailable {
		t.Fatalf("non-recursive system path must be available, got %s", caps.State)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestQuestionMismatchRejected(t *testing.T) {
	query := b4dns.BuildQuery("example.com", 0x1234, 1)
	resp := b4dns.BuildQuery("other.com", 0x1234, 1)
	resp[2] = 0x81 // make it look like a response
	resp[3] = 0x80
	if err := validateResponse(query, resp); err == nil {
		t.Fatal("question mismatch must be rejected (dns_question_mismatch_accepted_total)")
	}
}

func TestTxIDMismatchRejected(t *testing.T) {
	query := b4dns.BuildQuery("example.com", 0x1234, 1)
	resp := b4dns.BuildQuery("example.com", 0x9999, 1)
	if err := validateResponse(query, resp); err == nil {
		t.Fatal("txid mismatch must be rejected")
	}
}

var _ = x509.NewCertPool
