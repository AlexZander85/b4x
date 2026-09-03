package nfq

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fixtures"
	"github.com/daniellavrushin/b4/lab"
)

// levelCActionTestConfig returns a set config on the centralized executor path
// ("none" strategy) with the Level C runtime flags enabled and a confidence
// high enough to pass the strategy preconditions.
func levelCActionTestConfig(t *testing.T, strategies config.StrategyCatalogConfig) (*config.Config, *config.SetConfig) {
	t.Helper()
	cfg, set := actionExecutorTestConfig(t)
	cfg.System.Classifier.Runtime = config.DefaultClassifierRuntimeConfig
	cfg.System.Classifier.Runtime.Confidence.Mutate = 95
	cfg.System.Classifier.Runtime.Strategies = strategies
	cfg.EnsureRuntimeGeneration()
	return cfg, set
}

// reassemblePayloads rebuilds the TCP byte stream from the injected packets.
// Multi-write strategies may send segments out of stream order (disorder,
// reverse), so reassembly sorts by TCP sequence exactly like the peer stack.
func reassemblePayloads(t *testing.T, injector *fakePacketInjector, payloadStart int) []byte {
	t.Helper()
	type segment struct {
		seq uint32
		p   []byte
	}
	var segments []segment
	for _, pkt := range injector.packets4 {
		if err := action.ValidatePacket(pkt); err != nil {
			t.Fatalf("executor-built packet failed validation: %v", err)
		}
		seq := binary.BigEndian.Uint32(pkt[24:28])
		segments = append(segments, segment{seq: seq, p: append([]byte(nil), pkt[payloadStart:]...)})
	}
	for i := 1; i < len(segments); i++ {
		for j := i; j > 0 && segments[j].seq < segments[j-1].seq; j-- {
			segments[j], segments[j-1] = segments[j-1], segments[j]
		}
	}
	var out []byte
	for _, seg := range segments {
		out = append(out, seg.p...)
	}
	return out
}

func TestLevelCMarkerMultiSplitAppliedThroughExecutor(t *testing.T) {
	cfg, set := levelCActionTestConfig(t, config.StrategyCatalogConfig{MarkerMultiSplit: true})
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	fake := &fakePacketInjector{}
	w := NewWorkerWithQueue(cfg, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)

	w.dropAndInjectTCP(set, raw, dst)

	if fake.sent4 < 2 {
		t.Fatalf("level C multisplit must produce multiple writes, got %d", fake.sent4)
	}
	if fake.sent6 != 0 {
		t.Fatalf("unexpected IPv6 send: %d", fake.sent6)
	}
	if got := binary.BigEndian.Uint32(fake.packets4[0][24:28]); got != 1000 {
		t.Fatalf("first segment sequence: got %d want 1000", got)
	}
	reassembled := reassemblePayloads(t, fake, 40)
	if !bytes.Equal(reassembled, hello) {
		t.Fatalf("stream bytes changed: %d vs %d", len(reassembled), len(hello))
	}
}

func TestLevelCMarkerMultiDisorderAppliedThroughExecutor(t *testing.T) {
	cfg, set := levelCActionTestConfig(t, config.StrategyCatalogConfig{MarkerMultiDisorder: true})
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	fake := &fakePacketInjector{}
	w := NewWorkerWithQueue(cfg, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)

	w.dropAndInjectTCP(set, raw, dst)

	if fake.sent4 < 2 {
		t.Fatalf("level C multidisorder must produce multiple writes, got %d", fake.sent4)
	}
	reassembled := reassemblePayloads(t, fake, 40)
	if !bytes.Equal(reassembled, hello) {
		t.Fatalf("stream bytes changed after reordering: %d vs %d", len(reassembled), len(hello))
	}
	// Reverse order means the first on-wire payload is the tail segment.
	first := fake.packets4[0][40:]
	if bytes.Equal(first, hello[:len(first)]) {
		t.Fatalf("disorder strategy did not reorder the first segment")
	}
}

func TestLevelCTLSRecordSplitAppliedThroughExecutor(t *testing.T) {
	cfg, set := levelCActionTestConfig(t, config.StrategyCatalogConfig{TLSRecordSplit: true})
	trailing := []byte{0x17, 0x03, 0x03, 0, 1, 0}
	hello := append(fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512), trailing...)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	fake := &fakePacketInjector{}
	w := NewWorkerWithQueue(cfg, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)

	w.dropAndInjectTCP(set, raw, dst)

	if fake.sent4 < 2 {
		t.Fatalf("level C TLS record split must produce multiple writes, got %d", fake.sent4)
	}
	reassembled := reassemblePayloads(t, fake, 40)
	if !bytes.Equal(reassembled, hello) {
		t.Fatalf("TLS record split changed the stream: %d vs %d", len(reassembled), len(hello))
	}
}

func TestLevelCActionFailsOpenWhenDisabled(t *testing.T) {
	cfg, set := actionExecutorTestConfig(t)
	cfg.System.Classifier.Runtime = config.DefaultClassifierRuntimeConfig
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	fake := &fakePacketInjector{}
	w := NewWorkerWithQueue(cfg, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)

	w.dropAndInjectTCP(set, raw, dst)

	if fake.sent4 != 1 {
		t.Fatalf("level C disabled must keep legacy single-send, got %d", fake.sent4)
	}
}

func TestLevelCActionFailsOpenOnLowConfidence(t *testing.T) {
	cfg, set := levelCActionTestConfig(t, config.StrategyCatalogConfig{MarkerMultiSplit: true})
	cfg.System.Classifier.Runtime.Confidence.Mutate = 70 // below catalog MinConfidence 80
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	fake := &fakePacketInjector{}
	w := NewWorkerWithQueue(cfg, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)

	w.dropAndInjectTCP(set, raw, dst)

	if fake.sent4 != 1 {
		t.Fatalf("low confidence must fail open to legacy single-send, got %d", fake.sent4)
	}
}

func TestLevelCActionSuppressesRetransmission(t *testing.T) {
	cfg, set := levelCActionTestConfig(t, config.StrategyCatalogConfig{MarkerMultiSplit: true})
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	fake := &fakePacketInjector{}
	w := NewWorkerWithQueue(cfg, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)

	w.dropAndInjectTCP(set, raw, dst)
	if fake.sent4 < 2 {
		t.Fatalf("first flight must apply the strategy, got %d writes", fake.sent4)
	}
	first := fake.sent4

	// Same flow, same sequence: the token store suppresses the retransmission
	// and the worker fails open to a single legacy send.
	w.dropAndInjectTCP(set, raw, dst)
	if fake.sent4 != first+1 {
		t.Fatalf("retransmission must be suppressed to one legacy send: %d -> %d", first, fake.sent4)
	}
}

// fakeLevelTestSource implements nfq.FakeProfileSource over a standalone
// compiled artifact produced by the same lab.CompileFakeProfile pipeline the
// production bootstrap wires through discovery.NewFakeProfileSource (the
// catalog-backed Select path is exercised via the HTTP surface tests).
type fakeLevelTestSource struct {
	artifact lab.CompiledArtifact
	ok       bool
}

func (s *fakeLevelTestSource) SelectFakeProfile(target string) (lab.CompiledArtifact, bool) {
	if s == nil || !s.ok {
		return lab.CompiledArtifact{}, false
	}
	return s.artifact, true
}

// buildLevelCFakeProfile compiles one fake profile via the production
// lab.CompileFakeProfile pipeline.
func buildLevelCFakeProfile(t *testing.T, raw []byte, replacementSNI string) lab.CompiledArtifact {
	t.Helper()
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	source, err := lab.NewRawClientHelloArtifact("levelc-fake-source", lab.CapturedHelloProfile{ID: "source", HelloHash: hash, SHA256: hash, RawSize: len(raw), IPFamily: "ipv4", PrivacySafe: true}, raw, "level-c-test")
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := lab.CompileFakeProfile(lab.CompileRequest{
		Source:         source,
		Mode:           lab.CompileFingerprintPreserving,
		ReplacementSNI: replacementSNI,
		MTU:            lab.MTUEstimator{Family: "ipv4", MTU: 1500},
		Seed:           9,
		Provenance:     "level-c-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func TestLevelCFakeSplitAppliedThroughExecutor(t *testing.T) {
	cfg, set := levelCActionTestConfig(t, config.StrategyCatalogConfig{FakeDSplit: true})
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	profile := buildLevelCFakeProfile(t, hello, "fake.example")
	fake := &fakePacketInjector{}
	w := NewWorkerWithQueue(cfg, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)
	w.SetFakeProfileSource(&fakeLevelTestSource{artifact: profile, ok: true})

	w.dropAndInjectTCP(set, raw, dst)

	// The executor must apply the whole fake mix: at least one fake write
	// (replacement profile, SNI fake.example) and at least one real write
	// (original stream, SNI api.youtube.com) must hit the wire.
	if fake.sent4 < 2 {
		t.Fatalf("level C fake-split must send fake+real writes, got %d", fake.sent4)
	}
	fakeSNI := false
	realSNI := false
	for _, pkt := range fake.packets4 {
		payload := pkt[40:]
		// Segments carry partial TLS records, so SNI presence is detected
		// byte-wise: the replacement name only occurs in fake writes and the
		// original host only in real writes.
		if bytes.Contains(payload, []byte("fake.example")) {
			fakeSNI = true
		}
		if bytes.Contains(payload, []byte("api.youtube.com")) {
			realSNI = true
		}
	}
	if !fakeSNI || !realSNI {
		t.Fatalf("fake mix must carry both replacement (fake=%v) and original (real=%v) SNI on the wire", fakeSNI, realSNI)
	}
}

func TestLevelCFakeFailsOpenWithoutSource(t *testing.T) {
	cfg, set := levelCActionTestConfig(t, config.StrategyCatalogConfig{FakeDSplit: true})
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	fake := &fakePacketInjector{}
	w := NewWorkerWithQueue(cfg, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)
	// No fake profile source bound: the technique must fail open to the
	// legacy single-send path.

	w.dropAndInjectTCP(set, raw, dst)
	if fake.sent4 != 1 {
		t.Fatalf("fake without source must fail open to one legacy send, got %d", fake.sent4)
	}
}
