package nfq

import (
	"encoding/binary"
	"testing"

	libnfqueue "github.com/florianl/go-nfqueue"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fixtures"
	"github.com/daniellavrushin/b4/sni"
)

func TestDecodeOffloadMetadataEnvelope(t *testing.T) {
	payload := make([]byte, 1988)
	capLen := uint32(4096)
	skbInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(skbInfo, nfqaSKBGSO|nfqaSKBCsumNotReady|nfqaSKBCsumNotVerified)

	metadata := DecodeOffloadMetadata(libnfqueue.Attribute{
		Payload: &payload,
		CapLen:  &capLen,
		SkbInfo: &skbInfo,
	})
	if !metadata.IsGSO || !metadata.ChecksumNotReady || !metadata.ChecksumNotVerified {
		t.Fatalf("offload flags not decoded: %+v", metadata)
	}
	if metadata.PayloadLength != 1988 || metadata.OriginalLength != 4096 || !metadata.Truncated {
		t.Fatalf("length envelope mismatch: %+v", metadata)
	}
}

func TestDecodeOffloadMetadataMissingAndMalformedAttributesFailOpen(t *testing.T) {
	payload := make([]byte, 64)
	shortCapLen := uint32(32)
	shortSKBInfo := []byte{0x00, 0x01}
	metadata := DecodeOffloadMetadata(libnfqueue.Attribute{Payload: &payload, CapLen: &shortCapLen, SkbInfo: &shortSKBInfo})
	if metadata.IsGSO || metadata.ChecksumNotReady || metadata.ChecksumNotVerified || metadata.Truncated {
		t.Fatalf("malformed metadata changed packet semantics: %+v", metadata)
	}
	if metadata.PayloadLength != 64 || metadata.OriginalLength != 64 {
		t.Fatalf("malformed cap length was not clamped: %+v", metadata)
	}

	empty := DecodeOffloadMetadata(libnfqueue.Attribute{})
	if empty != (OffloadMetadata{}) {
		t.Fatalf("missing attributes should produce empty fail-open envelope: %+v", empty)
	}
}

func TestTruncatedNFQueuePayloadIsNeverPacketLocalCompleteClientHello(t *testing.T) {
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	offload := OffloadMetadata{
		IsGSO:          true,
		PayloadLength:  uint32(len(hello)),
		OriginalLength: uint32(len(hello) + 512),
		Truncated:      true,
	}
	observation := resolveAuthoritativeTLSObservationWithOffload(hello, classifier.TCPReassemblyResult{}, offload)
	if observation.Host != "" || observation.Complete || observation.Source != classifier.EvidencePacketSNI {
		t.Fatalf("truncated payload became authoritative: %+v", observation)
	}
	if observation.Reason != "nfqueue payload truncated" {
		t.Fatalf("missing truncation reason: %+v", observation)
	}
}

func TestCompleteReassemblyMayRecoverFromTruncatedCurrentCopy(t *testing.T) {
	hello := fixtures.BuildTLSClientHello("video.google.com", 0x0304, false, 0)
	result := classifier.TCPReassemblyResult{
		Status:        classifier.ReassemblyComplete,
		Metadata:      sni.ParseTLSClientHelloMetadata(hello),
		ClientHelloID: 91,
		ConfigGen:     17,
	}
	observation := resolveAuthoritativeTLSObservationWithOffload(hello[:16], result, OffloadMetadata{
		IsGSO:          true,
		PayloadLength:  16,
		OriginalLength: uint32(len(hello)),
		Truncated:      true,
	})
	if observation.Host != "video.google.com" || !observation.Complete || observation.Source != classifier.EvidenceReassembledSNI {
		t.Fatalf("complete reassembly did not recover authoritative evidence: %+v", observation)
	}
	if observation.ClientHelloID != 91 || observation.ConfigGen != 17 {
		t.Fatalf("reassembled scope lost: %+v", observation)
	}
}

func TestTruncatedOffloadSkipsPacketLocalTLSDecisionMetadata(t *testing.T) {
	cfg := config.NewConfig()
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	worker := &Worker{}
	complete := worker.tcpTLSDecisionMetadata(&cfg, &pktInfo{}, 51000, 443, hello)
	if !complete.HandshakeParsed || !complete.ClearSNI {
		t.Fatalf("control ClientHello was not parsed: %+v", complete)
	}
	metadata := worker.tcpTLSDecisionMetadata(&cfg, &pktInfo{offload: OffloadMetadata{Truncated: true}}, 51000, 443, hello)
	if metadata != (classifier.TLSMetadata{}) {
		t.Fatalf("truncated packet produced TLS decision metadata: %+v", metadata)
	}
}

func TestGSOCapabilityStatusUsesExplicitValidationLevels(t *testing.T) {
	levels := []GSOCapabilityLevel{
		GSOCapabilityUnsupported,
		GSOCapabilitySupportedUnvalidated,
		GSOCapabilityObserveOnly,
		GSOCapabilityClassifyReady,
		GSOCapabilityFullActionReady,
		GSOCapabilityFailed,
	}
	seen := make(map[GSOCapabilityLevel]struct{}, len(levels))
	for _, level := range levels {
		if level == "" {
			t.Fatal("empty capability level")
		}
		if _, exists := seen[level]; exists {
			t.Fatalf("duplicate capability level %q", level)
		}
		seen[level] = struct{}{}
	}

	worker := NewWorkerWithQueue(nil, 0)
	if status := worker.GSOCapabilityStatus(); status.Level != GSOCapabilitySupportedUnvalidated {
		t.Fatalf("unexpected default capability: %+v", status)
	}
	observed := OffloadMetadata{IsGSO: true, PayloadLength: 4096, OriginalLength: 4096}
	worker.observeOffloadMetadata(observed)
	status := worker.GSOCapabilityStatus()
	if status.Level != GSOCapabilitySupportedUnvalidated || status.LastObserved.IsZero() || status.LastMetadata != observed {
		t.Fatalf("observation status mismatch: %+v", status)
	}
	worker.setGSOCapabilityStatus(GSOCapabilityObserveOnly, "diagnostic scope validated")
	if status = worker.GSOCapabilityStatus(); status.Level != GSOCapabilityObserveOnly || status.Reason == "" {
		t.Fatalf("capability transition lost: %+v", status)
	}
}
