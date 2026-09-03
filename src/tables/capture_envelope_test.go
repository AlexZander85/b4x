package tables

import (
	"reflect"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
)

func TestCaptureRuleParams_LegacyMode(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Queue.TCPConnBytesLimit = 19
	cfg.Queue.UDPConnBytesLimit = 8
	// Legacy defaults: flag disabled.
	cfg.System.Classifier.Flags.CaptureEnvelopeEnabled = false

	p, err := captureRuleParamsFor(&cfg)
	if err != nil {
		t.Fatalf("captureRuleParamsFor: %v", err)
	}

	// Legacy contour: limits are extended by one packet (kernel range is
	// 0-based inclusive, envelope accepts packet indexes [0, limit)).
	if p.outgoingLimit != 20 || p.incomingLimit != 20 {
		t.Errorf("tcp limits = %d/%d, want 20/20", p.outgoingLimit, p.incomingLimit)
	}
	if p.udpLimit != 9 {
		t.Errorf("udp limit = %d, want 9", p.udpLimit)
	}
	if !p.alwaysSynAck || !p.alwaysFin || !p.alwaysRst || !p.alwaysQuic {
		t.Errorf("legacy always-queue flags must all be true, got syn_ack=%v fin=%v rst=%v quic=%v",
			p.alwaysSynAck, p.alwaysFin, p.alwaysRst, p.alwaysQuic)
	}
	if p.processedMark != capture.ProcessedMarkBit || p.processedMask != capture.ProcessedMarkMask {
		t.Errorf("legacy processed mark = 0x%x/0x%x, want 0x%x/0x%x",
			p.processedMark, p.processedMask, capture.ProcessedMarkBit, capture.ProcessedMarkMask)
	}
}

func TestCaptureRuleParams_EnvelopeMode(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Queue.IPv4Enabled = true
	cfg.Queue.IPv6Enabled = true
	cfg.Queue.TCPConnBytesLimit = 19
	cfg.Queue.UDPConnBytesLimit = 8

	cfg.System.Classifier.Flags.CaptureEnvelopeEnabled = true
	rc := &cfg.System.Classifier.Runtime.Capture
	rc.OutgoingPacketLimit = 5
	rc.IncomingPacketLimit = 7
	rc.AlwaysQueueSynAck = false
	rc.AlwaysQueueFIN = true
	rc.AlwaysQueueRST = false
	rc.AlwaysQueueQUIC = false
	rc.ProcessedMark = 1 << 26
	rc.ProcessedMarkMask = 1 << 26
	rc.QueueBypass = true

	p, err := captureRuleParamsFor(&cfg)
	if err != nil {
		t.Fatalf("captureRuleParamsFor: %v", err)
	}

	if p.outgoingLimit != 5 || p.incomingLimit != 7 {
		t.Errorf("envelope tcp limits = %d/%d, want 5/7", p.outgoingLimit, p.incomingLimit)
	}
	// UDP limit stays with the queue default — envelope has no UDP bound.
	if p.udpLimit != 9 {
		t.Errorf("udp limit = %d, want 9 (queue default)", p.udpLimit)
	}
	if p.alwaysSynAck || !p.alwaysFin || p.alwaysRst || p.alwaysQuic {
		t.Errorf("envelope always-queue flags not honored: syn_ack=%v fin=%v rst=%v quic=%v",
			p.alwaysSynAck, p.alwaysFin, p.alwaysRst, p.alwaysQuic)
	}
	if p.processedMark != 1<<26 || p.processedMask != 1<<26 {
		t.Errorf("envelope processed mark = 0x%x/0x%x, want 0x4000000/0x4000000", p.processedMark, p.processedMask)
	}
}

// TestCaptureRuleParams_Rollback verifies FB-11's passive-default contract:
// flipping the flag back off must restore exactly the legacy contour.
func TestCaptureRuleParams_Rollback(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Queue.TCPConnBytesLimit = 19
	cfg.Queue.UDPConnBytesLimit = 8

	legacy, err := captureRuleParamsFor(&cfg)
	if err != nil {
		t.Fatalf("legacy params: %v", err)
	}

	// Enable the flag without changing the runtime capture: the envelope falls
	// back to the same bounded defaults, so the effective contour must be
	// identical (masked processed-mark semantics included).
	cfg.System.Classifier.Flags.CaptureEnvelopeEnabled = true
	pEnvelope, err := captureRuleParamsFor(&cfg)
	if err != nil {
		t.Fatalf("envelope params: %v", err)
	}
	if pEnvelope.outgoingLimit != legacy.outgoingLimit ||
		pEnvelope.incomingLimit != legacy.incomingLimit ||
		pEnvelope.udpLimit != legacy.udpLimit {
		t.Errorf("envelope-default limits differ from legacy: %+v vs %+v", pEnvelope, legacy)
	}
	if pEnvelope.alwaysSynAck != legacy.alwaysSynAck ||
		pEnvelope.alwaysFin != legacy.alwaysFin ||
		pEnvelope.alwaysRst != legacy.alwaysRst ||
		pEnvelope.alwaysQuic != legacy.alwaysQuic {
		t.Errorf("envelope-default lifecycle flags differ from legacy: %+v vs %+v", pEnvelope, legacy)
	}
	if pEnvelope.processedMark&pEnvelope.processedMask != legacy.processedMark&legacy.processedMask {
		t.Errorf("envelope-default processed mark semantics differ: 0x%x&0x%x vs 0x%x&0x%x",
			pEnvelope.processedMark, pEnvelope.processedMask, legacy.processedMark, legacy.processedMask)
	}

	// Disable the flag again: same as legacy.
	cfg.System.Classifier.Flags.CaptureEnvelopeEnabled = false
	pRollback, err := captureRuleParamsFor(&cfg)
	if err != nil {
		t.Fatalf("rollback params: %v", err)
	}
	if !reflect.DeepEqual(pRollback, legacy) {
		t.Errorf("rollback contour differs from legacy: %+v vs %+v", pRollback, legacy)
	}
}

// TestIPTablesManifest_EnvelopeVariant exercises buildManifest under the
// envelope flag and proves the installed rule set actually differs from the
// legacy contour (first-N limits + dropped lifecycle flags).
func TestIPTablesManifest_EnvelopeVariant(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Queue.IPv6Enabled = true
	manager := NewIPTablesManager(&cfg, false)

	manifest, err := manager.buildManifest()
	if err != nil {
		t.Skipf("iptables capability unavailable for envelope variant: %v", err)
	}

	var legacySpec strings.Builder
	for _, rule := range manifest.Rules {
		legacySpec.WriteString(strings.Join(rule.Spec, " "))
		legacySpec.WriteByte('\n')
	}

	cfg.System.Classifier.Flags.CaptureEnvelopeEnabled = true
	rc := &cfg.System.Classifier.Runtime.Capture
	rc.OutgoingPacketLimit = 3
	rc.IncomingPacketLimit = 3
	rc.AlwaysQueueRST = false
	rc.AlwaysQueueSynAck = true
	rc.AlwaysQueueFIN = true
	rc.AlwaysQueueQUIC = false

	manager = NewIPTablesManager(&cfg, false)
	manifestEnv, err := manager.buildManifest()
	if err != nil {
		t.Fatalf("buildManifest(envelope): %v", err)
	}

	var envSpec strings.Builder
	for _, rule := range manifestEnv.Rules {
		envSpec.WriteString(strings.Join(rule.Spec, " "))
		envSpec.WriteByte('\n')
	}

	if legacySpec.String() == envSpec.String() {
		t.Fatal("envelope variant produced an identical rule set to the legacy contour")
	}

	envRules := envSpec.String()
	if strings.Contains(envRules, "--tcp-flags RST RST") {
		t.Error("envelope variant must not emit RST rules when AlwaysQueueRST=false")
	}
	for _, rule := range manifestEnv.Rules {
		spec := strings.Join(rule.Spec, " ")
		if strings.Contains(spec, "-p udp") && strings.Contains(spec, "connbytes") {
			t.Error("envelope variant must not emit UDP connbytes rules when AlwaysQueueQUIC=false")
		}
	}
	if !strings.Contains(envRules, "0:2") {
		t.Errorf("envelope variant must use first-N range 0:2 (OutgoingPacketLimit=3), got:\n%s", envRules)
	}
}
