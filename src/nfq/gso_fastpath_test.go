package nfq

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/fixtures"
	"github.com/daniellavrushin/b4/routing"
	libnfqueue "github.com/florianl/go-nfqueue"
)

func testGSOFastPathConfig(mode string, mutate, route bool) (*config.Config, *config.SetConfig) {
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Flags.ClassifierV2Enabled = true
	cfg.System.Classifier.DomainOnlyMode = config.DomainStrict
	cfg.System.Classifier.Runtime.Capture.NFQueue = config.NFQueueCaptureConfig{
		GSOMode:              mode,
		MaxGSOBytes:          65535,
		NormalizeForMutation: true,
		TCPOnly:              true,
	}
	set := config.NewSetConfig()
	set.Id = "youtube"
	set.Name = "youtube"
	set.Enabled = true
	set.Targets.DomainOnly = true
	set.Targets.DomainPolicy = config.DomainPolicyStrict
	set.Targets.DomainsToMatch = []string{"youtube.com"}
	// NewSetConfig intentionally carries the product's legacy combo/fake defaults.
	// A no-action GSO fixture must explicitly disable every normal-packet technique.
	set.Fragmentation.Strategy = config.ConfigNone
	set.Fragmentation.StrategyPool = nil
	set.Faking.SNI = false
	set.Faking.SNIMutation.Mode = config.ConfigOff
	set.TCP.Desync.Mode = config.ConfigOff
	set.TCP.Desync.PostDesync = false
	set.TCP.Win.Mode = config.ConfigOff
	set.TCP.DropSACK = false
	set.TCP.SynFake = false
	if mutate {
		set.Fragmentation.Strategy = "split"
	}
	if route {
		set.Routing.Enabled = true
		set.Routing.Mode = config.RoutingModeProxy
	}
	cfg.Sets = []*config.SetConfig{&set}
	return &cfg, &set
}

func testGSOPacket(payloadLen int, sport uint16) *pktInfo {
	return &pktInfo{
		ver:     IPv4,
		proto:   6,
		src:     net.IPv4(192, 0, 2, byte(sport%200+1)),
		dst:     net.IPv4(203, 0, 113, 10),
		srcStr:  "192.0.2.10",
		dstStr:  "203.0.113.10",
		srcMac:  "aa:bb:cc:dd:ee:10",
		offload: OffloadMetadata{IsGSO: true, PayloadLength: uint32(payloadLen), OriginalLength: uint32(payloadLen)},
	}
}

func splitGSOClientHelloRecords(record []byte) []byte {
	if len(record) < 5 || record[0] != 0x16 {
		return record
	}
	payload := record[5:]
	if len(payload) <= 16*1024 {
		return record
	}
	out := make([]byte, 0, len(record)+5)
	for len(payload) > 0 {
		n := len(payload)
		if n > 16*1024 {
			n = 16 * 1024
		}
		header := []byte{0x16, 0x03, 0x03, 0, 0}
		binary.BigEndian.PutUint16(header[3:5], uint16(n))
		out = append(out, header...)
		out = append(out, payload[:n]...)
		payload = payload[n:]
	}
	return out
}

func TestNFQueueGSOFlagIsModeAndScopeGated(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      string
		candidate bool
		discovery bool
		want      bool
	}{
		{name: "off", mode: config.GSOModeOff},
		{name: "observe production", mode: config.GSOModeObserve},
		{name: "observe candidate", mode: config.GSOModeObserve, candidate: true, want: true},
		{name: "observe discovery", mode: config.GSOModeObserve, discovery: true, want: true},
		{name: "classify", mode: config.GSOModeClassify, want: true},
		{name: "full requests capture only", mode: config.GSOModeFull, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := testGSOFastPathConfig(tc.mode, false, false)
			cfg.Queue.IsDiscovery = tc.discovery
			queueCfg := nfqueueOpenConfig(cfg, 17, tc.candidate)
			got := queueCfg.Flags&libnfqueue.NfQaCfgFlagGSO != 0
			if got != tc.want {
				t.Fatalf("GSO flag=%t want=%t config=%+v", got, tc.want, queueCfg)
			}
		})
	}
}

func TestGSOClassifyFastPathAcceptsCompleteNoActionClientHelloUnchanged(t *testing.T) {
	sizes := []int{1988, 4 * 1024, 16 * 1024, 32 * 1024}
	for i, size := range sizes {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			cfg, _ := testGSOFastPathConfig(config.GSOModeClassify, false, false)
			targetSize := size
			if size > 16*1024 {
				// A second TLS record header adds five bytes; preserve the requested
				// total wire-size fixture while keeping each record <= 2^14 bytes.
				targetSize -= 5
			}
			hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, targetSize)
			hello = splitGSOClientHelloRecords(hello)
			pkt := testGSOPacket(len(hello), uint16(51000+i))
			worker := NewWorkerWithQueue(cfg, 0)
			worker.setGSOCapabilityStatus(GSOCapabilityClassifyReady, "unit target capability")
			worker.SetGSOReadinessEvidence(fullGSOReadinessEvidence(dnsHintConfigGeneration(cfg)))
			vc := &verdictCtx{verdict: engine.VerdictAccept}
			handled, _, result := worker.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, uint16(51000+i), 443, uint32(1000+i*100000), true)
			if !handled || result != gsoPathAcceptedUnchanged || vc.verdict != engine.VerdictAccept {
				t.Fatalf("size=%d handled=%t result=%s verdict=%v", size, handled, result, vc.verdict)
			}
		})
	}
}

func TestGSOClassifyFastPathSuppressesNormalPacketAction(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeClassify, true, false)
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1988)
	pkt := testGSOPacket(len(hello), 52000)
	worker := NewWorkerWithQueue(cfg, 0)
	worker.setGSOCapabilityStatus(GSOCapabilityClassifyReady, "unit target capability")
	worker.SetGSOReadinessEvidence(fullGSOReadinessEvidence(dnsHintConfigGeneration(cfg)))
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	handled, _, result := worker.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, 52000, 443, 9000, true)
	if !handled || result != gsoPathActionSuppressed || vc.verdict != engine.VerdictAccept {
		t.Fatalf("unsafe action was not suppressed: handled=%t result=%s verdict=%v", handled, result, vc.verdict)
	}
}

func TestGSOClassifyFastPathRoutesWithoutMutatingSKB(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeClassify, false, true)
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1988)
	pkt := testGSOPacket(len(hello), 53000)
	worker := NewWorkerWithQueue(cfg, 0)
	worker.routeBindings = routing.NewBindingStore(routing.BindingCapabilities{ExactFlow: true}, 32)
	worker.setGSOCapabilityStatus(GSOCapabilityClassifyReady, "unit target capability")
	worker.SetGSOReadinessEvidence(fullGSOReadinessEvidence(dnsHintConfigGeneration(cfg)))
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	handled, _, result := worker.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, 53000, 443, 10000, true)
	if !handled || result != gsoPathRoutingOnly || vc.verdict != engine.VerdictAccept {
		t.Fatalf("routing-only GSO path mismatch: handled=%t result=%s verdict=%v", handled, result, vc.verdict)
	}
}

func TestGSOClassifyFastPathFailsOpenWithoutCapabilityOrCompleteInput(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeClassify, false, false)
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	worker := NewWorkerWithQueue(cfg, 0)

	pkt := testGSOPacket(len(hello), 54000)
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	handled, _, result := worker.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, 54000, 443, 11000, true)
	if !handled || result != gsoPathCapabilityFailOpen || vc.verdict != engine.VerdictAccept {
		t.Fatalf("unvalidated capability did not fail open: handled=%t result=%s verdict=%v", handled, result, vc.verdict)
	}

	worker.setGSOCapabilityStatus(GSOCapabilityClassifyReady, "unit target capability")
	pkt.offload.Truncated = true
	pkt.offload.OriginalLength++
	vc = &verdictCtx{verdict: engine.VerdictAccept}
	handled, _, result = worker.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, 54000, 443, 11000, true)
	if !handled || result != gsoPathInputFailOpen || vc.verdict != engine.VerdictAccept {
		t.Fatalf("truncated GSO did not fail open: handled=%t result=%s verdict=%v", handled, result, vc.verdict)
	}
}

func TestGSOObserveIsShadowOnlyInCandidateScope(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeObserve, false, false)
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	pkt := testGSOPacket(len(hello), 55000)
	worker := NewWorkerWithQueue(cfg, 0)
	worker.candidate = true
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	handled, _, result := worker.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, 55000, 443, 12000, true)
	if handled || result != gsoPathObserved || vc.verdict != engine.VerdictAccept {
		t.Fatalf("observe changed production verdict: handled=%t result=%s verdict=%v", handled, result, vc.verdict)
	}
	if status := worker.GSOCapabilityStatus(); status.Level != GSOCapabilityObserveOnly {
		t.Fatalf("observe capability not recorded: %+v", status)
	}
}
