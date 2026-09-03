package nfq

import (
	"net"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/config"
)

func TestPPEPassiveObserverTracksScopedTCPDirections(t *testing.T) {
	cfg := config.DefaultConfig
	cfg.System.Classifier = config.DefaultClassifierConfig
	cfg.System.Classifier.Runtime = config.DefaultClassifierRuntimeConfig
	tracker := ppe.NewPassiveTracker(16, time.Minute)
	worker := NewWorkerWithQueue(&cfg, 100)
	worker.SetPPEPassiveObserver(tracker)
	outPkt := &pktInfo{ver: IPv4, src: net.ParseIP("192.0.2.10"), dst: net.ParseIP("203.0.113.20"), srcStr: "192.0.2.10", dstStr: "203.0.113.20"}
	tcp := make([]byte, TCPHeaderMinLen)
	tcp[4], tcp[5], tcp[6], tcp[7] = 0, 0, 0, 10
	tcp[12] = 5 << 4
	tcp[13] = 0x18
	worker.observePPEPassiveTCP(&cfg, outPkt, 50000, 443, tcp, []byte{1})
	worker.observePPEPassiveTCP(&cfg, outPkt, 50000, 443, tcp, []byte{1})
	inPkt := &pktInfo{ver: IPv4, src: net.ParseIP("203.0.113.20"), dst: net.ParseIP("192.0.2.10"), srcStr: "203.0.113.20", dstStr: "192.0.2.10"}
	worker.observePPEPassiveTCP(&cfg, inPkt, 443, 50000, tcp, []byte{2})
	snapshot := tracker.Snapshot(time.Now())
	if snapshot.State != ppe.PassiveBidirectional || snapshot.OutgoingRetransmits != 1 || snapshot.IncomingProgress != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestPPEPassiveObserverIgnoresUnconfiguredPort(t *testing.T) {
	cfg := config.DefaultConfig
	cfg.System.Classifier = config.DefaultClassifierConfig
	cfg.System.Classifier.Runtime = config.DefaultClassifierRuntimeConfig
	tracker := ppe.NewPassiveTracker(16, time.Minute)
	worker := NewWorkerWithQueue(&cfg, 100)
	worker.SetPPEPassiveObserver(tracker)
	pkt := &pktInfo{ver: IPv4, srcStr: "192.0.2.10", dstStr: "203.0.113.20"}
	tcp := make([]byte, TCPHeaderMinLen)
	tcp[12] = 5 << 4
	worker.observePPEPassiveTCP(&cfg, pkt, 50000, 22, tcp, nil)
	if got := tracker.Snapshot(time.Now()); got.OutgoingPackets != 0 {
		t.Fatalf("unconfigured traffic observed: %+v", got)
	}
}
