package nfq

import (
	"net"
	"testing"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/classifier/fixtures"
	"github.com/daniellavrushin/b4/config"
)

func TestNFQTCPReassemblyAbortsWhenVisibilityIsUnknown(t *testing.T) {
	gate := ppe.DefaultVisibilityGate()
	gate.DisableRequirement("test reset")
	defer gate.DisableRequirement("test cleanup")
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Flags.TCPReassemblyMode = config.ReassemblyObserve
	worker := NewWorkerWithQueue(&cfg, 0)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 91), dst: net.IPv4(203, 0, 113, 91), srcMac: "aa:bb:cc:dd:ee:91"}
	payload := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	gate.EnsureRequired("gen-1", "proof required")
	result := worker.observeTCPReassembly(&cfg, pkt, 1000, 51000, 443, classifier.TCPFlagACK, payload)
	if result.Status != classifier.ReassemblyAborted || worker.tcpReassembly.Len() != 0 {
		t.Fatalf("result=%+v len=%d", result, worker.tcpReassembly.Len())
	}
}
