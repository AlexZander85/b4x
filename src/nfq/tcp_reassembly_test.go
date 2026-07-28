package nfq

import (
	"net"
	"testing"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fixtures"
)

func TestNFQTCPReassemblyIsObserveOnlyAndFeatureGated(t *testing.T) {
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	worker := NewWorkerWithQueue(&cfg, 0)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 80), dst: net.IPv4(203, 0, 113, 80), srcMac: "aa:bb:cc:dd:ee:80"}
	payload := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	original := append([]byte(nil), payload...)

	worker.observeTCPReassembly(&cfg, pkt, 1000, 51000, 443, classifier.TCPFlagACK, payload)
	if worker.tcpReassembly.Len() != 0 || string(payload) != string(original) {
		t.Fatalf("disabled reassembly changed state or payload: len=%d", worker.tcpReassembly.Len())
	}

	cfg.System.Classifier.Flags.TCPReassemblyMode = config.ReassemblyObserve
	worker.observeTCPReassembly(&cfg, pkt, 1000, 51000, 443, classifier.TCPFlagACK, payload)
	if worker.tcpReassembly.Len() != 1 {
		t.Fatalf("observe-only reassembly did not retain flow: len=%d", worker.tcpReassembly.Len())
	}
	key, _ := dnsClientKey(pkt.src, pkt.srcMac)
	flowKey := classifier.NewFlowKey(key, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), 51000, 443, 6)
	result, ok := worker.tcpReassembly.Lookup(flowKey)
	if !ok || result.Status != classifier.ReassemblyComplete || result.Metadata.SNI != "api.youtube.com" {
		t.Fatalf("observe-only result=%+v ok=%v", result, ok)
	}
	if string(payload) != string(original) {
		t.Fatal("observe-only reassembly mutated original payload")
	}

	worker.observeTCPReassembly(&cfg, pkt, 1000+uint32(len(payload)), 51000, 443, classifier.TCPFlagACK|classifier.TCPFlagFIN, nil)
	if worker.tcpReassembly.Len() != 0 {
		t.Fatal("FIN did not release observe-only state")
	}
}

func TestNFQTCPReassemblySYNSequenceBase(t *testing.T) {
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Flags.TCPReassemblyMode = config.ReassemblyObserve
	worker := NewWorkerWithQueue(&cfg, 0)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 81), dst: net.IPv4(203, 0, 113, 81), srcMac: "aa:bb:cc:dd:ee:81"}
	worker.observeTCPReassembly(&cfg, pkt, 9000, 51001, 443, classifier.TCPFlagSYN, nil)
	client, _ := dnsClientKey(pkt.src, pkt.srcMac)
	key := classifier.NewFlowKey(client, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), 51001, 443, 6)
	result, ok := worker.tcpReassembly.Lookup(key)
	if !ok || result.BaseSequence != 9001 {
		t.Fatalf("SYN base sequence result=%+v ok=%v", result, ok)
	}
}
