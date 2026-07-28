package nfq

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type canaryTestPorts struct{}

func (canaryTestPorts) IsTCPPort(port int) bool { return port == 443 }
func (canaryTestPorts) IsUDPPort(port int) bool { return port == 443 }

func canaryTCPPacket(src, dst string, sport, dport uint16, flags byte) *pktInfo {
	raw := make([]byte, 40)
	binary.BigEndian.PutUint16(raw[20:22], sport)
	binary.BigEndian.PutUint16(raw[22:24], dport)
	raw[32] = 5 << 4
	raw[33] = flags
	return &pktInfo{raw: raw, proto: 6, src: net.ParseIP(src), dst: net.ParseIP(dst), srcStr: src, dstStr: dst, ihl: 20}
}

func TestCanaryMonitorCountsLogicalFlowOnce(t *testing.T) {
	monitor := NewCanaryMonitor(16, time.Minute)
	syn := canaryTCPPacket("192.0.2.10", "203.0.113.20", 50000, 443, 0x02)
	monitor.Observe(syn, canaryTestPorts{})
	monitor.Observe(syn, canaryTestPorts{})
	monitor.MarkEligible(syn, canaryTestPorts{})
	monitor.MarkEligible(syn, canaryTestPorts{})
	snapshot := monitor.Snapshot(time.Now())
	if snapshot.FlowsStarted != 1 || snapshot.Samples != 0 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestCanaryMonitorTracksIncomingRSTAndProgress(t *testing.T) {
	monitor := NewCanaryMonitor(16, time.Minute)
	syn := canaryTCPPacket("192.0.2.10", "203.0.113.20", 50000, 443, 0x02)
	monitor.Observe(syn, canaryTestPorts{})
	monitor.MarkEligible(syn, canaryTestPorts{})
	monitor.Observe(canaryTCPPacket("203.0.113.20", "192.0.2.10", 443, 50000, 0x12), canaryTestPorts{})
	monitor.Observe(canaryTCPPacket("203.0.113.20", "192.0.2.10", 443, 50000, 0x04), canaryTestPorts{})
	snapshot := monitor.Snapshot(time.Now())
	if snapshot.Samples != 1 || snapshot.IncomingProgress != 1 || snapshot.Failures != 0 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestCanaryMonitorCountsRSTAsCompletedFailure(t *testing.T) {
	monitor := NewCanaryMonitor(16, time.Minute)
	syn := canaryTCPPacket("192.0.2.10", "203.0.113.20", 50000, 443, 0x02)
	monitor.Observe(syn, canaryTestPorts{})
	monitor.MarkEligible(syn, canaryTestPorts{})
	monitor.Observe(canaryTCPPacket("203.0.113.20", "192.0.2.10", 443, 50000, 0x04), canaryTestPorts{})
	snapshot := monitor.Snapshot(time.Now())
	if snapshot.Samples != 1 || snapshot.Failures != 1 || snapshot.IncomingProgress != 0 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestCanaryMonitorExcludesFlowsOutsideCandidateSet(t *testing.T) {
	monitor := NewCanaryMonitor(16, time.Minute)
	syn := canaryTCPPacket("192.0.2.10", "203.0.113.20", 50000, 443, 0x02)
	monitor.Observe(syn, canaryTestPorts{})
	monitor.Observe(canaryTCPPacket("203.0.113.20", "192.0.2.10", 443, 50000, 0x12), canaryTestPorts{})
	snapshot := monitor.Snapshot(time.Now())
	if snapshot.FlowsStarted != 0 || snapshot.Samples != 0 || snapshot.IncomingProgress != 0 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestCanaryMonitorAccountsEarlyProgressWhenFlowBecomesEligible(t *testing.T) {
	monitor := NewCanaryMonitor(16, time.Minute)
	syn := canaryTCPPacket("192.0.2.10", "203.0.113.20", 50000, 443, 0x02)
	monitor.Observe(syn, canaryTestPorts{})
	monitor.Observe(canaryTCPPacket("203.0.113.20", "192.0.2.10", 443, 50000, 0x12), canaryTestPorts{})
	monitor.MarkEligible(syn, canaryTestPorts{})
	snapshot := monitor.Snapshot(time.Now())
	if snapshot.FlowsStarted != 1 || snapshot.Samples != 1 || snapshot.IncomingProgress != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}
