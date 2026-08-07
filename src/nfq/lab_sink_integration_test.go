package nfq

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/fixtures"
	"github.com/daniellavrushin/b4/lab"
)

// TestLabSinkReachesWorkerAndCapturesOnlyEligibleSegments verifies the
// production wire: a registered lab session attaches a bounded sink to the
// worker, eligible ClientHello segments on TCP/443 are submitted through the
// real submitClientHelloSegment path, and the capture completes with an exact
// profile count. Non-eligible traffic (other client) is rejected downstream
// by the capture filter, not stored.
func TestLabSinkReachesWorkerAndCaptures(t *testing.T) {
	worker := NewWorkerWithQueue(nil, 0)

	retention := lab.NewMemoryRetention(16)
	controller := lab.NewSessionController(func(sink lab.SegmentSink) {
		worker.SetClientHelloSink(sink)
	})
	defer controller.Stop()

	request := lab.DefaultCaptureRequest()
	request.Duration = 300 * time.Millisecond
	request.Filter = lab.ClientFilter{IP: netip.MustParseAddr("192.168.1.50")}
	request.Retention = retention
	if _, err := controller.Start(request); err != nil {
		t.Fatalf("start: %v", err)
	}

	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	eligible := &pktInfo{
		src: net.ParseIP("192.168.1.50"), dst: net.ParseIP("203.0.113.10"),
		srcStr: "192.168.1.50", dstStr: "203.0.113.10", srcMac: "",
	}
	worker.submitClientHelloSegment(eligible, 1000, 51000, 443, classifier.TCPFlagSYN, hello)

	// Ineligible client: the capture filter rejects it downstream, so only
	// the first flow may complete.
	other := &pktInfo{
		src: net.ParseIP("192.168.1.99"), dst: net.ParseIP("203.0.113.11"),
		srcStr: "192.168.1.99", dstStr: "203.0.113.11", srcMac: "",
	}
	worker.submitClientHelloSegment(other, 2000, 51000, 443, classifier.TCPFlagSYN, hello)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if controller.Status().State != lab.SessionRunning {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	status := controller.Status()
	if status.State != lab.SessionCompleted {
		t.Fatalf("session did not complete: %s", status.State)
	}
	if len(status.Result.Profiles) != 1 {
		t.Fatalf("expected exactly 1 eligible profile, got %d: %+v", len(status.Result.Profiles), status.Result.Profiles)
	}
	if status.Result.Profiles[0].DestinationPort != 443 {
		t.Fatalf("unexpected profile port: %d", status.Result.Profiles[0].DestinationPort)
	}
	if profiles := retention.List(); len(profiles) != 1 {
		t.Fatalf("retention must match capture: got %d", len(profiles))
	}
}

// TestLabSinkDetachedWhenNoSession confirms the production path stays
// sink-free (no cost, no capture) unless an explicit session is running.
func TestLabSinkDetachedWhenNoSession(t *testing.T) {
	worker := NewWorkerWithQueue(nil, 0)
	controller := lab.NewSessionController(func(sink lab.SegmentSink) {
		worker.SetClientHelloSink(sink)
	})
	// Never started a session: the worker sink must be nil.
	if worker.getClientHelloSink() != nil {
		t.Fatal("worker must not observe a sink before a session starts")
	}
	request := lab.DefaultCaptureRequest()
	request.Duration = 100 * time.Millisecond
	request.Filter = lab.ClientFilter{IP: netip.MustParseAddr("192.168.1.50")}
	if _, err := controller.Start(request); err != nil {
		t.Fatalf("start: %v", err)
	}
	if worker.getClientHelloSink() == nil {
		t.Fatal("worker must observe a sink while a session is running")
	}
	controller.Stop()
	if worker.getClientHelloSink() != nil {
		t.Fatal("worker must not observe a sink after the session stopped")
	}
}
