package lab

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/fixtures"
)

// sessionTestSink records every attach/detach transition so tests can assert
// the production sink is only present while a session is running.
type sessionTestSink struct {
	attached []SegmentSink
}

func (t *sessionTestSink) record(sink SegmentSink) {
	if sink == nil {
		t.attached = append(t.attached, nil)
		return
	}
	t.attached = append(t.attached, sink)
}

func (t *sessionTestSink) last() SegmentSink {
	if len(t.attached) == 0 {
		return nil
	}
	return t.attached[len(t.attached)-1]
}

func (t *sessionTestSink) count() int { return len(t.attached) }

func sessionTestRequest() CaptureRequest {
	req := DefaultCaptureRequest()
	req.Duration = 200 * time.Millisecond
	req.Filter = ClientFilter{IP: netip.MustParseAddr("192.168.1.50")}
	req.Retention = NewMemoryRetention(16)
	return req
}

func sessionTestSegment(ip string, sequence uint32, flags byte, payload []byte) CaptureSegment {
	addr := netip.MustParseAddr(ip)
	return CaptureSegment{
		At:       time.Now(),
		Client:   classifier.ClientKey{SourceIP: addr},
		SrcIP:    addr,
		DstIP:    netip.MustParseAddr("203.0.113.10"),
		SrcPort:  51000,
		DstPort:  443,
		Sequence: sequence,
		Flags:    flags,
		Payload:  payload,
	}
}

func TestSessionControllerSinkAttachedOnlyWhileRunning(t *testing.T) {
	rec := &sessionTestSink{}
	controller := NewSessionController(rec.record)
	defer controller.Stop()

	id, err := controller.Start(sessionTestRequest())
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if id == "" {
		t.Fatal("session id must not be empty")
	}
	if rec.last() == nil {
		t.Fatal("sink must be attached while the session is running")
	}
	if status := controller.Status(); status.State != SessionRunning {
		t.Fatalf("expected running, got %s", status.State)
	}

	controller.Stop()
	if rec.last() != nil {
		t.Fatal("sink must be detached after stop")
	}
	// After an explicit stop the terminal capture result stays observable
	// (stop cancels cleanly and keeps any profiles captured so far); a brand
	// new controller reports idle.
	if status := controller.Status(); status.State != SessionCompleted && status.State != SessionIdle {
		t.Fatalf("expected completed or idle after stop, got %s", status.State)
	}
}

func TestSessionControllerRejectsConcurrentStart(t *testing.T) {
	rec := &sessionTestSink{}
	controller := NewSessionController(rec.record)
	defer controller.Stop()

	if _, err := controller.Start(sessionTestRequest()); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if _, err := controller.Start(sessionTestRequest()); err != ErrSessionActive {
		t.Fatalf("second start must fail with ErrSessionActive, got %v", err)
	}
	controller.Stop()
	if _, err := controller.Start(sessionTestRequest()); err != nil {
		t.Fatalf("start after stop must succeed, got %v", err)
	}
}

func TestSessionControllerCapturesHelloAndPublishesResult(t *testing.T) {
	rec := &sessionTestSink{}
	controller := NewSessionController(rec.record)
	defer controller.Stop()

	request := sessionTestRequest()
	if _, err := controller.Start(request); err != nil {
		t.Fatalf("start: %v", err)
	}

	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	sink := rec.last()
	if sink == nil {
		t.Fatal("sink not attached")
	}
	if !sink.Submit(sessionTestSegment("192.168.1.50", 1000, classifier.TCPFlagSYN, hello)) {
		t.Fatal("segment was dropped by bounded sink")
	}
	// Non-matching client must be rejected downstream (not saved).
	sink.Submit(sessionTestSegment("192.168.1.99", 2000, classifier.TCPFlagSYN, hello))

	waitForTerminal(t, controller)
	status := controller.Status()
	if status.State != SessionCompleted {
		t.Fatalf("expected completed, got %s (err=%s)", status.State, status.Error)
	}
	if status.Result.CompletedFlows != 1 {
		t.Fatalf("expected 1 completed flow, got %d", status.Result.CompletedFlows)
	}
	if len(status.Result.Profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(status.Result.Profiles))
	}
	if status.Result.Profiles[0].DestinationPort != 443 {
		t.Fatalf("unexpected destination port: %d", status.Result.Profiles[0].DestinationPort)
	}
	// Retention must receive the stored profile too.
	if profiles := request.Retention.(*MemoryRetention).List(); len(profiles) != 1 {
		t.Fatalf("retention must hold the captured profile, got %d", len(profiles))
	}
	// Sink detached after natural completion.
	if rec.last() != nil {
		t.Fatal("sink must be detached after completion")
	}
}

func TestSessionControllerInvalidateGenerationClearsActiveSession(t *testing.T) {
	rec := &sessionTestSink{}
	controller := NewSessionController(rec.record)
	defer controller.Stop()

	request := sessionTestRequest()
	request.ConfigGeneration = 42
	if _, err := controller.Start(request); err != nil {
		t.Fatalf("start: %v", err)
	}
	if rec.last() == nil {
		t.Fatal("sink must be attached while running")
	}
	if !controller.InvalidateGeneration(43) {
		t.Fatal("generation mismatch must invalidate the session")
	}
	if rec.last() != nil {
		t.Fatal("sink must be detached after invalidation")
	}
	if status := controller.Status(); status.State != SessionIdle {
		t.Fatalf("expected idle after invalidation, got %s", status.State)
	}
	// Matching generation must not touch an idle controller.
	if controller.InvalidateGeneration(43) {
		t.Fatal("idle controller must not report invalidation")
	}
}

func TestSessionControllerNoFilterRejectedAtStart(t *testing.T) {
	controller := NewSessionController(nil)
	defer controller.Stop()
	request := DefaultCaptureRequest()
	request.Duration = 200 * time.Millisecond
	if _, err := controller.Start(request); err != ErrCaptureFilter {
		t.Fatalf("start without filter must fail with ErrCaptureFilter, got %v", err)
	}
}

func waitForTerminal(t *testing.T, controller *SessionController) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if status := controller.Status(); status.State != SessionRunning {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("session did not reach terminal state in time")
}

var _ = capture.QueueRoleProduction
