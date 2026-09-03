package lab

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrSessionActive is returned by Start when a capture session is already
// running. One lab session at a time keeps the production sink lifecycle
// deterministic and prevents mixing capture artifacts across sessions.
var ErrSessionActive = errors.New("clienthello capture session is already active")

// SessionState describes the lifecycle of one lab capture session.
type SessionState string

const (
	SessionIdle      SessionState = "idle"
	SessionRunning   SessionState = "running"
	SessionCompleted SessionState = "completed"
	SessionFailed    SessionState = "failed"
)

// SessionStatus is the observable snapshot of a lab capture session.
type SessionStatus struct {
	State            SessionState  `json:"state"`
	SessionID        string        `json:"session_id"`
	ConfigGeneration uint64        `json:"config_generation"`
	StartedAt        time.Time     `json:"started_at"`
	CompletedAt      time.Time     `json:"completed_at"`
	Duration         time.Duration `json:"duration"`
	Result           CaptureResult `json:"result"`
	Error            string        `json:"error,omitempty"`
}

// sessionResult is the terminal outcome of an active session goroutine.
type sessionResult struct {
	status SessionStatus
	err    error
}

// SessionController owns at most one active lab capture session and bridges
// the production NFQUEUE path to CaptureClientHellos through a bounded,
// non-blocking ChannelSink. The sink is attached only while a session is
// running (attach(nil) on every terminal transition), so production never
// observes a live sink outside an explicit lab session.
//
// A new session is generation-scoped: the ConfigGeneration captured at Start
// is compared on InvalidateGeneration so reload/restart of the classifier
// config clears the sink, buffers and any partially captured profiles instead
// of mixing artifacts across generations.
type SessionController struct {
	mu          sync.Mutex
	attach      func(SegmentSink)
	session     *activeSession
	lastOutcome *sessionResult
}

type activeSession struct {
	id        string
	cancel    context.CancelFunc
	done      chan struct{}
	ch        chan CaptureSegment
	outcome   chan sessionResult
	request   CaptureRequest
	startedAt time.Time
}

// NewSessionController returns a controller that attaches/detaches the
// production capture sink through attach. A nil attach is allowed (tests,
// headless builds) and simply records the sink lifecycle internally.
func NewSessionController(attach func(SegmentSink)) *SessionController {
	return &SessionController{attach: attach}
}

// Start begins a capture session. Only one session may run at a time; a
// second concurrent Start returns ErrSessionActive. The request is normalized
// with the same bounds as CaptureClientHellos (duration <= 5m, bounded
// per-flow/total budgets).
func (s *SessionController) Start(request CaptureRequest) (string, error) {
	if s == nil {
		return "", errors.New("session controller is nil")
	}
	request, err := request.normalized()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithCancel(context.Background())

	// Bounded channel: a full channel drops only diagnostic capture, never
	// blocks the production packet path (ChannelSink.Submit is non-blocking).
	capacity := request.MaxSegmentsPerFlow * request.MaxFlows
	if capacity < 64 {
		capacity = 64
	}
	if capacity > 1024 {
		capacity = 1024
	}
	ch := make(chan CaptureSegment, capacity)

	s.mu.Lock()
	if s.session != nil {
		s.mu.Unlock()
		cancel()
		return "", ErrSessionActive
	}
	id := fmt.Sprintf("lab-%d", time.Now().UnixNano())
	session := &activeSession{
		id:        id,
		cancel:    cancel,
		done:      make(chan struct{}),
		ch:        ch,
		outcome:   make(chan sessionResult, 1),
		request:   request,
		startedAt: time.Now(),
	}
	s.session = session
	s.mu.Unlock()

	// Attach the bounded bridge to the production NFQUEUE path first, so no
	// eligible segment is lost between the attach and the capture loop start.
	s.setSink(ChannelSink{Segments: ch, MaxPayload: request.MaxBytesPerFlow})

	go s.run(ctx, session, ch)

	return id, nil
}

func (s *SessionController) run(ctx context.Context, session *activeSession, ch chan CaptureSegment) {
	defer close(session.done)
	defer s.setSink(nil)

	request := session.request
	result, err := CaptureClientHellos(ctx, request, ChannelSource{Segments: ch})
	status := SessionStatus{
		State:            SessionCompleted,
		SessionID:        session.id,
		ConfigGeneration: request.ConfigGeneration,
		StartedAt:        result.StartedAt,
		CompletedAt:      result.CompletedAt,
		Duration:         request.Duration,
		Result:           result,
	}
	if err != nil {
		status.State = SessionFailed
		status.Error = err.Error()
	}
	session.outcome <- sessionResult{status: status, err: err}

	s.mu.Lock()
	s.lastOutcome = &sessionResult{status: status, err: err}
	if s.session == session {
		s.session = nil
	}
	s.mu.Unlock()
}

// Stop cancels the active session (if any) and waits for its terminal
// cleanup, including the sink detach. Idempotent.
func (s *SessionController) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	session := s.session
	s.mu.Unlock()
	if session == nil {
		return
	}
	session.cancel()
	select {
	case <-session.done:
	case <-time.After(6 * time.Second):
	}
}

// Status reports the current session snapshot. A completed session keeps its
// terminal result until a new Start or InvalidateGeneration.
func (s *SessionController) Status() SessionStatus {
	if s == nil {
		return SessionStatus{State: SessionIdle}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastOutcome != nil {
		return s.lastOutcome.status
	}
	if s.session == nil {
		return SessionStatus{State: SessionIdle}
	}
	return SessionStatus{
		State:            SessionRunning,
		SessionID:        s.session.id,
		ConfigGeneration: s.session.request.ConfigGeneration,
		StartedAt:        s.session.startedAt,
		Duration:         s.session.request.Duration,
	}
}

// InvalidateGeneration stops and clears the active session when its captured
// generation does not match the given generation. Used by config reload and
// runtime transactions so capture artifacts never mix across generations.
// Returns true when a session was actually invalidated.
func (s *SessionController) InvalidateGeneration(generation uint64) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	session := s.session
	s.mu.Unlock()
	if session == nil || session.request.ConfigGeneration == generation {
		return false
	}
	s.Stop()
	s.mu.Lock()
	s.session = nil
	s.lastOutcome = nil
	s.mu.Unlock()
	return true
}

func (s *SessionController) setSink(sink SegmentSink) {
	if s == nil || s.attach == nil {
		return
	}
	s.attach(sink)
}
