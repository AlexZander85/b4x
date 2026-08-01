package fieldtest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/validation"
)

const APIVersion = "/api/v1"

type SessionStatus string

const (
	StatusReady   SessionStatus = "ready"
	StatusRunning SessionStatus = "running"
	StatusStopped SessionStatus = "stopped"
	StatusBlocked SessionStatus = "blocked"
)

type SilentSuite struct {
	Mode                                                                                                                    string
	Scenarios                                                                                                               []string
	RequireUniqueProgress, RequireBidirectionalVisibility, RequireIndependentEvidence, RequireDifferential, RequireControls bool
	AllowWARPCandidate, PromotionAllowed                                                                                    bool
}
type SessionRequest struct {
	ClientID, ClientIP, TargetAppID, TargetVariant, TargetPackage, StartType, QUICMode, IPFamily, ResolverMode, TraceProfile string
	ControlApps                                                                                                              []string
	ConfigGeneration                                                                                                         uint64
	DurationLimitSec                                                                                                         int
	Silent                                                                                                                   SilentSuite
}
type TestSession struct {
	SessionID        string
	Request          SessionRequest
	ConfigGeneration uint64
	Status           SessionStatus
	CreatedAt        time.Time
	EventStream      string
	// GateEvaluation is the latest structured hard-gate result recorded by
	// the Field Test Controller (FB-03); nil until first evaluation.
	GateEvaluation *validation.GateEvaluation
}
type Marker struct {
	Marker, Source    string
	DeviceMonotonicNS uint64
	At                time.Time
}
type Event struct {
	Schema                          uint16            `json:"schema"`
	SessionID                       string            `json:"session_id"`
	EventSeq                        uint64            `json:"event_seq"`
	FlowID                          string            `json:"flow_id,omitempty"`
	FlowEventSeq                    uint64            `json:"flow_event_seq,omitempty"`
	Timestamp                       time.Time         `json:"ts"`
	RelativeUS                      int64             `json:"t_rel_us"`
	Event                           string            `json:"event"`
	ConfigGen                       uint64            `json:"config_gen,omitempty"`
	RouteGen                        uint64            `json:"route_gen,omitempty"`
	SessionGen                      uint64            `json:"session_gen,omitempty"`
	ClientPseudonym                 string            `json:"client_pseudonym,omitempty"`
	Fields                          map[string]string `json:"fields,omitempty"`
}
type EventStream struct {
	mu     sync.RWMutex
	events []Event
	next   uint64
}

func Pseudonym(v string) string {
	h := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(h[:])[:16]
}
func NewSession(id string, req SessionRequest, gen uint64, now time.Time) (TestSession, error) {
	if id == "" || req.ClientID == "" || gen == 0 {
		return TestSession{}, errors.New("session requires client and config generation")
	}
	return TestSession{SessionID: id, Request: req, ConfigGeneration: gen, Status: StatusReady, CreatedAt: now, EventStream: APIVersion + "/test-sessions/" + id + "/events"}, nil
}
func (s *EventStream) Append(e Event) error {
	if e.Schema != 1 || e.SessionID == "" || e.Event == "" || e.Timestamp.IsZero() {
		return errors.New("invalid trace event")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.EventSeq == 0 {
		e.EventSeq = s.next + 1
	}
	if e.EventSeq <= s.next {
		return errors.New("event sequence must increase")
	}
	s.next = e.EventSeq
	s.events = append(s.events, e)
	return nil
}
func (s *EventStream) Snapshot() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]Event(nil), s.events...)
	sort.Slice(out, func(i, j int) bool { return out[i].EventSeq < out[j].EventSeq })
	return out
}
func (s *EventStream) JSONL() ([]byte, error) {
	var out []byte
	for _, e := range s.Snapshot() {
		b, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
		out = append(out, '\n')
	}
	return out, nil
}

type SessionReport struct {
	Session     TestSession
	Events      []Event
	Markers     []Marker
	Status      string
	Redacted    bool
	GeneratedAt time.Time
}

func (r SessionReport) Valid() bool {
	return r.Session.SessionID != "" && r.Redacted && r.GeneratedAt.After(time.Time{})
}
