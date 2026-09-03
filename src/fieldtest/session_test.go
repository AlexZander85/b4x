package fieldtest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEventStreamRejectsDuplicateAndRedactsIdentity(t *testing.T) {
	s, _ := NewSession("s-1", SessionRequest{ClientID: "android-main"}, 1, time.Now())
	if s.EventStream == "" {
		t.Fatal("missing stream")
	}
	var es EventStream
	if err := es.Append(Event{Schema: 1, SessionID: s.SessionID, Timestamp: time.Now(), Event: "session_start", ClientPseudonym: Pseudonym("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	if err := es.Append(Event{Schema: 1, SessionID: s.SessionID, EventSeq: 1, Timestamp: time.Now(), Event: "duplicate"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if len(Pseudonym("192.0.2.1")) != 23 {
		t.Fatal("unexpected pseudonym")
	}
}

// TestTraceEventSerializationPreservesGenerationFields pins FB-13: the trace
// event schema must carry distinct json tags for config/route/session
// generations (FT v1.5: trace carries ConfigGen/RouteGen/SessionGen). A
// regression that collapses the tags to config_gen would drop RouteGen and
// SessionGen on serialization and fail here.
func TestTraceEventSerializationPreservesGenerationFields(t *testing.T) {
	e := Event{
		Schema:     1,
		SessionID:  "s-fb13",
		EventSeq:   1,
		Timestamp:  time.Unix(1700000000, 0).UTC(),
		Event:      "flow_start",
		ConfigGen:  41,
		RouteGen:   7,
		SessionGen: 3,
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	line := string(raw)
	for _, want := range []string{`"config_gen":41`, `"route_gen":7`, `"session_gen":3`} {
		if !strings.Contains(line, want) {
			t.Fatalf("serialized trace event %s missing %s", line, want)
		}
	}
	var decoded Event
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ConfigGen != 41 || decoded.RouteGen != 7 || decoded.SessionGen != 3 {
		t.Fatalf("round-trip lost generations: %+v", decoded)
	}
}
