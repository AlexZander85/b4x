package fieldtest

import (
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
