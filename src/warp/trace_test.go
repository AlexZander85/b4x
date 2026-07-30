package warp

import (
	"testing"
	"time"
)

func TestTraceEnvelopeSequenceChecksumAndPriority(t *testing.T) {
	p := NewTracePipeline(1)
	e := TransportTraceEnvelope{SchemaVersion: 2, BootID: "b", ProcessID: "p", SessionID: "s", Sequence: 1, Priority: P0, Event: "start", ObservedAt: time.Unix(30000, 0)}.Seal()
	if !e.Valid(0) || !p.Publish(e) {
		t.Fatal("trace rejected")
	}
	e.Sequence = 1
	if p.Publish(e) {
		t.Fatal("duplicate sequence accepted")
	}
	if ValidateTraceCompatibility(e) != nil {
		t.Fatal("schema rejected")
	}
}
