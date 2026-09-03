package warp

import (
	"testing"
	"time"
)

func TestTraceExportRedactsAndBounds(t *testing.T) {
	e := TransportTraceEnvelope{SchemaVersion: 2, BootID: "b", ProcessID: "p", SessionID: "s", Sequence: 1, Event: "x", ObservedAt: time.Now(), Payload: map[string]string{"secret": "x"}}.Seal()
	x := TraceExport{Events: []TransportTraceEnvelope{e}, Redacted: true, Complete: true, MaxBytes: 1}.Bounded()
	if !x.Valid() || x.Events[0].Payload != nil {
		t.Fatal("trace export unsafe")
	}
}
