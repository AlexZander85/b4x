package fieldtest

import (
	"testing"
	"time"
)

func TestCreateIdempotentAndReportRedacted(t *testing.T) {
	c, err := NewController("http://127.0.0.1", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := SessionRequest{ClientID: "android-main"}
	first, replayed, err := c.Create("s-1", req, 7, "idem-1")
	if err != nil || replayed {
		t.Fatalf("create: sess=%+v replayed=%v err=%v", first, replayed, err)
	}
	second, replayed, err := c.Create("s-other", req, 7, "idem-1")
	if err != nil || !replayed || second.SessionID != "s-1" {
		t.Fatalf("idempotency replay failed: %+v %v %v", second, replayed, err)
	}
	if err := c.AddMarker("s-1", Marker{Marker: "ui_visible", Source: "adb-inferred"}); err != nil {
		t.Fatal(err)
	}
	rep, err := c.Report("s-1")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Valid() {
		t.Fatalf("report not valid: %+v", rep)
	}
	if len(rep.Events) == 0 || len(rep.Markers) != 1 {
		t.Fatalf("events=%d markers=%d", len(rep.Events), len(rep.Markers))
	}
	if err := c.Stop("s-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.AddMarker("s-1", Marker{Marker: "late", At: time.Now()}); err == nil {
		t.Fatal("marker after stop must fail")
	}
}
