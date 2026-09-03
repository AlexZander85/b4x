package silentpath

import (
	"testing"
	"time"
)

func TestFreshAndCompatibleSuccessSuppress(t *testing.T) {
	now := time.Unix(1, 0)
	if r, ok := HasActiveSuppressor([]Suppression{FreshSuccessSuppressor(now, time.Second)}, now); !ok || r != ReasonFreshScopeSuccess {
		t.Fatal(r)
	}
	if _, ok := HasActiveSuppressor([]Suppression{CompatibleSuccessSuppressor(now, time.Second)}, now.Add(time.Second)); ok {
		t.Fatal("stale success suppressed")
	}
}
func TestExplicitErrorAlwaysSuppresses(t *testing.T) {
	if r, ok := HasActiveSuppressor([]Suppression{{Reason: ReasonExplicitServerResponse}}, time.Now()); !ok || r != ReasonExplicitServerResponse {
		t.Fatal(r)
	}
}
