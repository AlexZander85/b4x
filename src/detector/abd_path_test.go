package detector

import (
	"github.com/daniellavrushin/b4/monitor"
	"testing"
	"time"
)

func TestProbeContextRejectsExpiredGenerationAndSelfInterference(t *testing.T) {
	now := time.Unix(11000, 0)
	scope := monitor.MonitorScopeKey{ClientScope: monitor.ClientScopeKey{ID: "c", Role: "forwarded"}, TargetRole: "target", NetworkContextID: "wan", ConfigGeneration: 2}
	c := ProbeContext{Scope: scope, Mode: PathNativeDirect, BudgetToken: "b", RequestExpiry: now.Add(time.Minute), MonitorGeneration: 2}
	if ValidateProbeContext(c, now) != nil {
		t.Fatal("valid context rejected")
	}
	c.MonitorGeneration = 1
	if ValidateProbeContext(c, now) == nil {
		t.Fatal("generation mismatch accepted")
	}
	c.MonitorGeneration = 2
	c.SelfInterference = true
	if ValidateProbeContext(c, now) == nil {
		t.Fatal("self-interference accepted")
	}
}

func TestVantageUnavailableIsNoOpinion(t *testing.T) {
	now := time.Unix(11000, 0)
	l := VantageObservation{TargetID: "t", Stage: StageHTTP, ExactEndpoint: true, Available: true, Success: false}
	o := VantageObservation{TargetID: "t", Stage: StageHTTP, ExactEndpoint: true, Available: false}
	r := CompareVantage(l, o, now)
	if r.ObserverOpinion || r.Explanation == "" {
		t.Fatalf("unavailable observer became opinion: %+v", r)
	}
}
