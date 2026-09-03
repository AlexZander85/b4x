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
	now := time.Unix(1100, 0)
	l := VantageObservation{TargetID: "t", Stage: StageHTTP, ExactEndpoint: true, Available: true, Success: false}
	o := VantageObservation{TargetID: "t", Stage: StageHTTP, ExactEndpoint: true, Available: false}
	r := CompareVantage(l, o, now)
	if r.ObserverOpinion || r.Opinion != VantageNoOpinion || r.Explanation == "" {
		t.Fatalf("unavailable observer became opinion: %+v", r)
	}
}

// TestVantageTCPTLSOnlyObserverCannotSupportHTTPHypothesis is the FB-30
// detection branch for the stage-aware capability gate: an observer that
// declares only tcp/tls stages must never be used to confirm an HTTP/body
// hypothesis. The comparison returns NO_OPINION, never a health verdict.
func TestVantageTCPTLSOnlyObserverCannotSupportHTTPHypothesis(t *testing.T) {
	now := time.Unix(1100, 0)
	capTCPTLS := ObserverCapability{ObserverID: "obs-1", Stages: []string{"tcp", "tls"}, Healthy: true, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	if !capTCPTLS.SupportsStage(StageTCP) || !capTCPTLS.SupportsStage(StageTLS) {
		t.Fatal("tcp/tls capability should cover tcp/tls stages")
	}
	if capTCPTLS.SupportsStage(StageHTTP) || capTCPTLS.SupportsStage(StageBody) {
		t.Fatal("tcp/tls-only capability must not cover http/body stages")
	}
	l := VantageObservation{TargetID: "svc", Stage: StageHTTP, ExactEndpoint: true, Available: true, Success: false}
	o := VantageObservation{ObserverID: "obs-1", TargetID: "svc", Stage: StageHTTP, ExactEndpoint: true, Available: true, Success: false, Capability: capTCPTLS}
	r := CompareVantage(l, o, now)
	if r.ObserverOpinion || r.Opinion != VantageNoOpinion {
		t.Fatalf("tcp/tls-only observer confirmed http: %+v", r)
	}
	lb := VantageObservation{TargetID: "svc", Stage: StageBody, ExactEndpoint: true, Available: true, Success: false}
	rb := CompareVantage(lb, o, now)
	if rb.ObserverOpinion || rb.Opinion != VantageNoOpinion {
		t.Fatalf("tcp/tls-only observer confirmed body: %+v", rb)
	}
}

// TestVantageCapabilityUnprovenIsNoOpinion covers the stale branch of the
// capability gate: an expired observer capability must not yield an opinion.
func TestVantageCapabilityUnprovenIsNoOpinion(t *testing.T) {
	now := time.Unix(1200, 0)
	stale := ObserverCapability{ObserverID: "cap-2", Stages: []string{"http"}, Healthy: true, ObservedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)} // expired => not fresh
	l := VantageObservation{TargetID: "a", Stage: StageHTTP, ExactEndpoint: false, Available: true, Success: true}
	o := VantageObservation{ObserverID: "stale-obs", TargetID: "a", Stage: StageHTTP, ExactEndpoint: false, Available: true, Success: true, Capability: stale}
	r := CompareVantage(l, o, now.Add(time.Hour))
	if r.ObserverOpinion || r.Opinion != VantageNoOpinion {
		t.Fatalf("unproven capability became opinion: %+v", r)
	}
}

// TestVantageExactModeIdentityConflationNoOpinion covers the identity/mode
// gate: exact-endpoint evidence must never be conflated with
// independent-resolution evidence, even for the same target.
func TestVantageExactModeIdentityConflationNoOpinion(t *testing.T) {
	now := time.Unix(1300, 0)
	l := VantageObservation{TargetID: "svc", Stage: StageTCP, ExactEndpoint: true, Available: true, Success: true}
	o := VantageObservation{ObserverID: "obs-mode", TargetID: "svc", Stage: StageTCP, ExactEndpoint: false, Available: true, Success: true}
	r := CompareVantage(l, o, now)
	if r.ObserverOpinion || r.Opinion != VantageNoOpinion {
		t.Fatalf("exact/independent mode conflation became opinion: %+v", r)
	}
	ot := VantageObservation{ObserverID: "obs-target", TargetID: "other", Stage: StageTCP, ExactEndpoint: true, Available: true, Success: true}
	rt := CompareVantage(l, ot, now)
	if rt.ObserverOpinion || rt.Opinion != VantageNoOpinion {
		t.Fatalf("target mismatch became opinion: %+v", rt)
	}
}

// TestVantageStageMismatchNoOpinion covers the stage-alignment gate: an
// observer reporting on a different stage must yield NO_OPINION rather than
// corroborating or contradicting the local verdict.
func TestVantageStageMismatchNoOpinion(t *testing.T) {
	now := time.Unix(1400, 0)
	l := VantageObservation{TargetID: "svc", Stage: StageHTTP, ExactEndpoint: true, Available: true, Success: false}
	o := VantageObservation{ObserverID: "obs-stage", TargetID: "svc", Stage: StageTLS, ExactEndpoint: true, Available: true, Success: false, Capability: ObserverCapability{Stages: []string{"tls"}, Healthy: true, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}}
	r := CompareVantage(l, o, now)
	if r.ObserverOpinion || r.Opinion != VantageNoOpinion {
		t.Fatalf("stage mismatch became opinion: %+v", r)
	}
}
