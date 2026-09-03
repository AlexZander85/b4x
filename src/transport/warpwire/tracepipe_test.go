// warpwire tests: trace-pipeline adaptation of engine events into the
// contract Runtime (§61 guards live) and the §73 hard-gate feed.
package warpwire

import (
	"strings"
	"testing"
	"time"

	engine "github.com/daniellavrushin/b4/transport/warp"
	warp "github.com/daniellavrushin/b4/warp"
)

func newRuntimeWithSession(t *testing.T, capacity int) (*warp.Runtime, string) {
	t.Helper()
	rt := warp.NewRuntime(warp.Config{TraceCapacity: capacity})
	const sess = "sess-e7"
	if err := rt.Register(sess, warp.EnrollmentPolicy{MaxAttempts: 5}); err != nil {
		t.Fatalf("register: %v", err)
	}
	return rt, sess
}

func TestEventAdapterPublishesSealedMonotonicEnvelopes(t *testing.T) {
	rt, sess := newRuntimeWithSession(t, 256)
	a := NewEventAdapter("boot-1", "proc-1", sess)

	evs := []engine.SupervisorEvent{
		{Name: "warp_session_generation_started", ObservedAt: time.Now()},
		{Name: "warp_masque_connected", Colo: "FRA", DurationMS: 120, ObservedAt: time.Now()},
		{Name: "warp_reconnect_scheduled", BackoffMS: 4000, FailureClass: "tcp-connect-failed", ObservedAt: time.Now()},
	}
	var prev uint64
	for _, ev := range evs {
		e := a.FromSupervisor(ev)
		if !e.Valid(prev) {
			t.Fatalf("envelope invalid after prev=%d: %+v", prev, e)
		}
		prev = e.Sequence
		if !rt.PublishTrace(sess, e) {
			t.Fatalf("publish rejected: %s", ev.Name)
		}
	}

	snap := rt.Trace().Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot = %d events", len(snap))
	}
	if snap[1].Priority != warp.P0 {
		t.Fatalf("masque_connected priority = %v", snap[1].Priority)
	}
	if snap[2].Payload["backoff_ms"] != "4000" || snap[2].Payload["failure_class"] != "tcp-connect-failed" {
		t.Fatalf("payload mapping = %+v", snap[2].Payload)
	}
	if snap[1].Payload["colo"] != "FRA" {
		t.Fatalf("colo not carried: %+v", snap[1].Payload)
	}
}

func TestNonRUAndGuardEventsFlowThroughPipeline(t *testing.T) {
	rt, sess := newRuntimeWithSession(t, 256)
	a := NewEventAdapter("boot-1", "proc-1", sess)

	// Establishment phase (supervisor source).
	sup := []engine.SupervisorEvent{
		{Name: "warp_session_generation_started", Attempt: 1},
		{Name: "warp_masque_connected", Colo: "FRA", DurationMS: 90},
	}
	for _, ev := range sup {
		if !rt.PublishTrace(sess, a.FromSupervisor(ev)) {
			t.Fatalf("rejected %s", ev.Name)
		}
	}

	nonru := []engine.NonRUEvent{
		{Name: "warp_dns_path_proven", Gen: 1},
		{Name: "warp_geo_probe_started", Gen: 1},
		{Name: "warp_geo_provider_result", Provider: "prov-a", Gen: 3, Detail: "country=\"DE\" iphash=abcd1234"},
		{Name: "warp_geo_quorum_evaluated", Verdict: "PASS_NON_RU", Gen: 3},
		{Name: "warp_geo_attestation_issued", Gen: 3},
		{Name: "warp_nonru_gate_opened", Gen: 3},
		{Name: "warp_nonru_route_promoted", Gen: 3},
	}
	for _, ev := range nonru {
		if !rt.PublishTrace(sess, a.FromNonRU(ev)) {
			t.Fatalf("rejected %s", ev.Name)
		}
	}
	guard := []engine.GuardEvent{
		{Name: "warp_camouflage_authorized", Detail: "guard started"},
		{Name: "warp_camouflage_cutoff", Detail: "validated control flow excluded"},
	}
	for _, ev := range guard {
		if !rt.PublishTrace(sess, a.FromGuard(ev)) {
			t.Fatalf("rejected %s", ev.Name)
		}
	}

	// §69-30: the promotion-required set must be complete in the pipeline.
	if missing := rt.VerifyTraceCompleteness(sess, RequiredPromotionEvents); len(missing) != 0 {
		t.Fatalf("missing required promotion events: %v", missing)
	}
}

func TestSupervisorSinkReportsDrops(t *testing.T) {
	rt, sess := newRuntimeWithSession(t, 2) // tiny ring
	a := NewEventAdapter("b", "p", sess)

	drops := 0
	sink := a.SupervisorSink(rt, func() { drops++ })
	for i := 0; i < 5; i++ {
		sink(engine.SupervisorEvent{Name: "warp_session_generation_started", Attempt: uint32(i + 1)})
	}
	if drops == 0 {
		t.Fatal("ring overflow was not reported as drop")
	}
}

func TestFeedNonRUGateStatusHealthyAndViolations(t *testing.T) {
	rt, _ := newRuntimeWithSession(t, 64)
	now := time.Now()

	freshHash := "deadbeefdeadbeef"
	healthy := engine.NonRUStatus{
		Open:    true,
		Verdict: engine.VerdictPassNonRU,
		Attestation: engine.GeoAttestation{
			Class:             "non-ru",
			Country:           "DE",
			Providers:         2,
			Quorum:            2,
			PublicIPHash:      freshHash,
			PathID:            "path-1",
			IssuedAt:          now,
			FreshUntil:        now.Add(time.Minute),
			SessionGeneration: 4,
		},
		Observations: []engine.GeoObservation{
			{Provider: "a", PublicIPHash: freshHash, Country: "DE", PathID: "path-1",
				Class: "non-ru", DNSProof: true, CounterDelta: 7, ExpiresAt: now.Add(time.Minute), SessionGeneration: 4},
			{Provider: "b", PublicIPHash: freshHash, Country: "DE", PathID: "path-1",
				Class: "non-ru", DNSProof: true, CounterDelta: 9, ExpiresAt: now.Add(time.Minute), SessionGeneration: 4},
		},
	}
	if v := FeedNonRUGateStatus(rt, healthy, now); len(v) != 0 {
		t.Fatalf("healthy status produced violations: %v", v)
	}

	// Corrupt truth: route active while the attestation is revoked+stale —
	// exactly what the §73 producers exist to catch.
	broken := healthy
	broken.Attestation.Revoked = true
	broken.Attestation.FreshUntil = now.Add(-time.Hour)
	v := FeedNonRUGateStatus(rt, broken, now)
	if len(v) == 0 {
		t.Fatal("revoked attestation with active route passed the gate")
	}
	joined := ""
	for _, err := range v {
		joined += err.Error() + "; "
	}
	if !strings.Contains(joined, "without fresh attestation") ||
		!strings.Contains(joined, "after attestation expiry") {
		t.Fatalf("violations missing expected classes: %s", joined)
	}

	// Any provider RU observation with an active route is a violation.
	ruObs := healthy
	ruFirst := healthy.Observations[0]
	ruFirst.Class = "ru"
	ruObs.Observations = []engine.GeoObservation{ruFirst, healthy.Observations[1]}
	violations := FeedNonRUGateStatus(rt, ruObs, now)
	found := false
	for _, err := range violations {
		if strings.Contains(err.Error(), "while any provider") {
			found = true
		}
	}
	if !found {
		t.Fatalf("provider-RU violation not surfaced: %v", violations)
	}
}

func TestConvertersPreserveContractSemantics(t *testing.T) {
	now := time.Now()
	att := engine.GeoAttestation{Class: "non-ru", Providers: 2, Quorum: 2, PublicIPHash: "h", PathID: "p", FreshUntil: now.Add(time.Minute)}
	c := convertAttestation(att)
	if c.Class != warp.GeoNonRU || !c.Valid(now) {
		t.Fatalf("converted attestation invalid: %+v", c)
	}
	obs := convertObservations([]engine.GeoObservation{{Provider: "x", Class: "ru", SessionGeneration: 9}})
	if obs[0].Class != warp.GeoRU || obs[0].SessionGeneration != "9" {
		t.Fatalf("observation conversion = %+v", obs[0])
	}
}
