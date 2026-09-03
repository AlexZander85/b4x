package detector

import (
	"github.com/daniellavrushin/b4/monitor"
	"testing"
	"time"
)

func TestHTTPEvidenceSeparatesHeadersAndBodyProgress(t *testing.T) {
	now := time.Unix(13000, 0)
	e := TLSHTTPEvidence{Scope: monitorScopeForDetector(), TargetID: "t", Fingerprint: FingerprintBrowser, Method: MethodGET, VerifiedCertificate: true, TLSVersion: "1.3", FailureCode: FailureBodyStall, Attribution: monitor.AttributionTransport, Authority: monitor.AuthorityAuthoritativeABD, Stage: "body", Milestone: MilestoneBodyProgress, Body: BodyProgressEvidence{UniqueBytes: 2048, Chunks: 2, LastProgressAt: now, StallDuration: time.Second, SuitableObject: true, MediaProgress: true}, ObservedAt: now}
	if !e.Valid() || !e.SupportsThrottling() {
		t.Fatalf("valid body evidence rejected: %+v", e)
	}
	if e.SupportsBodyBlock() {
		t.Fatal("non-media milestone became body block")
	}
	e.Milestone = MilestoneMediaProgress
	if !e.SupportsBodyBlock() {
		t.Fatal("media body stall not recognized")
	}
}

func TestMITMRequiresVerifiedAuthoritativePath(t *testing.T) {
	e := TLSHTTPEvidence{Scope: monitorScopeForDetector(), TargetID: "t", Fingerprint: FingerprintCanonical, Method: MethodGET, TLSVersion: "1.3", FailureCode: FailureTLSAlert, Authority: monitor.AuthorityPassiveObservation}
	if e.SupportsMITM() {
		t.Fatal("passive/unverified evidence claimed MITM")
	}
	e.VerifiedCertificate = true
	e.Authority = monitor.AuthorityAuthoritativeABD
	if !e.SupportsMITM() {
		t.Fatal("verified authoritative TLS alert not accepted")
	}
}

func monitorScopeForDetector() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{ClientScope: monitor.ClientScopeKey{ID: "c", Role: "forwarded"}, TargetRole: "target", NetworkContextID: "wan", ConfigGeneration: 1}
}
