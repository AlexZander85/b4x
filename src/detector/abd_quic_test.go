package detector

import (
	"testing"
	"time"
)

func TestQUICEvidenceKeepsTCPSeparateAndControls(t *testing.T) {
	now := time.Unix(14000, 0)
	scope := monitorScopeForDetector()
	obs := []QUICObservation{{Scope: scope, TargetID: "t", IPHash: "ip", IPFamily: "v4", Fingerprint: FingerprintBrowser, Stage: QUICQ1Initial, Control: "", Success: false, ObservedAt: now}, {Scope: scope, TargetID: "t", IPHash: "control", IPFamily: "v4", Fingerprint: FingerprintBrowser, Stage: QUICQ0UDPReachability, Control: QUICUDP443Control, Success: true, ObservedAt: now}}
	e, err := BuildQUICEvidence(scope, obs, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if e.ImpliesGlobalUDPBlock() {
		t.Fatal("target failure plus healthy UDP control became global block")
	}
}

func TestQUICRejectsCrossScope(t *testing.T) {
	now := time.Unix(14000, 0)
	o := QUICObservation{Scope: monitorScopeForDetector(), TargetID: "t", IPHash: "ip", IPFamily: "v4", Fingerprint: FingerprintBrowser, Stage: QUICQ1Initial, ObservedAt: now}
	other := o
	other.Scope.NetworkContextID = "other"
	if _, err := BuildQUICEvidence(o.Scope, []QUICObservation{other}, nil, now); err == nil {
		t.Fatal("cross-scope QUIC evidence accepted")
	}
}
