package silentpath

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

func testAuthorization() classifier.ActionAuthorization {
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.10")}
	flow := classifier.NewFlowKey(client, client.SourceIP, netip.MustParseAddr("198.51.100.10"), 50100, 443, 6)
	return classifier.ActionAuthorization{Client: client, FlowKey: flow, SetID: "youtube", Domain: "youtube.com", ConfigGen: 7, Final: true}
}

func TestObserveAssessmentCannotAuthorizeRecovery(t *testing.T) {
	a := ObserveAssessment(FailureBeforeServerHello, Scope{}, ReasonNoUniqueProgress)
	if a.RecoveryAllowed || a.Confidence != ConfidenceSuspicion {
		t.Fatalf("observe assessment unexpectedly active: %+v", a)
	}
}

func TestScopeRequiresExactAuthorizationNotDestination(t *testing.T) {
	auth := testAuthorization()
	scope := Scope{ClientKey: auth.Client, SetID: auth.SetID, ComponentID: "video", DomainKey: auth.Domain, ConfigGen: auth.ConfigGen, IPFamily: 4, TransportPath: "direct"}
	if !scope.ValidForRecovery(auth) {
		t.Fatal("exact authorized scope rejected")
	}
	scope.ComponentID = ""
	if scope.ValidForRecovery(auth) {
		t.Fatal("component-less, destination-like scope was accepted")
	}
}

func TestEvidenceExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	if !(Evidence{ExpiresAt: now}.Expired(now)) {
		t.Fatal("evidence must expire at its deadline")
	}
}
