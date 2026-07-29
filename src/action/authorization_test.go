package action

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

func TestPlanRequiresExactAuthorization(t *testing.T) {
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.10")}
	flow := classifier.NewFlowKey(client, client.SourceIP, netip.MustParseAddr("203.0.113.20"), 52000, 443, 6)
	input := PlanInput{BaseSequence: 1, Payload: []byte("payload"), MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1, RequireAuthorization: true, FlowKey: flow, Client: client, SetID: "youtube", ConfigGen: 7, DestinationPort: 443, L4Proto: 6}
	if _, err := Plan(input); !errors.Is(err, ErrAuthorizationRequired) {
		t.Fatalf("missing auth err=%v", err)
	}
	input.Authorization = &classifier.ActionAuthorization{ID: "a", FlowKey: flow, Client: client, SetID: "youtube", Domain: "youtube.com", EvidenceSource: classifier.EvidencePacketSNI, Confidence: 98, DomainPolicy: classifier.DomainPolicyStrict, ConfigGen: 7, Final: true, ExpiresAt: time.Now().Add(time.Minute)}
	if plan, err := Plan(input); err != nil || !plan.Valid {
		t.Fatalf("authorized plan=%+v err=%v", plan, err)
	}
}
