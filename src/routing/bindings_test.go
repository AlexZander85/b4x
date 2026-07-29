package routing

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

func bindingAuthorization(client classifier.ClientKey, sport uint16) classifier.ActionAuthorization {
	flow := classifier.NewFlowKey(client, client.SourceIP, netip.MustParseAddr("203.0.113.10"), sport, 443, 6)
	return classifier.ActionAuthorization{ID: string(rune(sport)), FlowKey: flow, Client: client, SetID: "youtube", Domain: "youtube.com", EvidenceSource: classifier.EvidencePacketSNI, Confidence: 100, DomainPolicy: classifier.DomainPolicyStrict, ConfigGen: 9, Final: true, ExpiresAt: time.Unix(1000, 0)}
}

func TestBindingStoreRequiresExactFlowCapability(t *testing.T) {
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.10")}
	now := time.Unix(100, 0)
	store := NewBindingStore(BindingCapabilities{}, 10)
	if _, err := store.Bind(BindingRequest{Authorization: bindingAuthorization(client, 40000), Owner: "b4", RouteID: "proxy"}, now); !errors.Is(err, ErrBindingCapability) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBindingStoreDoesNotCaptureAnotherFlowOrClient(t *testing.T) {
	clientA := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.10")}
	clientB := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.11")}
	now := time.Unix(100, 0)
	store := NewBindingStore(BindingCapabilities{ExactFlow: true}, 10)
	first, err := store.Bind(BindingRequest{Authorization: bindingAuthorization(clientA, 40000), Owner: "b4", RouteID: "proxy", TransactionID: "tx1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Bind(BindingRequest{Authorization: bindingAuthorization(clientB, 40001), Owner: "b4", RouteID: "proxy", TransactionID: "tx2"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.FlowKey == second.FlowKey || first.Client == second.Client {
		t.Fatal("route binding scope collapsed")
	}
	if removed := store.DeleteOwned("b4", "tx1"); removed != 1 {
		t.Fatalf("owned rollback removed %d", removed)
	}
	if _, ok := store.Lookup(second.ID, now); !ok {
		t.Fatal("rollback removed unrelated binding")
	}
}
