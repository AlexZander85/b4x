package nfq

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

func TestScopedFailureStateDoesNotCrossDomainClientOrGeneration(t *testing.T) {
	state := newScopedFailureState()
	now := time.Unix(100, 0)
	clientA := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.10")}
	clientB := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.11")}
	base := classifier.ScopedFailureKey{Client: clientA, DestinationIP: netip.MustParseAddr("203.0.113.7"), DestinationPort: 443, L4Proto: 6, SetID: "youtube", DomainKey: "youtube.com", ConfigGen: 3}
	if !state.AddBlocked(base, time.Minute, now) || !state.IsBlocked(base, now) {
		t.Fatal("scoped block not stored")
	}
	otherDomain := base
	otherDomain.DomainKey = "mail.google.com"
	otherClient := base
	otherClient.Client = clientB
	otherGeneration := base
	otherGeneration.ConfigGen = 4
	for name, key := range map[string]classifier.ScopedFailureKey{"domain": otherDomain, "client": otherClient, "generation": otherGeneration} {
		if state.IsBlocked(key, now) {
			t.Fatalf("block leaked across %s", name)
		}
	}
}

func TestScopedRSTStateUsesExactFlowKey(t *testing.T) {
	state := newScopedFailureState()
	now := time.Unix(200, 0)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.20")}
	first := classifier.NewFlowKey(client, client.SourceIP, netip.MustParseAddr("203.0.113.9"), 40000, 443, 6)
	second := classifier.NewFlowKey(client, client.SourceIP, netip.MustParseAddr("203.0.113.9"), 40001, 443, 6)
	state.MarkRSTSent(first, now)
	if !state.HasRSTSent(first, now) || state.HasRSTSent(second, now) {
		t.Fatal("RST state was not exact-flow scoped")
	}
}

func TestScopedEscalationDoesNotCrossService(t *testing.T) {
	state := newScopedFailureState()
	now := time.Unix(300, 0)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.30")}
	key := classifier.ScopedEscalationKey{Client: client, DomainKey: "youtube.com", SetID: "youtube", ConfigGen: 8}
	if !state.SetEscalation(key, "youtube-next", time.Minute, now) {
		t.Fatal("escalation rejected")
	}
	mail := key
	mail.DomainKey = "mail.google.com"
	if _, _, ok := state.GetEscalation(mail, now); ok {
		t.Fatal("escalation leaked to another service")
	}
}
