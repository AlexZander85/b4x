package classifier

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

func TestScopedLearnedObservationIsClientScopedAndExpiryDoesNotSlide(t *testing.T) {
	clk := clock.NewFixed(time.Unix(100, 0))
	store := NewHostHintStore(HostHintStoreConfig{}, clk)
	client := ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.10")}
	obs := ScopedLearnedObservation{Client: client, DestinationIP: netip.MustParseAddr("203.0.113.8"), L4Proto: 6, Domain: "api.youtube.com", SetID: "youtube", Source: EvidencePacketSNI, Confidence: 50, CreatedAt: clk.Now(), ExpiresAt: clk.Now().Add(30 * time.Second), ConfigGen: 7}
	if err := store.Observe(obs.Evidence()); err != nil {
		t.Fatal(err)
	}
	first := store.LookupForGeneration(client, obs.DestinationIP, 6, 7)
	clk.Advance(31 * time.Second)
	second := store.LookupForGeneration(client, obs.DestinationIP, 6, 7)
	if len(first) != 1 || len(second) != 0 {
		t.Fatalf("absolute expiry violated first=%d second=%d", len(first), len(second))
	}
	other := client
	other.SourceIP = netip.MustParseAddr("192.0.2.11")
	if got := store.Lookup(other, obs.DestinationIP, 6); len(got) != 0 {
		t.Fatalf("cross-client reuse: %+v", got)
	}
}
