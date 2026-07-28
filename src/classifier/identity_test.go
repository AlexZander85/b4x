package classifier

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

func identityMAC(values ...byte) [6]byte {
	var mac [6]byte
	copy(mac[:], values)
	return mac
}

func identityObservation(ip string, vlan uint16, device string) IdentityObservation {
	return IdentityObservation{
		L3Family:     4,
		SourceIP:     netip.MustParseAddr(ip),
		IfIndex:      2,
		VLAN:         vlan,
		SourceDevice: device,
	}
}

func TestIdentityStoreColdARPIsIPOnly(t *testing.T) {
	clk := clock.NewFixed(time.Unix(100, 0))
	store := NewIdentityStore(4, clk, MACResolverFunc(func(netip.Addr, int, uint16) ([6]byte, bool) {
		return [6]byte{}, false
	}))
	identity := store.Resolve(identityObservation("192.0.2.10", 10, "lan0"))
	if identity.Quality != IdentityIPOnly || identity.Key.SourceMAC != [6]byte{} {
		t.Fatalf("identity = %+v", identity)
	}
	if !strings.Contains(identity.TraceReason(), "client_identity=ip-only source_mac_lookup=miss") {
		t.Fatalf("trace = %q", identity.TraceReason())
	}
}

func TestIdentityStoreLateARPEnrichment(t *testing.T) {
	clk := clock.NewFixed(time.Unix(200, 0))
	resolved := false
	store := NewIdentityStore(4, clk, MACResolverFunc(func(netip.Addr, int, uint16) ([6]byte, bool) {
		if resolved {
			return identityMAC(0, 1, 2, 3, 4, 5), true
		}
		return [6]byte{}, false
	}))
	first := store.Resolve(identityObservation("192.0.2.11", 10, "lan0"))
	resolved = true
	clk.Advance(time.Second)
	second := store.Resolve(identityObservation("192.0.2.11", 10, "lan0"))
	if first.Quality != IdentityIPOnly || second.Quality != IdentityFull || second.SourceMACLookup != MACLookupLate {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	if second.Generation != first.Generation || !strings.Contains(second.Reason, "late ARP") {
		t.Fatalf("late enrichment changed identity generation: first=%+v second=%+v", first, second)
	}
}

func TestIdentityStoreDHCPReuseChangesGeneration(t *testing.T) {
	clk := clock.NewFixed(time.Unix(300, 0))
	store := NewIdentityStore(4, clk, nil)
	obs := identityObservation("192.0.2.12", 10, "lan0")
	obs.SourceMAC = identityMAC(0, 1, 2, 3, 4, 5)
	first := store.Resolve(obs)
	clk.Advance(time.Second)
	obs.SourceMAC = identityMAC(6, 7, 8, 9, 10, 11)
	second := store.Resolve(obs)
	if second.Generation == first.Generation || second.Key.SourceMAC == first.Key.SourceMAC || !strings.Contains(second.Reason, "dhcp/ip reuse") {
		t.Fatalf("reuse was not isolated: first=%+v second=%+v", first, second)
	}
	if !second.FirstSeen.After(first.FirstSeen) {
		t.Fatalf("reuse did not reset first seen: first=%v second=%v", first.FirstSeen, second.FirstSeen)
	}
}

func TestIdentityStoreSeparatesGuestVLANAndSourceDevice(t *testing.T) {
	store := NewIdentityStore(8, clock.NewFixed(time.Unix(400, 0)), nil)
	a := identityObservation("192.0.2.13", 10, "lan0")
	a.SourceMAC = identityMAC(0, 1, 2, 3, 4, 5)
	b := identityObservation("192.0.2.13", 20, "guest0")
	b.SourceMAC = identityMAC(0, 1, 2, 3, 4, 5)
	first := store.Resolve(a)
	second := store.Resolve(b)
	if store.Len() != 2 || first.Key.VLAN == second.Key.VLAN || first.MatchesSourceDevice(second.SourceDevice) {
		t.Fatalf("guest/LAN identities were merged: first=%+v second=%+v", first, second)
	}
}

func TestIdentityStoreBoundedEvictionAndMissingARP(t *testing.T) {
	store := NewIdentityStore(2, clock.NewFixed(time.Unix(500, 0)), nil)
	for i, ip := range []string{"192.0.2.20", "192.0.2.21", "192.0.2.22"} {
		obs := identityObservation(ip, 10, "lan0")
		obs.SourceMAC = identityMAC(byte(i), 1, 2, 3, 4, 5)
		store.Resolve(obs)
	}
	if store.Len() != 2 {
		t.Fatalf("store exceeded bound: %d", store.Len())
	}
	missing := store.Resolve(identityObservation("192.0.2.23", 10, "lan0"))
	if missing.Quality != IdentityIPOnly || missing.SourceMACLookup != MACLookupMiss {
		t.Fatalf("missing ARP identity = %+v", missing)
	}
}

func TestIdentityStoreGCAndDeleteAreIdempotent(t *testing.T) {
	clk := clock.NewFixed(time.Unix(600, 0))
	store := NewIdentityStore(2, clk, nil)
	identity := store.Resolve(identityObservation("192.0.2.30", 10, "lan0"))
	if !store.DeleteClient(identity.Key, identity.SourceDevice) || store.DeleteClient(identity.Key, identity.SourceDevice) {
		t.Fatal("delete was not idempotent")
	}
	store.Resolve(identityObservation("192.0.2.31", 10, "lan0"))
	clk.Advance(time.Hour)
	if removed := store.GC(clk.Now(), time.Minute); removed != 1 || store.GC(clk.Now(), time.Minute) != 0 {
		t.Fatal("GC was not idempotent")
	}
}
