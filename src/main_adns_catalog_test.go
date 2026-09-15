package main

import (
	"context"
	"testing"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

type catalogIDProvider struct{ id dnspath.DNSPathID }

func (p catalogIDProvider) ID() dnspath.DNSPathID { return p.id }
func (catalogIDProvider) Capabilities() dnspath.DNSPathCapabilities {
	return dnspath.DNSPathCapabilities{State: dnspath.CapAvailable}
}
func (p catalogIDProvider) Prepare(context.Context, dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	return dnspath.PreparedDNSPath{PathID: p.id}, nil
}
func (catalogIDProvider) Probe(context.Context, dnspath.PreparedDNSPath, dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	return dnspath.DNSPathProbeOutcome{}, nil
}
func (catalogIDProvider) Resolve(context.Context, dnspath.PreparedDNSPath, dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	return dnspath.DNSResponse{}, nil
}
func (catalogIDProvider) Health(context.Context, dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: dnspath.CapAvailable}
}
func (catalogIDProvider) Retire(context.Context, dnspath.PreparedDNSPath) error { return nil }

func TestCombinedADNSCatalogVersionChangesWithManagedCatalog(t *testing.T) {
	native := catalogIDProvider{id: dnspath.DNSPathID{Family: dnspath.DNSPathTCP, ResolverID: "r-a", IPFamily: "ipv4", CatalogVersion: adnsReferenceCatalog}}
	managedA := catalogIDProvider{id: dnspath.DNSPathID{Family: dnspath.DNSPathDNSCrypt, ResolverID: "r-b", IPFamily: "ipv4", CatalogVersion: "managed-a"}}
	managedB := catalogIDProvider{id: dnspath.DNSPathID{Family: dnspath.DNSPathDNSCrypt, ResolverID: "r-b", IPFamily: "ipv4", CatalogVersion: "managed-b"}}
	v1 := combinedADNSCatalogVersion([]dnspath.DNSPathProvider{native, managedA})
	v2 := combinedADNSCatalogVersion([]dnspath.DNSPathProvider{native, managedB})
	if v1 == v2 || v1 == adnsReferenceCatalog || v2 == adnsReferenceCatalog {
		t.Fatalf("managed catalog change must alter composite provenance: v1=%q v2=%q", v1, v2)
	}
}
