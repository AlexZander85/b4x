package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// QUICCapability reports whether the current build/host has a usable
// QUIC/UDP-443 path for DoH3/DoQ. Injected by the platform layer; the
// default is false, which yields honest UNSUPPORTED states (addendum §§38-39:
// unsupported router build returns UNSUPPORTED, not fake PASS).
var QUICCapability = func() (bool, string) {
	return false, "quic dataplane capability not proven for this build"
}

// DoH3Provider is the native DoH-over-HTTP/3 adapter (§38). Until QUIC
// readiness is current it reports UNSUPPORTED; it never silently falls back
// to HTTP/2 inside the same path identity.
type DoH3Provider struct {
	URL        string
	CatalogVer string
	id         dnspath.DNSPathID
}

func NewDoH3Provider(url, catalogVer string) *DoH3Provider {
	sum := sha256.Sum256([]byte(url))
	return &DoH3Provider{URL: url, CatalogVer: catalogVer, id: dnspath.DNSPathID{
		Family: dnspath.DNSPathDoH3, ResolverID: "r-doh3-" + hex.EncodeToString(sum[:6]),
		EndpointID: "e-doh3-" + hex.EncodeToString(sum[:6]), IPFamily: "ipv4", CatalogVersion: catalogVer,
	}}
}

func (p *DoH3Provider) ID() dnspath.DNSPathID { return p.id }

func (p *DoH3Provider) Capabilities() dnspath.DNSPathCapabilities {
	ok, reason := QUICCapability()
	if !ok {
		return dnspath.DNSPathCapabilities{State: dnspath.CapUnsupported, Reason: reason}
	}
	return dnspath.DNSPathCapabilities{State: dnspath.CapAvailable, IPv4: true}
}

var errQUICUnavailable = errors.New("quic path unavailable")

func (p *DoH3Provider) Prepare(_ context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	if caps := p.Capabilities(); caps.State != dnspath.CapAvailable {
		return dnspath.PreparedDNSPath{}, errQUICUnavailable
	}
	return dnspath.PreparedDNSPath{}, errQUICUnavailable // H3 wire path not enabled in v1.0
}

func (p *DoH3Provider) Probe(_ context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	return dnspath.DNSPathProbeOutcome{
		PathID: p.id, QuerySuiteID: q.SuiteCase,
		Stage: dnspath.StageConnect, Class: dnspath.OutcomeQUICUnavailable,
	}, nil
}

func (p *DoH3Provider) Resolve(_ context.Context, _ dnspath.PreparedDNSPath, _ dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	return dnspath.DNSResponse{}, errQUICUnavailable
}

func (p *DoH3Provider) Health(_ context.Context, _ dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: p.Capabilities().State}
}

func (p *DoH3Provider) Retire(_ context.Context, _ dnspath.PreparedDNSPath) error { return nil }

// DoQProvider is the native DNS-over-QUIC adapter (§39). Never attributed to
// dnscrypt-proxy (ADR-ADNS-003).
type DoQProvider struct {
	ServerName string
	CatalogVer string
	id         dnspath.DNSPathID
}

func NewDoQProvider(serverName, catalogVer string) *DoQProvider {
	sum := sha256.Sum256([]byte(serverName))
	return &DoQProvider{ServerName: serverName, CatalogVer: catalogVer, id: dnspath.DNSPathID{
		Family: dnspath.DNSPathDoQ, ResolverID: "r-doq-" + hex.EncodeToString(sum[:6]),
		EndpointID: "e-doq-" + hex.EncodeToString(sum[:6]), IPFamily: "ipv4", CatalogVersion: catalogVer,
	}}
}

func (p *DoQProvider) ID() dnspath.DNSPathID { return p.id }

func (p *DoQProvider) Capabilities() dnspath.DNSPathCapabilities {
	ok, reason := QUICCapability()
	if !ok {
		return dnspath.DNSPathCapabilities{State: dnspath.CapUnsupported, Reason: reason}
	}
	return dnspath.DNSPathCapabilities{State: dnspath.CapAvailable, IPv4: true}
}

func (p *DoQProvider) Prepare(_ context.Context, _ dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	return dnspath.PreparedDNSPath{}, errQUICUnavailable
}

func (p *DoQProvider) Probe(_ context.Context, _ dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	return dnspath.DNSPathProbeOutcome{
		PathID: p.id, QuerySuiteID: q.SuiteCase,
		Stage: dnspath.StageConnect, Class: dnspath.OutcomeQUICUnavailable,
	}, nil
}

func (p *DoQProvider) Resolve(_ context.Context, _ dnspath.PreparedDNSPath, _ dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	return dnspath.DNSResponse{}, errQUICUnavailable
}

func (p *DoQProvider) Health(_ context.Context, _ dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: p.Capabilities().State}
}

func (p *DoQProvider) Retire(_ context.Context, _ dnspath.PreparedDNSPath) error { return nil }
