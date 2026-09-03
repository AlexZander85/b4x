package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/managed"
)

// ManagedProvider is the B4X-side adapter for one managed dnscrypt-proxy
// instance (addendum §40, ADNS-8). It owns the supervisor handle and speaks
// plain DNS to the instance's loopback listener; causal identity (one
// resolver, optional one relay, one family) comes from the InstanceSpec.
type ManagedProvider struct {
	Spec          managed.InstanceSpec
	NewSupervisor func(spec managed.InstanceSpec, listenAddr string) *managed.Supervisor
	CatalogVer    string
	id            dnspath.DNSPathID
}

func NewManagedProvider(spec managed.InstanceSpec, catalogVer string, factory func(managed.InstanceSpec, string) *managed.Supervisor) *ManagedProvider {
	familyMap := map[string]dnspath.DNSPathFamily{
		"dnscrypt":            dnspath.DNSPathDNSCrypt,
		"pqdnscrypt":          dnspath.DNSPathPQDNSCrypt,
		"anonymized-dnscrypt": dnspath.DNSPathAnonymizedDNSCrypt,
		"odoh":                dnspath.DNSPathODoH,
		"doh":                 dnspath.DNSPathDoH,
		"doh3":                dnspath.DNSPathDoH3,
	}
	fam, ok := familyMap[spec.Family]
	if !ok {
		fam = dnspath.DNSPathDNSCrypt
	}
	sum := sha256.Sum256([]byte(spec.ServerName))
	p := &ManagedProvider{Spec: spec, CatalogVer: catalogVer, NewSupervisor: factory}
	p.id = dnspath.DNSPathID{
		Family:         fam,
		ResolverID:     "r-mg-" + hex.EncodeToString(sum[:6]),
		EndpointID:     "e-mg-" + hex.EncodeToString(sum[:6]),
		IPFamily:       "ipv4",
		CatalogVersion: catalogVer,
	}
	if spec.RelayName != "" {
		rsum := sha256.Sum256([]byte(spec.RelayName))
		p.id.RelayID = "rl-" + hex.EncodeToString(rsum[:6])
	}
	return p
}

func (p *ManagedProvider) ID() dnspath.DNSPathID { return p.id }

func (p *ManagedProvider) Capabilities() dnspath.DNSPathCapabilities {
	if err := managed.ValidateSpec(p.Spec); err != nil {
		return dnspath.DNSPathCapabilities{State: dnspath.CapBlockedByPolicy, Reason: err.Error()}
	}
	caps := dnspath.DNSPathCapabilities{State: dnspath.CapAvailable, IPv4: p.Spec.IPv4, IPv6: p.Spec.IPv6, ProviderVersion: "dnscrypt-proxy@" + managed.PinnedCommit[:7]}
	return caps
}

type managedHandle struct {
	supervisor *managed.Supervisor
	inner      *UDPProvider
}

// Prepare starts (or adopts) the managed instance and waits for functional
// readiness; readiness is a real query through the listener, never PID/sleep.
func (p *ManagedProvider) Prepare(ctx context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	if p.NewSupervisor == nil {
		return dnspath.PreparedDNSPath{}, fmt.Errorf("managed provider: supervisor factory missing")
	}
	spec := p.Spec
	if req.Diagnostic {
		spec.Diagnostic = true
		spec.Cache = false
	}
	sup := p.NewSupervisor(spec, spec.ListenAddr)
	if err := sup.Start(ctx); err != nil {
		return dnspath.PreparedDNSPath{}, err
	}
	loopback, err := netip.ParseAddr("127.0.0.1")
	if err != nil {
		return dnspath.PreparedDNSPath{}, err
	}
	_, port, err := splitHostPort(spec.ListenAddr)
	if err != nil {
		_ = sup.Retire(ctx)
		return dnspath.PreparedDNSPath{}, err
	}
	inner := NewUDPProvider(loopback, port, 0, p.CatalogVer)
	return dnspath.PreparedDNSPath{
		PathID: p.id, Generation: req.Generation, PreparedAt: time.Now(),
		Handle: &managedHandle{supervisor: sup, inner: inner},
	}, nil
}

func splitHostPort(addr string) (string, int, error) {
	var host string
	var port int
	_, err := fmt.Sscanf(addr, "%[^:]:%d", &host, &port)
	return host, port, err
}

func (p *ManagedProvider) handle(prepared dnspath.PreparedDNSPath) (*managedHandle, error) {
	h, ok := prepared.Handle.(*managedHandle)
	if !ok || h == nil || h.inner == nil {
		return nil, fmt.Errorf("managed provider: prepared handle missing")
	}
	return h, nil
}

func (p *ManagedProvider) Probe(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	h, err := p.handle(prepared)
	if err != nil {
		return dnspath.DNSPathProbeOutcome{PathID: prepared.PathID, Class: dnspath.OutcomeObserverUnavailable}, nil
	}
	out, err := h.inner.Probe(ctx, prepared, q)
	out.PathID = prepared.PathID
	return out, err
}

func (p *ManagedProvider) Resolve(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	h, err := p.handle(prepared)
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	return h.inner.Resolve(ctx, prepared, q)
}

func (p *ManagedProvider) Health(_ context.Context, prepared dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	h, err := p.handle(prepared)
	if err != nil {
		return dnspath.DNSPathHealth{State: dnspath.CapFailed}
	}
	switch h.supervisor.State() {
	case managed.StateReady:
		return dnspath.DNSPathHealth{State: dnspath.CapReady}
	case managed.StateStarting:
		return dnspath.DNSPathHealth{State: dnspath.CapUnknown}
	case managed.StateDegraded:
		return dnspath.DNSPathHealth{State: dnspath.CapDegraded}
	default:
		return dnspath.DNSPathHealth{State: dnspath.CapFailed}
	}
}

// Retire stops the backend and removes owned temp state (§52).
func (p *ManagedProvider) Retire(ctx context.Context, prepared dnspath.PreparedDNSPath) error {
	h, err := p.handle(prepared)
	if err != nil {
		return nil
	}
	return h.supervisor.Retire(ctx)
}
