package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// DoHProvider is the native DNS-over-HTTPS path (addendum §37): wire-format
// application/dns-message, with HTTP status, TLS, DNS message and answer
// correctness separated into explicit stages. Hostname endpoints require
// explicit bootstrap IPs so adaptive recovery never recursively depends on
// the system DNS path it is trying to diagnose/replace.
type DoHProvider struct {
	URL        string // https:// endpoint, canonical identity
	ServerName string // URL hostname retained for TLS SNI/certificate checks
	Bootstrap  []net.IP
	Mark       int
	Timeout    time.Duration
	CatalogVer string
	id         dnspath.DNSPathID
}

func NewDoHProvider(rawURL string, mark int, catalogVer string) *DoHProvider {
	return NewDoHProviderWithBootstrap(rawURL, nil, mark, catalogVer)
}

func NewDoHProviderWithBootstrap(rawURL string, bootstrap []net.IP, mark int, catalogVer string) *DoHProvider {
	p := &DoHProvider{URL: rawURL, Mark: mark, Timeout: 5 * time.Second, CatalogVer: catalogVer}
	if u, err := url.Parse(rawURL); err == nil {
		p.ServerName = u.Hostname()
	}
	p.Bootstrap = append([]net.IP(nil), bootstrap...)
	sum := sha256.Sum256([]byte(rawURL))
	p.id = dnspath.DNSPathID{
		Family:         dnspath.DNSPathDoH,
		ResolverID:     "r-doh-" + hex.EncodeToString(sum[:6]),
		EndpointID:     "e-doh-" + hex.EncodeToString(sum[:6]),
		IPFamily:       dohIPFamily(p.ServerName, p.Bootstrap),
		CatalogVersion: catalogVer,
	}
	return p
}

func dohIPFamily(serverName string, bootstrap []net.IP) string {
	if ip := net.ParseIP(serverName); ip != nil && ip.To4() == nil {
		return "ipv6"
	}
	for _, ip := range bootstrap {
		if ip != nil && ip.To4() == nil {
			return "ipv6"
		}
	}
	return "ipv4"
}

func (p *DoHProvider) ID() dnspath.DNSPathID { return p.id }

func (p *DoHProvider) Capabilities() dnspath.DNSPathCapabilities {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return dnspath.DNSPathCapabilities{State: dnspath.CapUnsupported, Reason: "doh endpoint must be a valid https:// URL"}
	}
	if net.ParseIP(p.ServerName) == nil && len(p.Bootstrap) == 0 {
		return dnspath.DNSPathCapabilities{State: dnspath.CapBlockedByBootstrap, Reason: "hostname DoH requires explicit bootstrap address"}
	}
	caps := dnspath.DNSPathCapabilities{State: dnspath.CapAvailable}
	if p.id.IPFamily == "ipv6" {
		caps.IPv6 = true
	} else {
		caps.IPv4 = true
	}
	return caps
}

func (p *DoHProvider) Prepare(_ context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	caps := p.Capabilities()
	if caps.State != dnspath.CapAvailable {
		return dnspath.PreparedDNSPath{}, fmt.Errorf("doh provider not preparable: %s", caps.Reason)
	}
	return dnspath.PreparedDNSPath{
		PathID: p.id, Generation: req.Generation, PreparedAt: time.Now(),
		Handle: b4dns.MarkedDoHClientWithBootstrap(p.Mark, p.Timeout, p.ServerName, p.Bootstrap),
	}, nil
}

func (p *DoHProvider) Retire(_ context.Context, _ dnspath.PreparedDNSPath) error { return nil }

func (p *DoHProvider) client(prepared dnspath.PreparedDNSPath) *http.Client {
	if c, ok := prepared.Handle.(*http.Client); ok && c != nil {
		return c
	}
	return b4dns.MarkedDoHClientWithBootstrap(p.Mark, p.Timeout, p.ServerName, p.Bootstrap)
}

func (p *DoHProvider) Probe(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	out := dnspath.DNSPathProbeOutcome{PathID: prepared.PathID, QuerySuiteID: q.SuiteCase, ObservedAt: time.Now()}
	query := b4dns.BuildQuery(q.Name, uint16(time.Now().UnixNano()), q.QType)
	start := time.Now()
	body, err := b4dns.ResolveDoH(ctx, p.client(prepared), p.URL, query)
	out.Latency = time.Since(start)
	if err != nil {
		out.Attribution = err.Error()
		// Mid-handshake cut means the TLS stage never completed — stage
		// attribution must reflect that, not the HTTP layer (§62). tlsCutError
		// also catches the io.EOF shape that outcomeFromError misses.
		if tlsCutError(err) {
			out.Class = dnspath.OutcomeTLSMidHandshakeReset
			out.Stage = dnspath.StageTLS
		} else {
			out.Class = outcomeFromError(err)
			out.Stage = dnspath.StageHTTP
			if out.Class == dnspath.OutcomeInconclusive {
				out.Class = dnspath.OutcomeHTTPStatusFailure
			}
		}
		return out, nil
	}
	out.ResponseCount = 1
	if err := validateResponse(query, body); err != nil {
		out.Stage = dnspath.StageDNSMessage
		out.Class = outcomeFromError(err)
		return out, nil
	}
	obs, fp, perr := parseStructured(body, p.id.ResolverID, time.Now())
	if perr != nil {
		out.Stage = dnspath.StageDNSMessage
		out.Class = dnspath.OutcomeMalformedDNS
		return out, nil
	}
	completeProbeEvidence(&out, body, q, obs, fp)
	return out, nil
}

func (p *DoHProvider) Resolve(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	query, err := productionQueryWire(q)
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	start := time.Now()
	body, err := b4dns.ResolveDoH(ctx, p.client(prepared), p.URL, query)
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	if err := validateResponse(query, body); err != nil {
		return dnspath.DNSResponse{}, err
	}
	obs, fp, err := parseStructured(body, p.id.ResolverID, time.Now())
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	if err := validateProductionResponse(body, obs); err != nil {
		return dnspath.DNSResponse{}, err
	}
	return dnspath.DNSResponse{
		Payload: body, Fingerprint: fp, RCode: obs.RCode,
		Latency: time.Since(start), ResponseCount: 1,
	}, nil
}

func (p *DoHProvider) Health(_ context.Context, _ dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: dnspath.CapAvailable}
}
