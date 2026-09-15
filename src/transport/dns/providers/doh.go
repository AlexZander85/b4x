package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// DoHProvider is the native DNS-over-HTTPS path (addendum §37): wire-format
// application/dns-message, with HTTP status, TLS, DNS message and answer
// correctness separated into explicit stages.
type DoHProvider struct {
	URL        string // https:// endpoint, canonical identity
	Mark       int
	Timeout    time.Duration
	CatalogVer string
	id         dnspath.DNSPathID
}

func NewDoHProvider(url string, mark int, catalogVer string) *DoHProvider {
	p := &DoHProvider{URL: url, Mark: mark, Timeout: 5 * time.Second, CatalogVer: catalogVer}
	sum := sha256.Sum256([]byte(url))
	p.id = dnspath.DNSPathID{
		Family:         dnspath.DNSPathDoH,
		ResolverID:     "r-doh-" + hex.EncodeToString(sum[:6]),
		EndpointID:     "e-doh-" + hex.EncodeToString(sum[:6]),
		IPFamily:       "ipv4",
		CatalogVersion: catalogVer,
	}
	return p
}

func (p *DoHProvider) ID() dnspath.DNSPathID { return p.id }

func (p *DoHProvider) Capabilities() dnspath.DNSPathCapabilities {
	if len(p.URL) < 8 || p.URL[:8] != "https://" {
		return dnspath.DNSPathCapabilities{State: dnspath.CapUnsupported, Reason: "doh endpoint must be https://"}
	}
	return dnspath.DNSPathCapabilities{State: dnspath.CapAvailable, IPv4: true}
}

func (p *DoHProvider) Prepare(_ context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	caps := p.Capabilities()
	if caps.State != dnspath.CapAvailable {
		return dnspath.PreparedDNSPath{}, fmt.Errorf("doh provider not preparable: %s", caps.Reason)
	}
	return dnspath.PreparedDNSPath{
		PathID: p.id, Generation: req.Generation, PreparedAt: time.Now(),
		Handle: b4dns.MarkedDoHClient(p.Mark, p.Timeout),
	}, nil
}

func (p *DoHProvider) Retire(_ context.Context, _ dnspath.PreparedDNSPath) error { return nil }

func (p *DoHProvider) client(prepared dnspath.PreparedDNSPath) *http.Client {
	if c, ok := prepared.Handle.(*http.Client); ok && c != nil {
		return c
	}
	return b4dns.MarkedDoHClient(p.Mark, p.Timeout)
}

func (p *DoHProvider) Probe(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	out := dnspath.DNSPathProbeOutcome{PathID: prepared.PathID, QuerySuiteID: q.SuiteCase, ObservedAt: time.Now()}
	query := b4dns.BuildQuery(q.Name, uint16(time.Now().UnixNano()), q.QType)
	start := time.Now()
	body, err := b4dns.ResolveDoH(ctx, p.client(prepared), p.URL, query)
	out.Latency = time.Since(start)
	if err != nil {
		out.Class = outcomeFromError(err)
		// Mid-handshake cut means the TLS stage never completed — stage
		// attribution must reflect that, not the HTTP layer (§62).
		if out.Class == dnspath.OutcomeTLSMidHandshakeReset {
			out.Stage = dnspath.StageTLS
		} else {
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
	out.Stage = dnspath.StageAnswer
	out.RCode = obs.RCode
	out.AnswerFingerprint = fp.AnswerDigest
	out.CNAMEFingerprint = fp.CNAMEDigest
	out.HTTPSFingerprint = fp.HTTPSDigest
	out.Class = dnspath.OutcomePassCorrect
	return out, nil
}

func (p *DoHProvider) Resolve(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	query := b4dns.BuildQuery(q.Name, q.TxID, q.QType)
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
	return dnspath.DNSResponse{
		Payload: body, Fingerprint: fp, RCode: obs.RCode,
		Latency: time.Since(start), ResponseCount: 1,
	}, nil
}

func (p *DoHProvider) Health(_ context.Context, _ dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: dnspath.CapAvailable}
}
