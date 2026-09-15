package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// UDPProvider is the native UDP resolver path (addendum §33): explicit
// resolver endpoint, transaction/source tuple validation, bounded
// retransmission, optional multi-response observation in diagnostic mode.
type UDPProvider struct {
	ResolverIP  netip.Addr
	Port        int
	Mark        int
	Timeout     time.Duration
	Retries     int
	ObserveRace bool // diagnostic multi-response window
	RaceWindow  time.Duration
	CatalogVer  string
	id          dnspath.DNSPathID
}

func NewUDPProvider(resolver netip.Addr, port int, mark int, catalogVer string) *UDPProvider {
	if port == 0 {
		port = 53
	}
	p := &UDPProvider{
		ResolverIP: resolver, Port: port, Mark: mark,
		Timeout: 3 * time.Second, Retries: 1, RaceWindow: 500 * time.Millisecond,
		CatalogVer: catalogVer,
	}
	sum := sha256.Sum256([]byte(resolver.String()))
	ipfam := "ipv4"
	if resolver.Is6() {
		ipfam = "ipv6"
	}
	p.id = dnspath.DNSPathID{
		Family:         dnspath.DNSPathUDP,
		ResolverID:     "r-" + hex.EncodeToString(sum[:6]),
		EndpointID:     "e-" + hex.EncodeToString(sum[:6]),
		IPFamily:       ipfam,
		CatalogVersion: catalogVer,
	}
	return p
}

func (p *UDPProvider) ID() dnspath.DNSPathID { return p.id }

func (p *UDPProvider) Capabilities() dnspath.DNSPathCapabilities {
	if !p.ResolverIP.IsValid() {
		return dnspath.DNSPathCapabilities{State: dnspath.CapUnsupported, Reason: "no resolver endpoint"}
	}
	caps := dnspath.DNSPathCapabilities{
		State: dnspath.CapAvailable, MultiResponse: true,
	}
	if p.ResolverIP.Is4() {
		caps.IPv4 = true
	} else {
		caps.IPv6 = true
	}
	return caps
}

func (p *UDPProvider) Prepare(_ context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	if !p.ResolverIP.IsValid() {
		return dnspath.PreparedDNSPath{}, fmt.Errorf("udp provider: resolver endpoint missing")
	}
	return dnspath.PreparedDNSPath{PathID: p.id, Generation: req.Generation, PreparedAt: time.Now()}, nil
}

func (p *UDPProvider) Retire(_ context.Context, _ dnspath.PreparedDNSPath) error { return nil }

// RawResponse is one UDP datagram with its arrival delta.
type RawResponse struct {
	Payload []byte
	Delta   time.Duration
}

// exchangeRaw sends one query and collects raw datagrams (validated and
// invalid) so the race observer keeps full arrival evidence.
func (p *UDPProvider) exchangeRaw(ctx context.Context, query []byte, observeRace bool) ([]RawResponse, time.Duration, error) {
	d := markedDialer(p.Mark, p.Timeout)
	addr := net.JoinHostPort(p.ResolverIP.String(), fmt.Sprintf("%d", p.Port))
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	start := time.Now()
	if _, err := conn.Write(query); err != nil {
		return nil, 0, err
	}
	window := p.Timeout
	if observeRace {
		window = p.RaceWindow
		if window <= 0 {
			window = 500 * time.Millisecond
		}
	}
	var responses []RawResponse
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(window))
		n, err := conn.Read(buf)
		if err != nil {
			if len(responses) > 0 {
				return responses, time.Since(start), nil
			}
			return nil, time.Since(start), err
		}
		resp := make([]byte, n)
		copy(resp, buf[:n])
		responses = append(responses, RawResponse{Payload: resp, Delta: time.Since(start)})
		if !observeRace {
			return responses, time.Since(start), nil
		}
	}
}

// exchange sends one query and collects structurally validated responses.
// In non-race mode the first validated response is returned; an invalid
// response is an error, never silently accepted.
func (p *UDPProvider) exchange(ctx context.Context, query []byte, observeRace bool) ([][]byte, time.Duration, error) {
	raw, elapsed, err := p.exchangeRaw(ctx, query, observeRace)
	var responses [][]byte
	for _, r := range raw {
		if verr := validateResponse(query, r.Payload); verr != nil {
			if !observeRace {
				return nil, elapsed, verr
			}
			continue
		}
		responses = append(responses, r.Payload)
	}
	if len(responses) == 0 && err == nil {
		err = fmt.Errorf("no valid response")
	}
	return responses, elapsed, err
}

func (p *UDPProvider) Probe(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	out := dnspath.DNSPathProbeOutcome{
		PathID: prepared.PathID, QuerySuiteID: q.SuiteCase, ObservedAt: time.Now(),
	}
	query := b4dns.BuildQuery(q.Name, uint16(time.Now().UnixNano()), q.QType)
	responses, latency, err := p.exchange(ctx, query, q.ObserveRace || p.ObserveRace)
	out.Latency = latency
	if err != nil {
		out.Class = outcomeFromError(err)
		out.Stage = dnspath.StageConnect
		return out, nil
	}
	out.ResponseCount = uint16(len(responses))
	obs, fp, perr := parseStructured(responses[len(responses)-1], p.id.ResolverID, time.Now())
	if perr != nil {
		out.Class = dnspath.OutcomeMalformedDNS
		out.Stage = dnspath.StageDNSMessage
		return out, nil
	}
	out.Stage = dnspath.StageAnswer
	out.RCode = obs.RCode
	out.Truncated = obs.Truncated
	out.AnswerFingerprint = fp.AnswerDigest
	out.CNAMEFingerprint = fp.CNAMEDigest
	out.HTTPSFingerprint = fp.HTTPSDigest
	if obs.Truncated {
		out.Class = dnspath.OutcomeTruncatedRequiresTCP
		return out, nil
	}
	if len(responses) > 1 {
		out.Class = dnspath.OutcomeInconclusive // multi-response: race observer classifies
		return out, nil
	}
	out.Class = dnspath.OutcomePassCorrect
	return out, nil
}

func (p *UDPProvider) Resolve(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	query := b4dns.BuildQuery(q.Name, q.TxID, q.QType)
	responses, latency, err := p.exchange(ctx, query, false)
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	obs, fp, err := parseStructured(responses[0], p.id.ResolverID, time.Now())
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	return dnspath.DNSResponse{
		Payload: responses[0], Fingerprint: fp, RCode: obs.RCode,
		Truncated: obs.Truncated, Latency: latency, ResponseCount: uint16(len(responses)),
	}, nil
}

func (p *UDPProvider) Health(_ context.Context, _ dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: dnspath.CapAvailable}
}
