package providers

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// DoTProvider is the native DNS-over-TLS path (addendum §36). TLS
// certificate and hostname validation are mandatory; no-SNI with disabled
// verification is prohibited.
type DoTProvider struct {
	ServerName string   // TLS hostname, mandatory
	Bootstrap  []net.IP // explicit bootstrap addresses (no system resolver)
	Port       int
	Mark       int
	Timeout    time.Duration
	RootCAs    *x509.CertPool
	CatalogVer string
	id         dnspath.DNSPathID
}

func NewDoTProvider(serverName string, bootstrap []net.IP, port int, mark int, catalogVer string) *DoTProvider {
	if port == 0 {
		port = 853
	}
	p := &DoTProvider{ServerName: serverName, Bootstrap: bootstrap, Port: port, Mark: mark, Timeout: 5 * time.Second, CatalogVer: catalogVer}
	sum := sha256.Sum256([]byte(serverName))
	p.id = dnspath.DNSPathID{
		Family:         dnspath.DNSPathDoT,
		ResolverID:     "r-dot-" + hex.EncodeToString(sum[:6]),
		EndpointID:     "e-dot-" + hex.EncodeToString(sum[:6]),
		IPFamily:       "ipv4",
		CatalogVersion: catalogVer,
	}
	return p
}

func (p *DoTProvider) ID() dnspath.DNSPathID { return p.id }

func (p *DoTProvider) Capabilities() dnspath.DNSPathCapabilities {
	if p.ServerName == "" {
		return dnspath.DNSPathCapabilities{State: dnspath.CapUnsupported, Reason: "dot requires TLS server name"}
	}
	if len(p.Bootstrap) == 0 {
		return dnspath.DNSPathCapabilities{State: dnspath.CapBlockedByBootstrap, Reason: "dot requires explicit bootstrap address"}
	}
	return dnspath.DNSPathCapabilities{State: dnspath.CapAvailable, IPv4: true}
}

func (p *DoTProvider) Prepare(_ context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	caps := p.Capabilities()
	if caps.State != dnspath.CapAvailable {
		return dnspath.PreparedDNSPath{}, fmt.Errorf("dot provider not preparable: %s", caps.Reason)
	}
	return dnspath.PreparedDNSPath{PathID: p.id, Generation: req.Generation, PreparedAt: time.Now()}, nil
}

func (p *DoTProvider) Retire(_ context.Context, _ dnspath.PreparedDNSPath) error { return nil }

var errDoTCert = errors.New("dot certificate validation failed")

func (p *DoTProvider) exchange(ctx context.Context, query []byte) ([]byte, time.Duration, dnspath.TransportStage, error) {
	d := markedDialer(p.Mark, p.Timeout)
	start := time.Now()
	var lastErr error
	for _, ip := range p.Bootstrap {
		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", p.Port))
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = err
			continue
		}
		tlsCfg := &tls.Config{
			ServerName: p.ServerName,
			MinVersion: tls.VersionTLS12,
			RootCAs:    p.RootCAs,
		}
		conn := tls.Client(raw, tlsCfg)
		_ = conn.SetDeadline(time.Now().Add(p.Timeout))
		if err := conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			var certErr x509.CertificateInvalidError
			var hostErr x509.HostnameError
			var unknownAuth x509.UnknownAuthorityError
			if errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &unknownAuth) {
				return nil, time.Since(start), dnspath.StageTLS, errDoTCert
			}
			return nil, time.Since(start), dnspath.StageTLS, err
		}
		defer conn.Close()
		frame := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
		copy(frame[2:], query)
		if _, err := conn.Write(frame); err != nil {
			return nil, time.Since(start), dnspath.StageConnect, err
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, time.Since(start), dnspath.StageDNSMessage, err
		}
		resp := make([]byte, int(binary.BigEndian.Uint16(lenBuf[:])))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, time.Since(start), dnspath.StageDNSMessage, err
		}
		if err := validateResponse(query, resp); err != nil {
			return nil, time.Since(start), dnspath.StageDNSMessage, err
		}
		return resp, time.Since(start), dnspath.StageAnswer, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no bootstrap address")
	}
	return nil, time.Since(start), dnspath.StageConnect, lastErr
}

func (p *DoTProvider) Probe(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	out := dnspath.DNSPathProbeOutcome{PathID: prepared.PathID, QuerySuiteID: q.SuiteCase, ObservedAt: time.Now()}
	query := b4dns.BuildQuery(q.Name, uint16(time.Now().UnixNano()), q.QType)
	resp, latency, stage, err := p.exchange(ctx, query)
	out.Latency = latency
	out.Stage = stage
	if err != nil {
		if errors.Is(err, errDoTCert) {
			out.Class = dnspath.OutcomeTLSCertFailure
		} else {
			out.Class = outcomeFromError(err)
		}
		return out, nil
	}
	out.ResponseCount = 1
	obs, fp, perr := parseStructured(resp, p.id.ResolverID, time.Now())
	if perr != nil {
		out.Class = dnspath.OutcomeMalformedDNS
		out.Stage = dnspath.StageDNSMessage
		return out, nil
	}
	out.RCode = obs.RCode
	out.AnswerFingerprint = fp.AnswerDigest
	out.CNAMEFingerprint = fp.CNAMEDigest
	out.HTTPSFingerprint = fp.HTTPSDigest
	out.Class = dnspath.OutcomePassCorrect
	return out, nil
}

func (p *DoTProvider) Resolve(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	query := b4dns.BuildQuery(q.Name, q.TxID, q.QType)
	resp, latency, _, err := p.exchange(ctx, query)
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	obs, fp, err := parseStructured(resp, p.id.ResolverID, time.Now())
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	return dnspath.DNSResponse{Payload: resp, Fingerprint: fp, RCode: obs.RCode, Latency: latency, ResponseCount: 1}, nil
}

func (p *DoTProvider) Health(_ context.Context, _ dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: dnspath.CapAvailable}
}
