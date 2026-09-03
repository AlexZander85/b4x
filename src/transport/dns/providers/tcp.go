package providers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// TCPProvider is the native TCP resolver path (addendum §34): RFC-compliant
// length-prefixed messages, used for TC fallback and UDP-drop differential.
type TCPProvider struct {
	ResolverIP netip.Addr
	Port       int
	Mark       int
	Timeout    time.Duration
	CatalogVer string
	id         dnspath.DNSPathID
	// SegmentWrites controls the TCP segmentation experiment (§35): when >1,
	// the query is written in N chunks. Multiple write() calls alone do NOT
	// prove on-wire segment boundaries — the SegmentationProven flag in
	// Capabilities is only set by capture/GSO/MSS parity evidence.
	SegmentWrites      int
	SegmentationProven bool
}

func NewTCPProvider(resolver netip.Addr, port int, mark int, catalogVer string) *TCPProvider {
	if port == 0 {
		port = 53
	}
	p := &TCPProvider{ResolverIP: resolver, Port: port, Mark: mark, Timeout: 5 * time.Second, CatalogVer: catalogVer}
	sum := sha256.Sum256([]byte(resolver.String()))
	ipfam := "ipv4"
	if resolver.Is6() {
		ipfam = "ipv6"
	}
	p.id = dnspath.DNSPathID{
		Family:         dnspath.DNSPathTCP,
		ResolverID:     "r-" + hex.EncodeToString(sum[:6]),
		EndpointID:     "e-" + hex.EncodeToString(sum[:6]),
		IPFamily:       ipfam,
		CatalogVersion: catalogVer,
	}
	return p
}

func (p *TCPProvider) ID() dnspath.DNSPathID {
	id := p.id
	if p.SegmentWrites > 1 {
		id.Family = dnspath.DNSPathTCPSegmented
	}
	return id
}

func (p *TCPProvider) Capabilities() dnspath.DNSPathCapabilities {
	if !p.ResolverIP.IsValid() {
		return dnspath.DNSPathCapabilities{State: dnspath.CapUnsupported, Reason: "no resolver endpoint"}
	}
	caps := dnspath.DNSPathCapabilities{State: dnspath.CapAvailable}
	if p.ResolverIP.Is4() {
		caps.IPv4 = true
	} else {
		caps.IPv6 = true
	}
	if p.SegmentWrites > 1 {
		if p.SegmentationProven {
			caps.Segmentation = true
		} else {
			// Without on-wire proof the experiment is diagnostic-only
			// (§35: BLOCKED_REPRESENTATION_UNKNOWN).
			caps.State = dnspath.CapRepresentationUnknown
			caps.Reason = "tcp segmentation lacks on-wire capture/GSO/MSS parity evidence"
		}
	}
	return caps
}

func (p *TCPProvider) Prepare(_ context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	if !p.ResolverIP.IsValid() {
		return dnspath.PreparedDNSPath{}, fmt.Errorf("tcp provider: resolver endpoint missing")
	}
	return dnspath.PreparedDNSPath{PathID: p.ID(), Generation: req.Generation, PreparedAt: time.Now()}, nil
}

func (p *TCPProvider) Retire(_ context.Context, _ dnspath.PreparedDNSPath) error { return nil }

func (p *TCPProvider) exchange(ctx context.Context, query []byte) ([]byte, time.Duration, error) {
	d := net.Dialer{Timeout: p.Timeout}
	addr := net.JoinHostPort(p.ResolverIP.String(), fmt.Sprintf("%d", p.Port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	start := time.Now()
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	chunks := p.SegmentWrites
	if chunks < 1 {
		chunks = 1
	}
	// split the frame into chunks; chunk boundaries never split the 2-byte
	// length prefix from at least one payload byte
	per := (len(frame) + chunks - 1) / chunks
	for off := 0; off < len(frame); {
		end := off + per
		if end > len(frame) {
			end = len(frame)
		}
		if _, err := conn.Write(frame[off:end]); err != nil {
			return nil, time.Since(start), err
		}
		off = end
	}
	_ = conn.SetReadDeadline(time.Now().Add(p.Timeout))
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, time.Since(start), err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen <= 0 || respLen > 65535 {
		return nil, time.Since(start), fmt.Errorf("invalid tcp dns length %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, time.Since(start), err
	}
	if err := validateResponse(query, resp); err != nil {
		return nil, time.Since(start), err
	}
	return resp, time.Since(start), nil
}

func (p *TCPProvider) Probe(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	out := dnspath.DNSPathProbeOutcome{PathID: prepared.PathID, QuerySuiteID: q.SuiteCase, ObservedAt: time.Now()}
	query := b4dns.BuildQuery(q.Name, uint16(time.Now().UnixNano()), q.QType)
	resp, latency, err := p.exchange(ctx, query)
	out.Latency = latency
	if err != nil {
		out.Class = outcomeFromError(err)
		out.Stage = dnspath.StageConnect
		return out, nil
	}
	out.ResponseCount = 1
	obs, fp, perr := parseStructured(resp, p.id.ResolverID, time.Now())
	if perr != nil {
		out.Class = dnspath.OutcomeMalformedDNS
		out.Stage = dnspath.StageDNSMessage
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

func (p *TCPProvider) Resolve(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	query := b4dns.BuildQuery(q.Name, q.TxID, q.QType)
	resp, latency, err := p.exchange(ctx, query)
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	obs, fp, err := parseStructured(resp, p.id.ResolverID, time.Now())
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	return dnspath.DNSResponse{
		Payload: resp, Fingerprint: fp, RCode: obs.RCode, Latency: latency, ResponseCount: 1,
	}, nil
}

func (p *TCPProvider) Health(_ context.Context, _ dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: dnspath.CapAvailable}
}
