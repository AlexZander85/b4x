// MASQUE CONNECT-IP session over HTTP/2 (addendum v1.2 ADR-WARP-4 base
// transport; design §2). Wire format verified against the pinned usque
// reference: plain HTTP CONNECT (x/net/http2 isNormalConnect path) to
// https://cloudflareaccess.com with headers cf-connect-proto:cf-connect-ip /
// pq-enabled:false / empty User-Agent; IP packets travel as RFC 9297 capsule
// DATAGRAM frames (type varint(0)) in both directions on the CONNECT stream;
// foreign capsule types are skipped inbound.
//
// Trust rule (design §0.1/§12 refinement): a 200 response alone does NOT
// establish trust — ValidateDataPlane must observe two full packet round
// trips before callers emit masque_connected / stop camouflage
// (Aether "edge accepts control but drops traffic" class).
package transportwarp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/netip"

	"golang.org/x/net/http2"
)

const (
	// DefaultSNI is the canonical MASQUE SNI (usque internal/consts.go).
	DefaultSNI = "consumer-masque.cloudflareclient.com"
	// DefaultConnectURI is the CONNECT URI template (usque ConnectURI).
	DefaultConnectURI = "https://cloudflareaccess.com"
	// DefaultMTU is the tunnel inner MTU (addendum §16; usque TUN default).
	DefaultMTU = 1280
	// DefaultValidateWindow bounds the post-handshake data-plane check.
	DefaultValidateWindow = 10 * time.Second
	// DefaultProbeInterval is the probe cadence (Aether quic.rs 700ms).
	DefaultProbeInterval = 700 * time.Millisecond
	// requiredProbeSuccesses mirrors DATA_PROBE_REQUIRED_SUCCESSES=2.
	requiredProbeSuccesses = 2
	// maxCapsuleLen rejects absurd allocations on malformed input.
	maxCapsuleLen = 64 << 10
	// tlsHandshakeTimeout bounds the pinned handshake phase.
	tlsHandshakeTimeout = 5 * time.Second
)

// Session lifecycle errors mapped to §62.1 failure classes by Classify.
var (
	ErrValidationTimeout = errors.New("transportwarp: data-plane validation timeout (control ok, traffic dropped)")
	ErrPacketTooBig      = errors.New("transportwarp: packet exceeds tunnel MTU")
	ErrSessionClosed     = errors.New("transportwarp: session closed")
	ErrMalformedCapsule  = errors.New("transportwarp: malformed capsule framing")
)

// Failure classes (addendum §62.1 minimum set, structural not textual).
const (
	FailureDialPolicy    = "dial-policy-apply-failed"
	FailureTCPConnect    = "tcp-connect-failed"
	FailureTLSAlert      = "tls-alert"
	FailureTLSPin        = "tls-pin-mismatch"
	FailureTLSTimeout    = "tls-timeout"
	FailureH2Negotiation = "h2-negotiation-failed"
	FailureConnectReject = "connect-ip-rejected"
	FailureConnectTimeo  = "connect-ip-timeout"
	FailureValidation    = "data-plane-validation-timeout"
)

// SessionConfig is one connection attempt's parameters.
type SessionConfig struct {
	Endpoint        netip.AddrPort // numeric endpoint (must be catalog-listed)
	SNI             string         // cover SNI or DefaultSNI
	ConnectURI      string         // authority template, DefaultConnectURI
	ClientKey       *ecdsa.PrivateKey
	Pin             *ecdsa.PublicKey
	ExtraPins       map[string]bool
	Policy          DialPolicy
	LocalV4         [4]byte       // assigned WARP address (probe source)
	MTU             int           // DefaultMTU when zero
	ValidateWindow  time.Duration // DefaultValidateWindow when zero
	ProbeInterval   time.Duration // DefaultProbeInterval when zero
	HandshakeBudget time.Duration // overall TCP+TLS+headers budget, default 20s
}

func (c *SessionConfig) fillDefaults() {
	if c.SNI == "" {
		c.SNI = DefaultSNI
	}
	if c.ConnectURI == "" {
		c.ConnectURI = DefaultConnectURI
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.ValidateWindow == 0 {
		c.ValidateWindow = DefaultValidateWindow
	}
	if c.ProbeInterval == 0 {
		c.ProbeInterval = DefaultProbeInterval
	}
	if c.HandshakeBudget == 0 {
		c.HandshakeBudget = 20 * time.Second
	}
}

// ConnectResult is the structured outcome of one attempt (MasquePhaseTrace
// subset, §62.1): layer-specific failure class instead of a bare error.
type ConnectResult struct {
	Status       int           // HTTP status of the CONNECT-IP response; 0 before headers
	DurationMS   uint64
	FailureClass string        // "" on success
	PinDigest    string        // SHA-256 of the trusted endpoint key
	ProtocolErr  string        // remote protocol error text when available
}

// Session is one established CONNECT-IP stream carrying IP packets both ways.
type Session struct {
	cfg SessionConfig

	pw      *io.PipeWriter
	resp    io.ReadCloser
	tr      *http2.Transport
	packets chan packetMsg

	writeMu sync.Mutex
	closeOnce sync.Once
	done    chan struct{}
	cancel  context.CancelFunc
}

type packetMsg struct {
	data []byte
	err  error
}

// DialSession establishes the tunnel and returns it together with the
// structured attempt result. On any failure the returned error wraps a known
// failure class; resources are fully released.
func DialSession(parent context.Context, cfg SessionConfig) (*Session, ConnectResult, error) {
	start := time.Now()
	cfg.fillDefaults()

	res := ConnectResult{PinDigest: PinDigest(cfg.Pin)}
	fail := func(class string, err error) (*Session, ConnectResult, error) {
		res.FailureClass = class
		res.DurationMS = msSince(start)
		return nil, res, fmt.Errorf("%s: %w", class, err)
	}

	clientCert, err := ClientCertificate(cfg.ClientKey)
	if err != nil {
		return fail(FailureTLSAlert, err)
	}
	tlsCfg, err := PrepareTLSConfig(clientCert, cfg.SNI, cfg.Pin, cfg.ExtraPins)
	if err != nil {
		return fail(FailureTLSAlert, err)
	}

	ctx, cancel := context.WithCancel(parent)
	tr := &http2.Transport{
		DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			rawConn, err := cfg.Policy.Dialer().DialContext(ctx, "tcp", cfg.Endpoint.String())
			if err != nil {
				return nil, err
			}
			hsCtx, hsCancel := context.WithTimeout(ctx, tlsHandshakeTimeout)
			defer hsCancel()
			tc := tls.Client(rawConn, tlsCfg)
			if err := tc.HandshakeContext(hsCtx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			if proto := tc.ConnectionState().NegotiatedProtocol; proto != "h2" {
				_ = rawConn.Close()
				return nil, fmt.Errorf("%w: negotiated %q", ErrMalformedCapsule, proto)
			}
			return tc, nil
		},
	}

	pr, pw := io.Pipe()
	u, err := url.Parse(cfg.ConnectURI)
	if err != nil {
		cancel()
		return fail(FailureH2Negotiation, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, u.String(), pr)
	if err != nil {
		cancel()
		return fail(FailureH2Negotiation, err)
	}
	req.Host = authorityWithDefaultPort(u, "443")
	req.ContentLength = -1
	req.Header = make(http.Header)
	req.Header.Set("cf-connect-proto", "cf-connect-ip")
	req.Header.Set("pq-enabled", "false")
	req.Header.Set("User-Agent", "")

	sess := &Session{
		cfg:     cfg,
		pw:      pw,
		tr:      tr,
		packets: make(chan packetMsg, 16),
		done:    make(chan struct{}),
		cancel:  cancel,
	}

	handshakeCtx, hsAbort := context.WithTimeout(ctx, cfg.HandshakeBudget)
	defer hsAbort()
	type dialOut struct {
		rsp *http.Response
		err error
	}
	dialed := make(chan dialOut, 1)
	go func() {
		rsp, err := (&http.Client{Transport: tr}).Do(req)
		dialed <- dialOut{rsp, err}
	}()

	var rsp *http.Response
	select {
	case out := <-dialed:
		rsp, err = out.rsp, out.err
	case <-handshakeCtx.Done():
		err = handshakeCtx.Err()
	case <-parent.Done():
		err = parent.Err()
	}
	if err != nil {
		sess.closeQuietly()
		switch {
		case errors.Is(err, ErrPinMismatch):
			return fail(FailureTLSPin, err)
		case errors.Is(err, context.DeadlineExceeded):
			return fail(FailureConnectTimeo, err)
		default:
			return fail(classifyDialError(err), err)
		}
	}
	res.Status = rsp.StatusCode
	if rsp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(rsp.Body, 4096)) //nolint:errcheck
		rsp.Body.Close()
		sess.closeQuietly()
		return fail(FailureConnectReject, fmt.Errorf("connect-ip responded %d", rsp.StatusCode))
	}

	sess.resp = rsp.Body
	res.DurationMS = msSince(start)
	go sess.readerLoop()
	return sess, res, nil
}

// WritePacket sends one outbound IP packet as a DATAGRAM capsule. Frames are
// written atomically under a mutex so concurrent pumps cannot interleave a
// capsule header with its payload.
func (s *Session) WritePacket(pkt []byte) error {
	select {
	case <-s.done:
		return ErrSessionClosed
	default:
	}
	if len(pkt) == 0 || len(pkt) > s.cfg.MTU {
		return fmt.Errorf("%w: %d bytes (mtu %d)", ErrPacketTooBig, len(pkt), s.cfg.MTU)
	}
	frame := make([]byte, 0, 2*binary.MaxVarintLen64+len(pkt))
	frame = AppendVarint(frame, 0)
	frame = AppendVarint(frame, uint64(len(pkt)))
	frame = append(frame, pkt...)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.pw.Write(frame); err != nil {
		return err
	}
	return nil
}

// ReadPacket returns the next inbound IP packet, transparently skipping
// non-DATAGRAM capsule types. It blocks until data, error, or ctx cancel.
func (s *Session) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case m := <-s.packets:
		return m.data, m.err
	default:
	}
	select {
	case m := <-s.packets:
		return m.data, m.err
	case <-s.done:
		// readerLoop drains remaining buffered frames into the channel and
		// closes it; give it a short window before reporting closure.
		select {
		case m := <-s.packets:
			return m.data, m.err
		case <-time.After(250 * time.Millisecond):
			return nil, ErrSessionClosed
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TryRead returns the next packet without blocking (drains the pump queue).
func (s *Session) TryRead() ([]byte, bool, error) {
	select {
	case m := <-s.packets:
		return m.data, true, m.err
	default:
		return nil, false, nil
	}
}

// ValidateDataPlane proves the inner path carries packets: a synthetic DNS
// probe is sent every ProbeInterval; two observed inbound packets within
// ValidateWindow pass (any inbound datagram counts — Aether semantics). On
// timeout the session is torn down: a control-only tunnel must never be
// reported healthy.
func (s *Session) ValidateDataPlane(ctx context.Context) error {
	probe, err := NewDNSProbe(s.cfg.LocalV4, [4]byte{8, 8, 8, 8}, "cloudflare.com")
	if err != nil {
		return fmt.Errorf("probe build: %w", err)
	}
	if err := s.WritePacket(probe.Packet); err != nil {
		return fmt.Errorf("%s: %w", FailureTCPConnect, err)
	}
	timer := time.NewTimer(s.cfg.ValidateWindow)
	defer timer.Stop()
	ticker := time.NewTicker(s.cfg.ProbeInterval)
	defer ticker.Stop()
	successes := 0
	for successes < requiredProbeSuccesses {
		select {
		case m := <-s.packets:
			if m.err != nil {
				return fmt.Errorf("data plane lost during validation: %w", m.err)
			}
			successes++
		case <-ticker.C:
			if err := s.WritePacket(probe.Packet); err != nil {
				return fmt.Errorf("data plane lost during validation: %w", err)
			}
		case <-timer.C:
			s.Close()
			return fmt.Errorf("%s: %w", FailureValidation, ErrValidationTimeout)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Close releases the stream and the underlying transport exactly once.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.pw.Close()
		if s.resp != nil {
			_ = s.resp.Close()
		}
		if s.tr != nil {
			s.tr.CloseIdleConnections()
		}
	})
	return nil
}

// Done exposes session termination for supervisors.
func (s *Session) Done() <-chan struct{} { return s.done }

func (s *Session) readerLoop() {
	br := bufio.NewReaderSize(s.resp, 16<<10)
	defer close(s.packets)
	terminal := func(err error) {
		s.Close() // unblock emit via done-case even when the queue is full
		s.emit(packetMsg{err: normalizeReadErr(err)})
	}
	for {
		typ, err := readVarintStream(br)
		if err != nil {
			terminal(err)
			return
		}
		length, err := readVarintStream(br)
		if err != nil {
			terminal(err)
			return
		}
		if length > maxCapsuleLen {
			terminal(fmt.Errorf("%w: length %d", ErrMalformedCapsule, length))
			return
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(br, payload); err != nil {
			terminal(err)
			return
		}
		if typ != 0 {
			continue // foreign control capsule: skip inbound (usque semantics)
		}
		s.emit(packetMsg{data: payload})
	}
}

func (s *Session) emit(m packetMsg) {
	select {
	case s.packets <- m:
	case <-s.done:
	}
}

func (s *Session) closeQuietly() {
	s.cancel()
	s.Close()
}

func readVarintStream(r *bufio.Reader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	size := 1 << (first >> 6)
	v := uint64(first & 0x3f)
	for i := 1; i < size; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v = v<<8 | uint64(b)
	}
	return v, nil
}

func classifyDialError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "dial policy"), strings.Contains(msg, "SO_MARK"), strings.Contains(msg, "bind device"):
		return FailureDialPolicy
	case strings.Contains(msg, "handshake timeout"):
		return FailureTLSTimeout
	default:
		return FailureTCPConnect
	}
}

func normalizeReadErr(err error) error {
	if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") {
		return ErrSessionClosed
	}
	return err
}

func msSince(t time.Time) uint64 { return uint64(time.Since(t).Milliseconds()) }

func authorityWithDefaultPort(u *url.URL, def string) string {
	host := u.Hostname()
	port := u.Port()
	if host == "" {
		return u.Host
	}
	if port == "" {
		port = def
	}
	return net.JoinHostPort(host, port)
}

// EndpointHash is the redacted-safe trace identifier of an endpoint.
func EndpointHash(ep netip.AddrPort) string {
	sum := sha256.Sum256([]byte(ep.String()))
	return hex.EncodeToString(sum[:8])
}
