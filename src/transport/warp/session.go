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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/netip"

	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"
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
	// writeBlockWarnMS: a request-body write slower than this is traced even
	// when the frame trace is off (H2 backpressure evidence, bd b4x-46z).
	writeBlockWarnMS = 50
)

var (
	// tlsHandshakeTimeout bounds the pinned handshake phase. A var (not
	// const) so M-02 tests can shrink it to a deterministic short window.
	tlsHandshakeTimeout = 5 * time.Second
)

// Session lifecycle errors mapped to §62.1 failure classes by Classify.
var (
	ErrValidationTimeout   = errors.New("transportwarp: data-plane validation timeout (control ok, traffic dropped)")
	ErrTLSHandshakeTimeout = errors.New("transportwarp: TLS handshake timed out")
	ErrPacketTooBig        = errors.New("transportwarp: packet exceeds tunnel MTU")
	ErrSessionClosed       = errors.New("transportwarp: session closed")
	ErrMalformedCapsule    = errors.New("transportwarp: malformed capsule framing")
	ErrH2ALPN              = errors.New("transportwarp: ALPN negotiation failed")
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
	// FailureInternalPanic classifies an engine-goroutine panic that a recover
	// frame contained (M3-07). It is an anomaly signal, not a transport fault:
	// the tunnel remains process-alive and the supervisor backs off, but a run
	// of three consecutive panics pauses the operator.
	FailureInternalPanic = "internal-panic"
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
	// DialFunc overrides the raw-TCP carrier of the control socket (Backend
	// B userspace proxy adapter: the inner session dials THROUGH the base).
	// When nil the constrained DialPolicy dialer is used. The pinned TLS
	// handshake and capsule framing are unchanged.
	DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
	// Fingerprint (b4x fork extension, masquerade FX-M1): when non-empty,
	// the MASQUE H3 client emits a uTLS browser ClientHello instead of the
	// crypto/tls one. Supported values: "chrome120" (closest to the WARP
	// client's boringssl profile), "firefox". Empty = vanilla (default).
	Fingerprint string
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
	Status       int // HTTP status of the CONNECT-IP response; 0 before headers
	DurationMS   uint64
	FailureClass string // "" on success
	PinDigest    string // SHA-256 of the trusted endpoint key
	ProtocolErr  string // remote protocol error text when available
	Colo         string // cf-warp-colo edge telemetry (warp-socks mod.rs pattern)
}

// Session is one established CONNECT-IP stream carrying IP packets both ways.
type Session struct {
	cfg SessionConfig

	pw      *io.PipeWriter
	resp    io.ReadCloser
	tr      *http2.Transport
	packets chan packetMsg

	writeMu   sync.Mutex
	closeOnce sync.Once
	done      chan struct{}
	cancel    context.CancelFunc

	// framePool reuses outbound frame buffers (M-09: KPI-3 zero-copy uplink,
	// sized MTU+headroom). Pool is never nil for a live session.
	framePool *sync.Pool

	// Packet accounting (addendum §43 counter-delta proof: a geo probe is
	// only valid when the inner counters moved) plus packet taps for
	// secondary in-tunnel consumers (geo gate). Counters are atomic; the
	// tap registry is mutex-guarded.
	txPkts, txBytes atomic.Uint64
	rxPkts, rxBytes atomic.Uint64
	droppedPrimary  atomic.Uint64
	subMu           sync.Mutex
	subs            map[chan []byte]struct{}
	droppedTaps     uint64
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
			// Raw-TCP carrier: the Backend-B proxy dial func when wired
			// (the control stream then flows THROUGH the base tunnel),
			// otherwise the constrained DialPolicy socket (§17/§18).
			rawConn, err := func() (net.Conn, error) {
				if cfg.DialFunc != nil {
					return cfg.DialFunc(ctx, "tcp", cfg.Endpoint.String())
				}
				return cfg.Policy.Dialer().DialContext(ctx, "tcp", cfg.Endpoint.String())
			}()
			if err != nil {
				return nil, err
			}
			hsCtx, hsCancel := context.WithTimeout(ctx, tlsHandshakeTimeout)
			defer hsCancel()
			tc := tls.Client(rawConn, tlsCfg)
			if err := tc.HandshakeContext(hsCtx); err != nil {
				_ = rawConn.Close()
				// M-02: a handshake deadline is a TLS-layer timeout, not a TCP
				// connect timeout. crypto/tls surfaces context.DeadlineExceeded; the
				// sentinel names the layer before the generic DeadlineExceeded catch.
				if errors.Is(err, context.DeadlineExceeded) {
					return nil, fmt.Errorf("%w: %v", ErrTLSHandshakeTimeout, err)
				}
				// M-03: no overlapping ALPN (client offers only h2) surfaces as
				// "no application protocol" from crypto/tls; this is an H2-negotiation
				// failure, not a generic connect failure.
				if strings.Contains(err.Error(), "no application protocol") {
					return nil, fmt.Errorf("%w: %v", ErrH2ALPN, err)
				}
				return nil, err
			}
			// ALPN: "h2" is the expected negotiation; "" is ACCEPTED by
			// field evidence (2026-08-25): production MASQUE edges
			// (162.159.198.1/.2/.10) complete TLS WITHOUT echoing an ALPN
			// value — the pin already binds the peer identity, and the h2
			// preface itself is enforced by http2.Transport on this
			// connection. Any OTHER protocol (e.g. http/1.1) stays fatal.
			if proto := tc.ConnectionState().NegotiatedProtocol; proto != "h2" && proto != "" {
				_ = rawConn.Close()
				// M-03: ALPN mismatch is an H2-negotiation failure, not a malformed
				// capsule (which defaulted to FailureTCPConnect). Sentinel so the
				// classifier names the real layer.
				return nil, fmt.Errorf("%w: negotiated %q", ErrH2ALPN, proto)
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
		cfg:       cfg,
		pw:        pw,
		tr:        tr,
		packets:   make(chan packetMsg, 16),
		done:      make(chan struct{}),
		cancel:    cancel,
		framePool: newFramePool(cfg.MTU),
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
		// M-01: an abort (handshake-budget or parent) racing a successful Do
		// leaves rsp sitting in the buffered dialed channel unread, so the
		// round-trip's response body is never closed and the h2 connection can
		// be held in the x/net/http2 idle pool (no idle-scavenger). Reap the
		// response as soon as the background Do lands (it finishes because the
		// request context is the *parent*, which is still alive on a budget
		// abort), then give the transport a second CloseIdleConnections so the
		// conn leaves the pool.
		reapDone := make(chan struct{})
		go func() {
			defer func() { _ = recover() }() // M3-07: gate the goroutine frame
			defer close(reapDone)
			out, ok := <-dialed
			if ok && out.rsp != nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(out.rsp.Body, 4096))
				_ = out.rsp.Body.Close()
			}
		}()
		sess.closeQuietly()
		go func() {
			defer func() { _ = recover() }() // M3-07
			<-reapDone                       // conn is idle again once the body is closed
			sess.tr.CloseIdleConnections()
		}()
		switch {
		case errors.Is(err, ErrPinMismatch):
			return fail(FailureTLSPin, err)
		case errors.Is(err, ErrTLSHandshakeTimeout):
			return fail(FailureTLSTimeout, err)
		case errors.Is(err, context.DeadlineExceeded):
			return fail(FailureConnectTimeo, err)
		default:
			return fail(classifyDialError(err), err)
		}
	}
	res.Status = rsp.StatusCode
	// Free edge telemetry (warp-socks): the CONNECT response carries the
	// terminating colo code; redacted-safe for traces.
	res.Colo = rsp.Header.Get("cf-warp-colo")
	if rsp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(rsp.Body, 4096)) //nolint:errcheck
		rsp.Body.Close()
		sess.closeQuietly()
		return fail(FailureConnectReject, fmt.Errorf("connect-ip responded %d", rsp.StatusCode))
	}

	sess.resp = rsp.Body
	sess.traceEv(fmt.Sprintf("connect-200 colo=%s", res.Colo))
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
	// M-09: reuse a pooled frame sized MTU+headroom instead of allocating a
	// fresh slice + copying the payload on every packet. The buffer is only
	// returned after pw.Write has copied the bytes out.
	frame := getFrame(s.framePool)
	*frame = AppendVarint(*frame, 0)
	*frame = AppendVarint(*frame, uint64(len(pkt)))
	*frame = append(*frame, pkt...)

	s.writeMu.Lock()
	writeStart := time.Now()
	_, err := s.pw.Write(*frame)
	wrMS := time.Since(writeStart).Milliseconds()
	s.writeMu.Unlock()
	putFrame(s.framePool, frame)
	if traceEnabled() || wrMS >= writeBlockWarnMS {
		s.traceTx(pkt, wrMS, err)
	}
	if err != nil {
		return err
	}
	s.txPkts.Add(1)
	s.txBytes.Add(uint64(len(pkt)))
	return nil
}

// ReadPacket returns the next inbound IP packet, transparently skipping
// non-DATAGRAM capsule types. It blocks until data, error, or ctx cancel.
// A closed packets channel reports ErrSessionClosed (never a zero-value
// `(nil, nil)` — M3-01).
func (s *Session) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case m, ok := <-s.packets:
		if !ok {
			return nil, ErrSessionClosed
		}
		return m.data, m.err
	default:
	}
	select {
	case m, ok := <-s.packets:
		if !ok {
			return nil, ErrSessionClosed
		}
		return m.data, m.err
	case <-s.done:
		// readerLoop drains remaining buffered frames into the channel and
		// closes it; give it a short window before reporting closure.
		select {
		case m, ok := <-s.packets:
			if !ok {
				return nil, ErrSessionClosed
			}
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
	case m, ok := <-s.packets:
		if !ok {
			return nil, true, ErrSessionClosed
		}
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
		case m, ok := <-s.packets:
			if !ok {
				// readerLoop closed the channel: the session is dead —
				// validation must FAIL, never pass on a dead tunnel (KPI-4).
				return fmt.Errorf("%s: %w", FailureValidation, ErrSessionClosed)
			}
			if m.err != nil {
				return fmt.Errorf("data plane lost during validation: %w", m.err)
			}
			successes++
		case <-s.done:
			return fmt.Errorf("%s: %w", FailureValidation, ErrSessionClosed)
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
		// Unblock tap receivers: closed channels end their select loops.
		s.subMu.Lock()
		taps := make([]chan []byte, 0, len(s.subs))
		for ch := range s.subs {
			taps = append(taps, ch)
		}
		s.subs = nil
		s.subMu.Unlock()
		for _, ch := range taps {
			close(ch)
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
		s.traceEv("reader-terminal: " + normalizeReadErr(err).Error())
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
		s.traceRx(typ, payload)
		if typ != 0 {
			continue // foreign control capsule: skip inbound (usque semantics)
		}
		s.rxPkts.Add(1)
		s.rxBytes.Add(uint64(len(payload)))
		s.emit(packetMsg{data: payload})
	}
}

// emit delivers one inbound packet to the primary consumer and to every
// tap subscriber. Delivery is DROP-INSTEAD-OF-BLOCK on both paths (resource
// discipline, research Part 4): a stalled consumer must never wedge the
// capsule reader, which would head-of-line-block the whole session.
func (s *Session) emit(m packetMsg) {
	select {
	case s.packets <- m:
	default:
		if m.err == nil { // error messages matter more than data frames
			s.droppedPrimary.Add(1)
			s.traceDropPrimary(m.data)
		} else {
			// prefer-send: never drop a terminal error while the queue has room
			// (M3-01). The outer select already tried one non-blocking send; this
			// inner select does the honest blocking attempt, interleaved with
			// done — so a full queue combined with closure loses the error
			// consciously, but a free slot always wins.
			select {
			case s.packets <- m:
			case <-s.done:
			}
		}
	}
	if m.err == nil && m.data != nil {
		s.fanOut(m.data)
	}
}

func (s *Session) fanOut(pkt []byte) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for ch := range s.subs {
		// M-30: each tap receives a private copy. pumpInbound hands the raw
		// payload to gVisor (buffer.MakeWithData, sliveless); a future
		// mutating/NAT-rewrite subscriber must not corrupt other taps or the
		// payload already queued on the primary packets channel.
		cp := append([]byte(nil), pkt...)
		select {
		case ch <- cp:
		default:
			s.droppedTaps++
			s.traceDropTap(pkt)
		}
	}
}

// SubscribePackets registers a secondary consumer of inbound DATAGRAM
// payloads. The returned channel is buffered; overflow drops frames
// (counted in DroppedFrames). The cancel function unsubscribes and closes
// the channel exactly once; Session.Close closes all remaining taps.
//
// Contract (M-30): every payload delivered here is a private copy; a
// subscriber may mutate the slice without affecting the primary consumer,
// other taps, or gVisor.
func (s *Session) SubscribePackets() (<-chan []byte, func()) {
	select {
	case <-s.done:
		// Closed session (M3-03): no ghost subscription may be registered on a
		// re-created subs map. Return a closed channel + no-op cancel instead.
		ch := make(chan []byte)
		close(ch)
		return ch, func() {}
	default:
	}
	ch := make(chan []byte, 64)
	s.subMu.Lock()
	if s.subs == nil {
		s.subs = make(map[chan []byte]struct{})
	}
	s.subs[ch] = struct{}{}
	s.subMu.Unlock()
	cancel := func() {
		s.subMu.Lock()
		if _, ok := s.subs[ch]; ok {
			delete(s.subs, ch)
			close(ch)
		}
		s.subMu.Unlock()
	}
	return ch, cancel
}

// PacketCounters snapshots the §43 inner-path traffic counters.
type PacketCounters struct {
	TxPackets uint64
	TxBytes   uint64
	RxPackets uint64
	RxBytes   uint64
}

// Counters returns the current tx/rx packet counters of this session.
func (s *Session) Counters() PacketCounters {
	return PacketCounters{
		TxPackets: s.txPkts.Load(),
		TxBytes:   s.txBytes.Load(),
		RxPackets: s.rxPkts.Load(),
		RxBytes:   s.rxBytes.Load(),
	}
}

// DroppedFrames reports dropped primary-consumer frames and dropped tap
// frames (drop-instead-of-block accounting).
func (s *Session) DroppedFrames() (primary, taps uint64) {
	s.subMu.Lock()
	taps = s.droppedTaps
	s.subMu.Unlock()
	return s.droppedPrimary.Load(), taps
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
	// Pin family is fail-closed on the H2 path too (M3-04): a pin incident
	// (rotation / bad cert) is reported as FailureTLSPin, never as a generic
	// FailureTCPConnect that could be mistaken for a purely network verdict.
	if errors.Is(err, ErrPinMismatch) || errors.Is(err, ErrPinNotECDSA) || errors.Is(err, ErrBadEndpointCert) {
		return FailureTLSPin
	}
	// M-02: a TLS-handshake deadline is classified structurally (sentinel),
	// never by the string branch crypto/tls did not produce (it surfaces
	// context.DeadlineExceeded on a handshake timeout).
	if errors.Is(err, ErrTLSHandshakeTimeout) {
		return FailureTLSTimeout
	}
	// M-03: ALPN mismatch is an H2-negotiation failure, never a generic
	// FailureTCPConnect (structured sentinel, same rationale as M-02).
	if errors.Is(err, ErrH2ALPN) {
		return FailureH2Negotiation
	}
	// M-04: a bare privilege/socket errno (EPERM/EACCES — e.g. Keenetic
	// without CAP_NET_ADMIN on SO_MARK, or a forbidden source bind) must be a
	// dial-policy verdict, not FailureTCPConnect, even when no *_text* branch
	// matched a wrapped message.
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return FailureDialPolicy
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "dial policy"), strings.Contains(msg, "SO_MARK"), strings.Contains(msg, "bind device"):
		return FailureDialPolicy
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
