// MASQUE CONNECT-IP session over QUIC/HTTP-3 — path B of the E-H3 design:
// hand-written H3 dialect over raw quic-go streams, wire shape verified
// against the pinned usque reference (warp/usque clone, api/masque.go) and
// its connect-ip-go fork (warp/connect-ip-go clone):
//
//	QUIC  : ConnectionIDLength=20 (usque masque.go:181-183 — without it the
//	        backend intermittently closes with PROTOCOL_VIOLATION),
//	        EnableDatagrams, settings {0x276:1} (SETTINGS_H3_DATAGRAM_00
//	        legacy draft; the official client still sends it — usque
//	        masque.go:190-200), keepalive PING 15s, MaxIdleTimeout 90s,
//	        windows conn 10 MB / stream 1 MB, MaxIncomingStreams 100.
//	UDP   : dual-bind by peer family (usque connectTunnelHTTP3:166-176),
//	        DialPolicy marks applied before bind (addendum §18).
//	TLS   : same pin contract as the H2 branch, ALPN h3, TLS 1.3 only,
//	        CurvePreferences P-256,P-384 (no HelloRetryRequest).
//	H3    : control stream (type 0x00) + SETTINGS incl. {0x276:1};
//	        extended CONNECT bi-stream with EXACTLY the verified header set:
//	        :method CONNECT, :protocol cf-connect-ip (the value usque passes
//	        as requestProtocol), :scheme https, :authority IP:port (owner
//	        mandate; NOTE usque itself sends the template domain here —
//	        flagged, see report), capsule-protocol ?1 (connect-ip-go
//	        client.go:40), user-agent "" (usque additionalHeaders). The H2
//	        headers cf-connect-proto/pq-enabled are NOT sent on H3 — usque
//	        adds them only in its H2 branch.
//	Retry : exactly 2 attempts for the retriable failure family (design §4:
//	        ErrClosed/AppError-0/IdleTimeout/StatelessReset/TransportError-
//	        NoError/PROTOCOL_VIOLATION/"failed to read response" — the last
//	        being connect-ip-go client.go:61 wording usque retries on).
package transportwarp

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC transport constants (E-H3 design §1; prompt EH2).
const (
	// DefaultH3OpenStreamBudget bounds open_bi: the edge may HANG stream
	// creation on flow-control exhaustion instead of erroring (design §4;
	// prompt EH2: обёртка таймаута 10 с).
	DefaultH3OpenStreamBudget = 10 * time.Second
	// h3KeepAlivePeriod holds NAT mappings alive (design: 15–20s band).
	h3KeepAlivePeriod = 15 * time.Second
	// h3MaxIdleTimeout explicit — never the library default (design §1).
	h3MaxIdleTimeout = 90 * time.Second
	// Flow-control windows (design §1: conn 10 MB / stream 1 MB).
	h3ConnWindow   uint64 = 10 << 20
	h3StreamWindow uint64 = 1 << 20
	// h3MaxStreams mirrors the tun profiles (usque/Aether).
	h3MaxStreams int64 = 100
)

// New H3 failure classes (§62.1 continuation, design §8).
const (
	FailureQUICProtocolViolation = "quic-protocol-violation"
	FailureUDPEgressBlocked      = "udp-egress-blocked"
	FailureQUICStreamQuotaHang   = "quic-stream-quota-hang"
	FailureH3Negotiation         = "h3-negotiation-failed"
)

// settingsH3DatagramDraft00 is SETTINGS_H3_DATAGRAM_00 = 0x276 (usque
// masque.go:195; deprecated id the official client still emits).
const settingsH3DatagramDraft00 uint64 = 0x276

// WriteControlPreamble is the client control-stream opening: stream type
// varint + SETTINGS carrying the legacy datagram setting. QPACK table
// capacity stays unadvertised (=0): dynamic table unused by contract.
func WriteControlPreamble() []byte {
	out := AppendVarint(nil, h3StreamControl)
	settings := AppendVarint(nil, settingsH3DatagramDraft00)
	settings = AppendVarint(settings, 1)
	return appendH3Frame(out, h3FrameSettings, settings)
}

// H3SessionConfig is one QUIC/H3 attempt's parameters (mirror of
// SessionConfig for the H3 carrier).
type H3SessionConfig struct {
	Endpoint        netip.AddrPort // numeric catalog endpoint
	SNI             string         // cover SNI or DefaultSNI
	ClientKey       *ecdsa.PrivateKey
	Pin             *ecdsa.PublicKey
	ExtraPins       map[string]bool
	Policy          DialPolicy
	LocalV4         [4]byte       // assigned WARP address (probe source)
	MTU             int           // DefaultMTU when zero
	ValidateWindow  time.Duration // DefaultValidateWindow when zero
	ProbeInterval   time.Duration // DefaultProbeInterval when zero
	HandshakeBudget time.Duration // dial+handshake+CONNECT budget, default 20s
	OpenStreamBudet time.Duration // open_bi wrap, DefaultH3OpenStreamBudget
}

func (c *H3SessionConfig) fillDefaults() {
	if c.SNI == "" {
		c.SNI = DefaultSNI
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
	if c.OpenStreamBudet == 0 {
		c.OpenStreamBudet = DefaultH3OpenStreamBudget
	}
}

// H3ConnectResult is the structured outcome of one H3 attempt (ConnectResult
// mirror for traces).
type H3ConnectResult struct {
	Status       int
	DurationMS   uint64
	FailureClass string
	PinDigest    string
	ProtocolErr  string
	Colo         string
}

// H3Session is one established CONNECT-IP session over QUIC datagrams.
type H3Session struct {
	cfg     H3SessionConfig
	conn    *quic.Conn
	tr      *quic.Transport
	uc      *net.UDPConn
	stream  *quic.Stream
	packets chan packetMsg

	writeMu   sync.Mutex
	closeOnce sync.Once
	done      chan struct{}
	cancel    context.CancelFunc

	txPkts, txBytes atomic.Uint64
	rxPkts, rxBytes atomic.Uint64
	droppedPrimary  atomic.Uint64
	subMu           sync.Mutex
	subs            map[chan []byte]struct{}
	droppedTaps     uint64
}

// DialH3Session establishes the tunnel: UDP carrier → QUIC handshake →
// control stream → extended CONNECT → response verification. Retriable
// failures are attempted exactly twice (design §4 taxonomy); every other
// class returns immediately with its structural code.
func DialH3Session(parent context.Context, cfg H3SessionConfig) (*H3Session, H3ConnectResult, error) {
	start := time.Now()
	cfg.fillDefaults()

	res := H3ConnectResult{PinDigest: PinDigest(cfg.Pin)}
	fail := func(class string, err error) (*H3Session, H3ConnectResult, error) {
		res.FailureClass = class
		res.DurationMS = msSince(start)
		return nil, res, fmt.Errorf("%s: %w", class, err)
	}

	var lastClass string
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		sess, ares, err := dialH3Once(parent, start, cfg)
		res = ares
		if err == nil {
			return sess, res, nil
		}
		lastClass, lastErr = res.FailureClass, err
		if attempt == 2 || !isRetriableH3Failure(err) {
			break
		}
	}
	return fail(lastClass, lastErr)
}

func dialH3Once(parent context.Context, start time.Time, cfg H3SessionConfig) (*H3Session, H3ConnectResult, error) {
	cfg.fillDefaults()
	res := H3ConnectResult{PinDigest: PinDigest(cfg.Pin)}

	ctx, cancel := context.WithCancel(parent)
	sess := &H3Session{
		cfg:     cfg,
		packets: make(chan packetMsg, 16),
		done:    make(chan struct{}),
		cancel:  cancel,
	}
	abandon := func(class string, err error) (*H3Session, H3ConnectResult, error) {
		sess.closeResources()
		res.FailureClass = class
		res.DurationMS = msSince(start)
		return nil, res, fmt.Errorf("%s: %w", class, err)
	}

	clientCert, err := ClientCertificate(cfg.ClientKey)
	if err != nil {
		return abandon(FailureTLSAlert, err)
	}
	tlsCfg, err := PrepareH3TLSConfig(clientCert, cfg.SNI, cfg.Pin, cfg.ExtraPins)
	if err != nil {
		return abandon(FailureTLSAlert, err)
	}

	// Dual-bind by peer family (usque pattern); policy constraints applied
	// inside ListenConfig.Control before bind.
	network := "udp4"
	laddr := "0.0.0.0:0"
	if !cfg.Endpoint.Addr().Is4() {
		network = "udp6"
		laddr = "[::]:0"
	}
	uc, err := cfg.Policy.ListenUDP(ctx, network, laddr)
	if err != nil {
		return abandon(classifyUDPListenError(err), err)
	}
	sess.uc = uc

	tr := &quic.Transport{Conn: uc, ConnectionIDLength: 20} // CID20 or PROTOCOL_VIOLATION (design §1)
	sess.tr = tr
	remote := net.UDPAddrFromAddrPort(cfg.Endpoint)
	conf := &quic.Config{
		EnableDatagrams:            true,
		KeepAlivePeriod:            h3KeepAlivePeriod,
		MaxIdleTimeout:             h3MaxIdleTimeout,
		MaxConnectionReceiveWindow: h3ConnWindow,
		MaxStreamReceiveWindow:     h3StreamWindow,
		MaxIncomingStreams:         h3MaxStreams,
		HandshakeIdleTimeout:       cfg.HandshakeBudget,
		DisablePathMTUDiscovery:    false, // PMTUD auto per design §1
	}
	hsCtx, hsCancel := context.WithTimeout(ctx, cfg.HandshakeBudget)
	defer hsCancel()
	conn, err := tr.Dial(hsCtx, remote, tlsCfg, conf)
	if err != nil {
		return abandon(classifyH3HandshakeError(err), err)
	}
	sess.conn = conn

	// Control stream opening is local and instant; drain nothing inbound
	// (server qpack streams stay silent at capacity 0 — documented limit).
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		return abandon(classifyH3HandshakeError(err), err)
	}
	if _, err := ctrl.Write(WriteControlPreamble()); err != nil {
		return abandon(classifyH3HandshakeError(err), err)
	}

	// open_bi under budget: quota exhaustion HANGS instead of erroring
	// (design §4 trap; timeout ⇒ full reconnect cycle, not same-conn retry).
	osCtx, osCancel := context.WithTimeout(ctx, cfg.OpenStreamBudet)
	stream, err := conn.OpenStreamSync(osCtx)
	osCancel()
	if err != nil {
		class := FailureQUICStreamQuotaHang
		if ctx.Err() != nil || hsCtx.Err() != nil {
			class = FailureConnectTimeo
		}
		return abandon(class, err)
	}
	sess.stream = stream

	// Extended CONNECT request — exact verified header set (see package doc).
	authority := AuthorityForEndpoint(cfg.Endpoint.Addr().String(), cfg.Endpoint.Port())
	wr := &qpackWriter{}
	wr.b = appendQPACKInt(wr.b, 0x00, 8, 0)        // RIC=0
	wr.b = appendQPACKInt(wr.b, 0x00, 7, 0)        // Base delta 0
	wr.b = append(wr.b, 0xC0|qpackIdxMethodConnct) // :method CONNECT -> 0xCF
	wr.encodeLiteralNameLine(":protocol", "cf-connect-ip")
	wr.encodeLiteralNameLine(":scheme", "https")
	wr.b = appendQPACKInt(wr.b, 0x50, 4, qpackIdxAuthority) // :authority name-ref static #0
	wr.b = appendQPACKStringImpl(wr.b, 0x00, 8, authority)
	wr.encodeLiteralNameLine("capsule-protocol", "?1")
	wr.encodeLiteralNameLine("user-agent", "")
	if _, err := stream.Write(appendH3Headers(nil, wr.b)); err != nil {
		return abandon(classifyH3RequestError(err), err)
	}

	// Response under the remaining handshake budget: silence here is the
	// blocked-endpoint signature (handshake completes, CONNECT never answers
	// — design §4 second timer).
	fr := newH3Framer(stream)
	type rspOut struct {
		typ     uint64
		payload []byte
		err     error
	}
	rspCh := make(chan rspOut, 1)
	go func() {
		typ, payload, rerr := fr.ReadKnownFrame(map[uint64]bool{h3FrameHeaders: true})
		rspCh <- rspOut{typ, payload, rerr}
	}()
	var rsp rspOut
	select {
	case rsp = <-rspCh:
	case <-hsCtx.Done():
		stream.CancelRead(quic.StreamErrorCode(0))
		return abandon(FailureConnectTimeo, hsCtx.Err())
	case <-parent.Done():
		return abandon(FailureSessionAborted, parent.Err())
	}
	if rsp.err != nil {
		return abandon(classifyH3ResponseError(rsp.err), rsp.err)
	}
	fields, derr := DecodeFieldSection(rsp.payload)
	if derr != nil {
		return abandon(FailureH3Negotiation, derr)
	}
	status := 0
	for _, kv := range fields {
		if kv[0] == ":status" {
			fmt.Sscanf(kv[1], "%d", &status) //nolint:errcheck // numeric per protocol
		}
		if kv[0] == "cf-warp-colo" {
			res.Colo = kv[1]
		}
	}
	res.Status = status
	if status < 200 || status > 299 {
		return abandon(FailureConnectReject, fmt.Errorf("connect-ip responded %d", status))
	}

	res.DurationMS = msSince(start)
	go sess.readerLoop()
	return sess, res, nil
}

// ---- session I/O (contract parity with Session) ----

// WritePacket sends one outbound IP packet as an H3 datagram
// varint(qsid)+varint(ctx=0)+payload.
func (s *H3Session) WritePacket(pkt []byte) error {
	select {
	case <-s.done:
		return ErrSessionClosed
	default:
	}
	if len(pkt) == 0 || len(pkt) > s.cfg.MTU {
		return fmt.Errorf("%w: %d bytes (mtu %d)", ErrPacketTooBig, len(pkt), s.cfg.MTU)
	}
	frame := WrapH3Datagram(uint64(s.stream.StreamID()), 0, pkt)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.conn.SendDatagram(frame); err != nil {
		var tooBig *quic.DatagramTooLargeError
		if errors.As(err, &tooBig) {
			return fmt.Errorf("%w: datagram payload cap %d", ErrPacketTooBig, tooBig.MaxDatagramPayloadSize)
		}
		return err
	}
	s.txPkts.Add(1)
	s.txBytes.Add(uint64(len(pkt)))
	return nil
}

// ReadPacket blocks for the next inbound IP packet (skipping foreign
// quarters/context ids — Aether tolerance semantics). A closed packets
// channel reports ErrSessionClosed (never a zero-value `(nil, nil)` — M3-01).
func (s *H3Session) ReadPacket(ctx context.Context) ([]byte, error) {
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

// TryRead drains the pump queue without blocking.
func (s *H3Session) TryRead() ([]byte, bool, error) {
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

// ValidateDataPlane proves the inner path: identical semantics to the H2
// branch (session.go) — synthetic DNS probe every ProbeInterval, two inbound
// packets within ValidateWindow pass, timeout tears the session down.
func (s *H3Session) ValidateDataPlane(ctx context.Context) error {
	probe, err := NewDNSProbe(s.cfg.LocalV4, [4]byte{8, 8, 8, 8}, "cloudflare.com")
	if err != nil {
		return fmt.Errorf("probe build: %w", err)
	}
	if err := s.WritePacket(probe.Packet); err != nil {
		return fmt.Errorf("%s: %w", FailureUDPEgressBlocked, err)
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

// Done exposes termination for supervisors.
func (s *H3Session) Done() <-chan struct{} { return s.done }

func (s *H3Session) readerLoop() {
	defer close(s.packets)
	myQuarter := uint64(s.stream.StreamID()) / 4
	for {
		dg, err := s.conn.ReceiveDatagram(context.Background())
		if err != nil {
			s.Close() // unblock emit even on full queue
			s.emit(packetMsg{err: normalizeReadErr(err)})
			return
		}
		qsid, cid, pkt, uerr := UnwrapH3Datagram(dg)
		if uerr != nil || cid != 0 || qsid != myQuarter {
			continue // foreign/malformed datagram: skip, never kill the reader
		}
		s.rxPkts.Add(1)
		s.rxBytes.Add(uint64(len(pkt)))
		s.emit(packetMsg{data: pkt})
	}
}

func (s *H3Session) emit(m packetMsg) {
	select {
	case s.packets <- m:
	default:
		if m.err == nil {
			s.droppedPrimary.Add(1)
		} else {
			// prefer-send (M3-01): never drop a terminal error while the queue
			// has room; the inner select interleaves the honest blocking send
			// with done so a full queue + closure loses it consciously.
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

func (s *H3Session) fanOut(pkt []byte) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- pkt:
		default:
			s.droppedTaps++
		}
	}
}

// SubscribePackets registers a secondary tap consumer (parity with Session).
func (s *H3Session) SubscribePackets() (<-chan []byte, func()) {
	select {
	case <-s.done:
		// Closed session (M3-03): no ghost subscription may be registered. Return
		// a closed channel + no-op cancel instead.
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

// PacketCounters snapshots tx/rx traffic (§43 counter-delta proof input).
type H3PacketCounters struct {
	TxPackets uint64
	TxBytes   uint64
	RxPackets uint64
	RxBytes   uint64
}

func (s *H3Session) Counters() H3PacketCounters {
	return H3PacketCounters{
		TxPackets: s.txPkts.Load(),
		TxBytes:   s.txBytes.Load(),
		RxPackets: s.rxPkts.Load(),
		RxBytes:   s.rxBytes.Load(),
	}
}

func (s *H3Session) DroppedFrames() (primary, taps uint64) {
	s.subMu.Lock()
	taps = s.droppedTaps
	s.subMu.Unlock()
	return s.droppedPrimary.Load(), taps
}

// Close releases everything exactly once (control stream is NEVER closed
// alone — the whole connection goes, per H3_CLOSED_CRITICAL_STREAM rule).
// Parity with Session.Close: remaining taps are closed so their consumers
// (e.g. the supervisor tapPump) unblock — M3-03.
func (s *H3Session) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.cancel()
		s.closeResources()
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

func (s *H3Session) closeResources() {
	if s.conn != nil {
		_ = s.conn.CloseWithError(quic.ApplicationErrorCode(0), "session closed")
	}
	if s.tr != nil {
		_ = s.tr.Close()
	}
	if s.uc != nil {
		_ = s.uc.Close()
	}
}

// ---- classification ----

// isRetriableH3Failure implements the design §4 retry family: connection
// closed cleanly (AppError 0 / TransportError NoError / ErrClosed), idle
// timeout, stateless reset, PROTOCOL_VIOLATION-once, and the
// "failed to read response" class (connect-ip-go client.go:61 wording).
func isRetriableH3Failure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) && strings.Contains(err.Error(), FailureQUICProtocolViolation) {
		return true
	}
	var te *quic.TransportError
	if errors.As(err, &te) {
		switch te.ErrorCode {
		case quic.NoError, quic.ProtocolViolation:
			return te.Remote
		}
		return false
	}
	var ae *quic.ApplicationError
	if errors.As(err, &ae) {
		return ae.Remote && uint64(ae.ErrorCode) == 0
	}
	if errors.Is(err, &quic.IdleTimeoutError{}) || errors.Is(err, &quic.StatelessResetError{}) ||
		errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), FailureQUICProtocolViolation)
}

func classifyUDPListenError(err error) string {
	return FailureUDPEgressBlocked
}

// classifyH3HandshakeError splits dial-phase outcomes for the ladder: fast
// network refusal vs silent path (both udp-egress-blocked candidates) vs TLS
// pin mismatch (fail-closed).
func classifyH3HandshakeError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrPinMismatch) {
		return FailureTLSPin
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "tls:") || strings.Contains(msg, "crypto"):
		return FailureTLSAlert
	case errors.Is(err, &quic.IdleTimeoutError{}), errors.Is(err, &quic.HandshakeTimeoutError{}),
		strings.Contains(msg, "timeout"):
		return FailureUDPEgressBlocked
	case errors.Is(err, net.ErrClosed):
		return FailureUDPEgressBlocked
	default:
		return FailureUDPEgressBlocked
	}
}

func classifyH3RequestError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "closed") {
		return FailureQUICProtocolViolation
	}
	return FailureTCPConnect
}

// classifyH3ResponseError maps the response-read phase: transport
// PROTOCOL_VIOLATION and plain read failures form the retriable class
// (prompt EH2: «failed to read response» + PROTOCOL_VIOLATION).
func classifyH3ResponseError(err error) string {
	var te *quic.TransportError
	if errors.As(err, &te) && te.ErrorCode == quic.ProtocolViolation {
		return FailureQUICProtocolViolation
	}
	if errors.Is(err, &quic.IdleTimeoutError{}) || errors.Is(err, net.ErrClosed) {
		return FailureQUICProtocolViolation
	}
	msg := err.Error()
	if strings.Contains(msg, "closed") || strings.Contains(msg, "read") {
		return FailureQUICProtocolViolation
	}
	return FailureConnectTimeo
}

// FailureSessionAborted covers parent-context cancellation mid-dial (not a
// network verdict; distinct so supervisors never count it against health).
const FailureSessionAborted = "session-aborted"
