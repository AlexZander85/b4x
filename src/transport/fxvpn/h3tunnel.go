// H3 CONNECT carrier - handwritten minimal HTTP/3 over raw quic-go (owner
// decision FX2 option (a): x/net/http3 is NOT vendored and stays so). Wire
// shape mirrors the reference h3ProxySession (main.go:2609-2794) but builds
// the protocol by hand from the proven E-H1/E-H2 primitives: QUIC ALPN h3,
// InitialPacketSize 1200 (reference gotcha: the 1280 default exceeds low-MTU
// paths once IP/UDP headers are added - handshakes die invisibly),
// KeepAlivePeriod 30s; control+QPACK uni-streams; plain CONNECT per target
// (:method CONNECT, :authority, Proxy-Authorization Bearer); 2xx => DATA
// frames relay raw bytes.
package fxvpn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	h3InitialPacketSize = 1250 // Firefox pads the Initial to ~1200-1250; the
	// previous constant 1200 was itself a marker (masquerade §7.4.3, FX-M0).
	// RFC 8899 PMTU grows it back after the handshake.
	h3KeepAlivePeriod = 30 * time.Second
	h3MaxStreams      = 64
)

// DialH3 establishes one upstream HTTP/3 CONNECT session through a UDP
// carrier socket created under cfg.Policy (SO_MARK/SO_BINDTODEVICE before
// bind, fail-closed).
func DialH3(ctx context.Context, cfg TunnelConfig) (*H3Tunnel, error) {
	cfg.fillDefaults()
	authority := cfg.Authority()

	// Review F2: the server list serves HOSTNAMES (prod records are
	// hostname:2499) while quic.Dial needs a UDP address — resolve here,
	// exactly where H2 resolves implicitly (tls.DialWithDialer). SNI stays
	// the NAME; the socket family is computed from the RESOLVED address,
	// not from the literal (a name would always parse to nil -> "udp" and
	// could mismatch the actual target family on dual-stack).
	rctx, rcancel := context.WithTimeout(ctx, cfg.HandshakeBudget)
	ip, rerr := resolveEdgeHost(rctx, cfg)
	rcancel()
	if rerr != nil {
		return nil, fmt.Errorf("fxvpn: h3 resolve %s: %w", cfg.Host, rerr)
	}
	family := "udp4"
	if ip.To4() == nil {
		family = "udp6"
	}
	uc, err := cfg.Policy.ListenUDP(ctx, family, ":0")
	if err != nil {
		return nil, fmt.Errorf("fxvpn: h3 carrier socket %s: %w", authority, err)
	}

	dctx, cancel := context.WithTimeout(ctx, cfg.HandshakeBudget)
	defer cancel()

	tlsCfg := &tls.Config{
		ServerName:       cfg.Host,
		MinVersion:       tls.VersionTLS13,
		NextProtos:       []string{"h3"},
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384},
	}
	if cfg.TLS != nil {
		tlsCfg = cfg.TLS.Clone()
		tlsCfg.MinVersion = tls.VersionTLS13
		tlsCfg.NextProtos = []string{"h3"}
		tlsCfg.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.CurveP384}
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = cfg.Host
		}
	}
	// Masquerade §7.4.3: Firefox cipher/curve offer on the QUIC handshake.
	cfg.Masquerade.ApplyHelloShaping(tlsCfg)

	// Masquerade §7.4.1: the QUIC preflight bait — 1-2 RFC-accurate fake
	// Initials with a WHITE SNI leave a THROWAWAY TTL-limited socket before
	// the real handshake. The real carrier socket and handshake are never
	// touched (red line 2), and a failed bait never blocks the dial (the
	// bait is transparent noise, not a dependency).
	if cfg.Masquerade.PreflightFake {
		network := family
		payloads := preflightFakeInitials(cfg.Masquerade, cfg.Host, cfg.Masquerade.FakeCount)
		if len(payloads) > 0 {
			baitAddr := &net.UDPAddr{IP: ip, Port: cfg.Port}
			baitPolicy := DialPolicy{TTL: cfg.Masquerade.FakeTTL}
			for i, p := range payloads {
				if i > 0 {
					time.Sleep(baitGap())
				}
				if err := preflightSend([][]byte{p}, baitAddr, baitPolicy, network); err != nil {
					break // best-effort: stop firing, keep dialing
				}
			}
		}
	}

	quicCfg := &quic.Config{
		KeepAlivePeriod:    h3KeepAlivePeriod,
		InitialPacketSize:  h3InitialPacketSize,
		MaxIncomingStreams: h3MaxStreams,
	}
	if cfg.Masquerade.InitialPadding >= 1200 && cfg.Masquerade.InitialPadding <= 1400 {
		quicCfg.InitialPacketSize = uint16(cfg.Masquerade.InitialPadding)
	}
	conn, err := quic.Dial(dctx, uc, &net.UDPAddr{IP: ip, Port: cfg.Port}, tlsCfg, quicCfg)
	if err != nil {
		_ = uc.Close()
		return nil, classifyH3HandshakeFailure(authority, err)
	}
	if got := conn.ConnectionState().TLS.NegotiatedProtocol; got != "h3" {
		_ = conn.CloseWithError(0, "")
		_ = uc.Close()
		return nil, fmt.Errorf("%w: %s negotiated %q", errH3NegotiationFailed, authority, got)
	}
	if err := writeClientPreamble(conn); err != nil {
		_ = conn.CloseWithError(0, "")
		_ = uc.Close()
		return nil, err
	}

	s := &H3Tunnel{
		conn:          conn,
		udpConn:       uc,
		edgeAuthority: authority,
		cfg:           cfg,
		token:         cfg.Token,
		stopWatchDone: make(chan struct{}),
	}
	s.alive.Store(true)
	go s.watchDone()
	return s, nil
}

// classifyH3HandshakeFailure maps QUIC handshake outcomes onto ladder
// classes: blackhole/timeouts => udp-egress-blocked; TLS/ALPN/protocol
// rejections => h3-negotiation-failed; anything else passes through raw.
func classifyH3HandshakeFailure(authority string, err error) error {
	var idle *quic.IdleTimeoutError
	var hs *quic.HandshakeTimeoutError
	var vne *quic.VersionNegotiationError
	var sre *quic.StatelessResetError
	switch {
	case errors.As(err, &idle), errors.As(err, &hs), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %s: %v", errUDPEgressBlocked, authority, err)
	case errors.As(err, &vne), errors.As(err, &sre):
		return fmt.Errorf("%w: %s: %v", errUDPEgressBlocked, authority, err)
	}
	msg := err.Error()
	if strings.Contains(msg, "no application protocol") ||
		strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "PROTOCOL_VIOLATION") {
		return fmt.Errorf("%w: %s: %v", errH3NegotiationFailed, authority, err)
	}
	var ae *quic.ApplicationError
	if errors.As(err, &ae) {
		return fmt.Errorf("%w: %s: %v", errH3NegotiationFailed, authority, err)
	}
	return fmt.Errorf("fxvpn: h3 dial %s: %w", authority, err)
}

// H3Tunnel is one live upstream HTTP/3 CONNECT session.
type H3Tunnel struct {
	conn          *quic.Conn
	udpConn       *net.UDPConn
	edgeAuthority string
	cfg           TunnelConfig

	tokenMu sync.RWMutex
	token   string

	health        failureTracker
	closeOnce     sync.Once
	closeErr      error
	alive         atomic.Bool
	stopWatchDone chan struct{}
}

// watchDone flips the alive flag when the QUIC connection terminates.
func (s *H3Tunnel) watchDone() {
	select {
	case <-s.conn.Context().Done():
		s.alive.Store(false)
	case <-s.stopWatchDone:
	}
}

// IsAlive reports whether new tunnels may be opened.
func (s *H3Tunnel) IsAlive() bool { return s.alive.Load() }

func (s *H3Tunnel) bearerToken() string {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	return s.token
}

// UpdateToken swaps the proxy pass in place; applies to subsequent tunnels
// (reference UpdateToken semantics).
func (s *H3Tunnel) UpdateToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("fxvpn: empty proxy session token")
	}
	s.tokenMu.Lock()
	s.token = token
	s.tokenMu.Unlock()
	return nil
}

// Close tears the session down once.
func (s *H3Tunnel) Close() error {
	s.closeOnce.Do(func() {
		s.alive.Store(false)
		close(s.stopWatchDone)
		s.closeErr = s.conn.CloseWithError(0, "")
		if cerr := s.udpConn.Close(); s.closeErr == nil {
			s.closeErr = cerr
		}
	})
	return s.closeErr
}

// OpenTunnel opens one plain CONNECT relay to authority over H3.
func (s *H3Tunnel) OpenTunnel(parent context.Context, authority string) (net.Conn, error) {
	octx, cancel := context.WithTimeout(parent, s.cfg.OpenBudget)
	stream, err := s.conn.OpenStreamSync(octx)
	if err != nil {
		cancel()
		return nil, s.health.observe(authority, classifyOpenFailure(err), fmt.Errorf("fxvpn: open stream: %w", err))
	}

	req := EncodeConnectFieldSection(authority, [][2]string{
		{"proxy-authorization", "Bearer " + s.bearerToken()},
	})
	if _, err := stream.Write(appendH3Headers(nil, req)); err != nil {
		_ = stream.Close()
		cancel()
		return nil, s.health.observe(authority, "", fmt.Errorf("fxvpn: write CONNECT %s: %w", authority, err))
	}
	// Bound the response wait: quic-go streams honor deadlines.
	if derr := stream.SetDeadline(octxDeadline(octx)); derr != nil {
		_ = stream.Close()
		cancel()
		return nil, s.health.observe(authority, "", fmt.Errorf("fxvpn: CONNECT %s deadline: %w", authority, derr))
	}

	fr := newH3Framer(stream)
	_, payload, err := fr.ReadKnownFrame(map[uint64]bool{h3FrameHeaders: true})
	if err != nil {
		_ = stream.Close()
		cancel()
		return nil, s.health.observe(authority, classifyOpenFailure(err), fmt.Errorf("fxvpn: CONNECT %s response: %w", authority, err))
	}
	fields, derr := DecodeFieldSection(payload)
	if derr != nil {
		_ = stream.Close()
		cancel()
		return nil, s.health.observe(authority, "", fmt.Errorf("fxvpn: CONNECT %s headers: %w", authority, derr))
	}
	status := 0
	for _, kv := range fields {
		if kv[0] == ":status" {
			status, _ = strconv.Atoi(kv[1])
			break
		}
	}
	if status < 200 || status > 299 {
		_ = stream.Close()
		cancel()
		rej := &ConnectRejectedError{StatusCode: status, Status: strconv.Itoa(status)}
		var kind string
		if rej.StatusCode == http.StatusBadGateway {
			kind = "bad-gateway"
		}
		return nil, s.health.observe(authority, kind, rej)
	}
	s.health.observe(authority, "", nil)
	// The establishment budget must not kill the long-lived relay: clear it.
	_ = stream.SetDeadline(time.Time{})
	return &tunnelConn{
		reader: &h3StreamReader{fr: fr, st: stream},
		writer: &h3StreamWriter{st: stream},
		cancel: cancel,
	}, nil
}

// octxDeadline extracts the context deadline (zero time when absent).
func octxDeadline(ctx context.Context) time.Time {
	d, _ := ctx.Deadline()
	return d
}

// preflightSend is the bait injection seam (a package var so the fake-stand
// tests pin the datagrams without touching sockets); production wires
// sendPreflightReal.
var preflightSend preflightSender = sendPreflightReal

// resolveEdgeHost turns cfg.Host into the carrier IP (review F2). Literals
// parse directly; names go through the configured resolver (default
// net.DefaultResolver) under the handshake budget.
func resolveEdgeHost(ctx context.Context, cfg TunnelConfig) (net.IP, error) {
	if ip := net.ParseIP(cfg.Host); ip != nil {
		return ip, nil
	}
	res := cfg.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	ips, err := res.LookupIPAddr(ctx, cfg.Host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %q", cfg.Host)
	}
	return ips[0].IP, nil
}

// h3StreamReader turns inbound DATA frames into a plain byte stream.
type h3StreamReader struct {
	fr  *h3Framer
	st  *quic.Stream
	buf []byte
	eof bool
}

func (r *h3StreamReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 && !r.eof {
		typ, payload, err := r.fr.ReadKnownFrame(map[uint64]bool{h3FrameData: true})
		if err != nil {
			if errors.Is(err, io.EOF) {
				r.eof = true
				break
			}
			return 0, err
		}
		if typ == h3FrameData {
			r.buf = payload
		}
	}
	if len(r.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// Close tears the relay stream down.
func (r *h3StreamReader) Close() error { return r.st.Close() }

// h3StreamWriter wraps outbound bytes into DATA frames.
type h3StreamWriter struct{ st *quic.Stream }

func (w *h3StreamWriter) Write(p []byte) (int, error) {
	if _, err := w.st.Write(appendH3Frame(nil, h3FrameData, p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close finishes the send side (FIN).
func (w *h3StreamWriter) Close() error { return w.st.Close() }
