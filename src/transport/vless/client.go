package vless

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// In-process VLESS client (design §8, phase V4). b4x speaks the VLESS framing
// itself and reuses the ALREADY-vendored utls (fingerprints) and
// gorilla/websocket (ws/httpupgrade) — zero new Go dependencies. The external
// helper remains for the transports we do NOT implement (grpc/xhttp/kcp/quic:
// hybrid).
//
// V4a here: raw/tcp + TLS. V4c: ws/httpupgrade. REALITY (V4b) lives in
// reality.go.

// VLESS request framing constants (public protocol, version 0).
const (
	vlessVersion byte = 0x00
	cmdTCP       byte = 0x01
	atypIPv4     byte = 0x01
	atypDomain   byte = 0x02
	atypIPv6     byte = 0x03
)

// InProcessTransports is the closed set the in-process client can carry.
func InProcessTransports() []string {
	return []string{TransportTCP, TransportWS, TransportHTTPUpgrade}
}

// SupportsInProcess reports whether the vendored in-process stack can carry
// the node: raw/tcp, ws and httpupgrade over none/tls/reality. grpc, xhttp,
// kcp and quic stay behind the external helper (no vendored grpc; xhttp is
// Xray-proprietary; kcp/quic need their own UDP stack).
func SupportsInProcess(n Node) bool {
	switch n.Transport {
	case TransportTCP, TransportWS, TransportHTTPUpgrade:
	default:
		return false
	}
	if n.Flow != "" && n.Flow != FlowVision {
		// Only XTLS Vision is a known flow; anything else is refused (the
		// helper path never renders it anyway — Validate rejects it too).
		return false
	}
	switch n.Security {
	case SecurityNone, SecurityTLS, SecurityReality:
	default:
		return false
	}
	if _, err := ParseUUID(n.UUID); err != nil {
		// The public corpus contains nodes whose id is not a 16-byte UUID
		// (e.g. a 30-char login). The in-process client needs a real UUID, so
		// such a node must stay on the helper path.
		return false
	}
	return true
}

// ParseUUID parses the VLESS user id (32 hex chars, dash-separated allowed).
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != 32 {
		return out, fmt.Errorf("vless: uuid %q must be 32 hex chars (got %d)", s, len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return out, fmt.Errorf("vless: uuid %q: %w", s, err)
	}
	copy(out[:], b)
	return out, nil
}

// Dialer is the in-process VLESS client for ONE node. Dial returns a net.Conn
// carrying the requested target stream through that node.
type Dialer struct {
	Node Node
	// Base dials the node's TCP endpoint. nil => a default net.Dialer. The
	// service injects its base carrier here for bootstrap-through-carrier.
	Base func(ctx context.Context, network, addr string) (net.Conn, error)
	// Timeout bounds the whole dial (connect + TLS + upgrade + framing).
	Timeout time.Duration
	// RootCAs overrides the trust store for plain TLS (tests / pinned CAs).
	RootCAs *x509.CertPool
}

// Dial establishes the VLESS stream to target through the node.
func (d *Dialer) Dial(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	if !SupportsInProcess(d.Node) {
		return nil, fmt.Errorf("vless: in-process client does not support transport %q/security %q", d.Node.Transport, d.Node.Security)
	}
	if err := d.Node.Validate(); err != nil {
		return nil, err
	}
	id, err := ParseUUID(d.Node.UUID)
	if err != nil {
		return nil, err
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	base := d.Base
	if base == nil {
		nd := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		base = nd.DialContext
	}
	serverAddr := net.JoinHostPort(d.Node.Host, strconv.Itoa(int(d.Node.Port)))
	raw, err := base(dialCtx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("vless: dial node %s: %w", serverAddr, err)
	}
	stream, err := d.wrapTransport(dialCtx, raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if dl, ok := stream.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dl.SetDeadline(time.Now().Add(timeout))
	}
	if err := writeRequest(stream, id, target, encodeFlowAddon(d.Node.Flow)); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("vless: write request: %w", err)
	}
	if dl, ok := stream.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dl.SetDeadline(time.Time{})
	}
	// The VLESS response header is read LAZILY (on the first Read), not here:
	// Xray writes it into a buffered writer and flushes it together with the
	// first body block (EncodeResponseHeader + SetFlushNext). Reading it
	// synchronously would deadlock against a real server, because the first
	// body block only arrives after we send our own (padded) payload.
	sc := &streamConn{Conn: stream}
	if d.Node.Flow == FlowVision {
		enc := newVisionWriter(stream, append([]byte(nil), id[:]...))
		if err := enc.writePreamble(); err != nil {
			_ = stream.Close()
			return nil, fmt.Errorf("vless: vision preamble: %w", err)
		}
		sc.r = newVisionReader(stream, append([]byte(nil), id[:]...))
		sc.w = enc
	} else {
		sc.r = stream
		sc.w = stream
	}
	return sc, nil
}

// streamConn is the dialed VLESS stream: writes pad (Vision) or pass through,
// and the response header is parsed once on the first read.
type streamConn struct {
	net.Conn
	r          io.Reader
	w          io.Writer
	headerOnce sync.Once
	headerErr  error
}

func (c *streamConn) Read(p []byte) (int, error) {
	if err := c.header(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func (c *streamConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *streamConn) header() error {
	c.headerOnce.Do(func() { c.headerErr = readResponse(c.Conn) })
	return c.headerErr
}

// wrapTransport applies the configured transport over the raw node connection:
// TLS (utls) first, then ws/httpupgrade upgrade on top of it.
func (d *Dialer) wrapTransport(ctx context.Context, raw net.Conn) (net.Conn, error) {
	conn := raw
	if d.Node.Security == SecurityTLS || d.Node.Security == SecurityReality {
		tlsConn, err := d.handshakeTLS(ctx, conn)
		if err != nil {
			return nil, err
		}
		conn = tlsConn
	}
	switch d.Node.Transport {
	case TransportTCP:
		return conn, nil
	case TransportWS:
		return d.upgradeWebsocket(conn)
	case TransportHTTPUpgrade:
		return d.upgradeHTTPUpgrade(conn)
	default:
		return nil, fmt.Errorf("vless: in-process transport %q unsupported", d.Node.Transport)
	}
}

// handshakeTLS runs the uTLS client handshake with the node's fingerprint and
// SNI. REALITY is delegated to applyReality (V4b).
func (d *Dialer) handshakeTLS(ctx context.Context, conn net.Conn) (net.Conn, error) {
	var authKey []byte
	cfg := &utls.Config{
		ServerName: d.Node.SNI,
		NextProtos: d.Node.ALPN,
		RootCAs:    d.RootCAs,
		// REALITY borrows a real site's certificate but authenticates the
		// server inside the handshake, so certificate verification is not the
		// trust anchor there. Plain TLS keeps normal verification.
		InsecureSkipVerify: d.Node.Security == SecurityReality,
	}
	if d.Node.Security == SecurityReality {
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyRealityCertificate(authKey, rawCerts)
		}
	}
	uconn := utls.UClient(conn, cfg, clientHelloID(d.Node.Fingerprint))
	if d.Node.Security == SecurityReality {
		k, err := applyReality(uconn, d.Node)
		if err != nil {
			return nil, err
		}
		authKey = k
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("vless: tls handshake: %w", err)
	}
	return uconn, nil
}

// clientHelloID maps the node fingerprint onto a uTLS preset. An empty value
// keeps the Chrome default; unknown values are already dropped by Validate.
func clientHelloID(fp string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(fp)) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "360":
		return utls.Hello360_Auto
	case "qq":
		return utls.HelloQQ_Auto
	case "random":
		return utls.HelloRandomized
	case "randomized":
		return utls.HelloRandomizedALPN
	default:
		return utls.HelloChrome_Auto
	}
}

// encodeFlowAddon builds the VLESS request addons for an XTLS flow. Xray
// marshals Addons (a protobuf with `string flow = 1`) with proto.Marshal when
// flow == "xtls-rprx-vision" (proxy/vless/encoding/addons.go, EncodeHeaderAddons),
// i.e. the bytes are `0x0A <len> <flow>`. An empty flow yields no addons.
//
// This is the request-header half of XTLS Vision; the body framing (padding +
// splice) is implemented in vision.go and wired by Dial, so in-process now
// carries flow=xtls-rprx-vision (interop-verified against Xray, see
// vision_interop_test.go and artifacts/vless-vision-interop/).
func encodeFlowAddon(flow string) []byte {
	if flow == "" {
		return nil
	}
	out := make([]byte, 0, 2+len(flow))
	out = append(out, 0x0A, byte(len(flow)))
	out = append(out, flow...)
	return out
}

// writeRequest emits the VLESS version-0 request header for target.
func writeRequest(w io.Writer, id [16]byte, target netip.AddrPort, addons []byte) error {
	addr := target.Addr().Unmap()
	buf := make([]byte, 0, 32+len(addons)+18)
	buf = append(buf, vlessVersion)
	buf = append(buf, id[:]...)
	buf = append(buf, byte(len(addons)))
	buf = append(buf, addons...)
	buf = append(buf, cmdTCP)
	port := target.Port()
	buf = append(buf, byte(port>>8), byte(port))
	switch {
	case addr.Is4():
		buf = append(buf, atypIPv4)
		a := addr.As4()
		buf = append(buf, a[:]...)
	case addr.Is6():
		buf = append(buf, atypIPv6)
		a := addr.As16()
		buf = append(buf, a[:]...)
	default:
		return fmt.Errorf("vless: unsupported target address %v", addr)
	}
	if _, err := w.Write(buf); err != nil {
		return err
	}
	return nil
}

// readResponse consumes the VLESS version-0 response header (version + addons).
func readResponse(r io.Reader) error {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	if head[0] != vlessVersion {
		return fmt.Errorf("vless: bad response version 0x%02x", head[0])
	}
	if head[1] > 0 {
		if _, err := io.ReadFull(r, make([]byte, int(head[1]))); err != nil {
			return err
		}
	}
	return nil
}
