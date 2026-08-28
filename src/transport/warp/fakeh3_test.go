package transportwarp

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// fakeH3Edge is the EH1 stand (design §10): a QUIC/H3 endpoint speaking the
// minimal MASQUE dialect — ALPN h3, uni control stream + SETTINGS, extended
// CONNECT on a bi-stream, RFC 9484 datagram echo — carrying the §66-style
// behavioral matrix switches ported from fakeserver_test.go to H3.
type fakeH3Edge struct {
	t                 *testing.T
	key               *ecdsa.PrivateKey
	tr                *quic.Transport
	addr              *net.UDPAddr
	mu                sync.Mutex
	status            int  // CONNECT response status (default 200)
	dropDatagrams     bool // accept control, never echo (silent-DPI class)
	teardownAfterEcho int  // echo N datagrams then hard-close the connection
	hangConnect       bool // accept the CONNECT stream but never answer it
	// delayResponse sleeps before answering CONNECT (late-answer fixture:
	// the answer arrives after the client response window expired).
	delayResponse time.Duration
	quotaZeroStreams  bool // advertise MAX_STREAMS=0: client open_bi hangs (quota trap)
	killImmediately   bool // close conn with AppError 0 right after control stream (retry fixture)
	colo              string
	connects          int
	connAccepts       int
	payloads          [][]byte
}

const (
	fakeH3HandshakeTimeout = 2 * time.Second
	fakeH3IdleTimeout      = 10 * time.Second
)

func newFakeH3Edge(t *testing.T) *fakeH3Edge {
	t.Helper()
	return newFakeH3EdgeWithKey(t, newTestKey(t))
}

// newFakeH3EdgeOpts allows pre-listen fixture options (quota/kill flags are
// baked into the QUIC listener config, so they must be applied before start).
func newFakeH3EdgeOpts(t *testing.T, opts func(*fakeH3Edge)) *fakeH3Edge {
	t.Helper()
	return newFakeH3EdgeWithKeyOpts(t, newTestKey(t), opts)
}

func newFakeH3EdgeWithKey(t *testing.T, key *ecdsa.PrivateKey) *fakeH3Edge {
	t.Helper()
	return newFakeH3EdgeWithKeyOpts(t, key, nil)
}

func newFakeH3EdgeWithKeyOpts(t *testing.T, key *ecdsa.PrivateKey, opts func(*fakeH3Edge)) *fakeH3Edge {
	t.Helper()
	e := &fakeH3Edge{t: t, key: key, status: 200, colo: "TST"}
	if opts != nil {
		opts(e)
	}
	uc, err := (DialPolicy{}).ListenUDP(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake h3 edge listen: %v", err)
	}
	e.addr = uc.LocalAddr().(*net.UDPAddr)
	e.tr = &quic.Transport{Conn: uc}
	tlsCfg := &tls.Config{ //nolint:gosec // test fixture: self-signed by contract
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{selfSignedDERForTest(t, key)},
			PrivateKey:  key,
		}},
		NextProtos: []string{"h3"},
	}
	conf := &quic.Config{
		EnableDatagrams:      true,
		MaxIncomingStreams:   100,
		HandshakeIdleTimeout: fakeH3HandshakeTimeout,
		MaxIdleTimeout:       fakeH3IdleTimeout,
	}
	if e.quotaZeroStreams {
		conf.MaxIncomingStreams = -1 // negative: peer may open NO bi streams
	}
	ln, err := e.tr.Listen(tlsCfg, conf)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go e.handleConn(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); e.tr.Close() })
	return e
}

// addrOf returns the UDP address of the edge (client dial target).
func (e *fakeH3Edge) addrOf() net.Addr { return e.addr }

func (e *fakeH3Edge) pinPub() *ecdsa.PublicKey { return &e.key.PublicKey }

func (e *fakeH3Edge) setBehavior(status int, drop bool, teardownAfter int, hang bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status, e.dropDatagrams, e.teardownAfterEcho, e.hangConnect = status, drop, teardownAfter, hang
}

func (e *fakeH3Edge) counters() (connects int, payloads [][]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.connects, append([][]byte(nil), e.payloads...)
}

func (e *fakeH3Edge) acceptCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.connAccepts
}

func (e *fakeH3Edge) setDelayResponse(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.delayResponse = d
}

func (e *fakeH3Edge) handleConn(conn *quic.Conn) {
	e.mu.Lock()
	e.connAccepts++
	kill := e.killImmediately
	e.mu.Unlock()
	if kill {
		// Clean remote shutdown (AppError 0): the design §4 retriable family.
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "kill fixture")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fakeH3IdleTimeout)
	defer cancel()
	if _, err := acceptControlStreams(ctx, conn); err != nil {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0x01), "control stream failed")
		return
	}
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		if !e.handleConnect(conn, stream, ctx) {
			return
		}
	}
}

// handleConnect answers one extended-CONNECT bi-stream; false = kill conn.
func (e *fakeH3Edge) handleConnect(conn *quic.Conn, stream *quic.Stream, ctx context.Context) bool {
	e.mu.Lock()
	e.connects++
	status, drop, teardownAfter, hang := e.status, e.dropDatagrams, e.teardownAfterEcho, e.hangConnect
	colo := e.colo
	e.mu.Unlock()

	fr := newH3Framer(stream)
	typ, payload, err := fr.ReadKnownFrame(map[uint64]bool{h3FrameHeaders: true})
	if err != nil || typ != h3FrameHeaders {
		return false
	}
	fields, derr := DecodeFieldSection(payload)
	if derr != nil || len(fields) < 2 {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0x02), "bad CONNECT headers")
		return false
	}
	if fields[0] != ([2]string{":method", "CONNECT"}) {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0x02), "not a CONNECT")
		return false
	}

	if hang {
		<-ctx.Done() // never answer: the client budget must fire first
		return false
	}
	if delay := func() time.Duration {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.delayResponse
	}(); delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return false
		}
	}

	wr := &qpackWriter{}
	wr.b = appendQPACKInt(wr.b, 0x00, 8, 0)
	wr.b = appendQPACKInt(wr.b, 0x00, 7, 0)
	switch status {
	case 200:
		wr.b = append(wr.b, 0xC0|qpackIdxStatus200) // indexed static :status 200 -> 0xD9
	default:
		wr.encodeLiteralNameLine(":status", fmt.Sprintf("%d", status))
	}
	wr.encodeLiteralNameLine("cf-warp-colo", colo)
	if _, err := stream.Write(appendH3Headers(nil, wr.b)); err != nil {
		return false
	}
	if status != 200 {
		return true // stream ends; conn lives for the next attempt
	}

	echoed := 0
	for teardownAfter <= 0 || echoed < teardownAfter {
		dg, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return false
		}
		qsid, cid, pkt, uerr := UnwrapH3Datagram(dg)
		if uerr != nil {
			continue // tolerate malformed inbound, Aether-style skip
		}
		e.mu.Lock()
		e.payloads = append(e.payloads, append([]byte(nil), pkt...))
		e.mu.Unlock()
		if drop {
			continue
		}
		if err := conn.SendDatagram(WrapH3Datagram(qsid*4, cid, pkt)); err != nil {
			return false
		}
		echoed++
		if teardownAfter > 0 && echoed >= teardownAfter {
			_ = conn.CloseWithError(quic.ApplicationErrorCode(0x03), "teardown mid-stream")
			return false
		}
	}
	return true
}

// ---- test-side minimal-H3 driver (EH2 will productize this shape) ----

// pinRecorder captures the raw VerifyPeerCertificate outcome so assertions do
// not depend on how quic-go wraps handshake failures.
type pinRecorder struct {
	mu  sync.Mutex
	err error
}

func (p *pinRecorder) store(err error) { p.mu.Lock(); p.err = err; p.mu.Unlock() }

func (p *pinRecorder) load() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// verifyPin mirrors the tlsconf.go leaf-pubkey equality contract for the h3
// driver (EH2 will share one production implementation).
func verifyPin(rawCerts [][]byte, pin *ecdsa.PublicKey) error {
	if len(rawCerts) == 0 {
		return ErrBadEndpointCert
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadEndpointCert, err)
	}
	leafPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrPinNotECDSA
	}
	if leafPub.Equal(pin) {
		return nil
	}
	return ErrPinMismatch
}

type h3TestClient struct {
	conn   *quic.Conn
	stream *quic.Stream
	tr     *quic.Transport
	pins   *pinRecorder
	Status int
	Colo   string
	Fields [][2]string
}

// dialH3TestClient dials the edge, opens control+CONNECT streams, sends the
// request headers and returns without reading the response.
func dialH3TestClient(t *testing.T, addr net.Addr, sni string, pin *ecdsa.PublicKey, authority string, extra [][2]string) *h3TestClient {
	t.Helper()
	cl, _, err := tryDialH3TestClient(t, addr, sni, pin, authority, extra)
	if err != nil {
		t.Fatalf("dial: %v (pinErr=%v)", err, cl.pins.load())
	}
	return cl
}

// tryDialH3TestClient is the non-fatal variant used by fail-closed tests.
func tryDialH3TestClient(t *testing.T, addr net.Addr, sni string, pin *ecdsa.PublicKey, authority string, extra [][2]string) (*h3TestClient, error, error) {
	t.Helper()
	clientKey := newTestKey(t)
	cert, err := ClientCertificate(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	rec := &pinRecorder{}
	tlsCfg := &tls.Config{ //nolint:gosec // pinned-peer scheme; ALPN differs from PrepareTLSConfig
		Certificates:       []tls.Certificate{cert},
		ServerName:         sni,
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			err := verifyPin(rawCerts, pin)
			rec.store(err)
			return err
		},
	}
	uc, err := (DialPolicy{}).ListenUDP(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: uc, ConnectionIDLength: 20} // CID20 mandatory (design §1 / usque)
	conf := &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: fakeH3HandshakeTimeout,
		MaxIdleTimeout:       fakeH3IdleTimeout,
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, derr := tr.Dial(dialCtx, addr, tlsCfg, conf)
	if derr != nil {
		_ = tr.Close()
		return &h3TestClient{pins: rec}, derr, rec.load()
	}
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		_ = tr.Close()
		return &h3TestClient{pins: rec}, err, rec.load()
	}
	if _, err := ctrl.Write(WriteControlPreamble()); err != nil {
		_ = tr.Close()
		return &h3TestClient{pins: rec}, err, rec.load()
	}
	st, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		_ = tr.Close()
		return &h3TestClient{pins: rec}, err, rec.load()
	}
	if _, err := st.Write(appendH3Headers(nil, EncodeConnectFieldSection(authority, extra))); err != nil {
		_ = tr.Close()
		return &h3TestClient{pins: rec}, err, rec.load()
	}
	cl := &h3TestClient{conn: conn, stream: st, tr: tr, pins: rec}
	t.Cleanup(func() { _ = cl.conn.CloseWithError(0, "test done"); _ = cl.tr.Close() })
	return cl, nil, nil
}

// readResponse awaits the CONNECT response headers under ctx.
func (c *h3TestClient) readResponse(ctx context.Context) error {
	type readResult struct {
		typ     uint64
		payload []byte
		err     error
	}
	out := make(chan readResult, 1)
	go func() {
		fr := newH3Framer(c.stream)
		typ, payload, err := fr.ReadKnownFrame(map[uint64]bool{h3FrameHeaders: true, h3FrameData: true})
		out <- readResult{typ, payload, err}
	}()
	select {
	case r := <-out:
		if r.err != nil {
			return r.err
		}
		if r.typ != h3FrameHeaders {
			return fmt.Errorf("expected HEADERS, got %#x", r.typ)
		}
		fields, err := DecodeFieldSection(r.payload)
		if err != nil {
			return err
		}
		c.Fields = fields
		for _, kv := range fields {
			if kv[0] == ":status" {
				fmt.Sscanf(kv[1], "%d", &c.Status) //nolint:errcheck // numeric by protocol
			}
			if kv[0] == "cf-warp-colo" {
				c.Colo = kv[1]
			}
		}
		if c.Status == 0 {
			return errors.New("response without :status")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *h3TestClient) sendDatagram(pkt []byte) error {
	return c.conn.SendDatagram(WrapH3Datagram(uint64(c.stream.StreamID()), 0, pkt))
}

func (c *h3TestClient) receiveDatagram(ctx context.Context) ([]byte, error) {
	dg, err := c.conn.ReceiveDatagram(ctx)
	if err != nil {
		return nil, err
	}
	_, _, pkt, err := UnwrapH3Datagram(dg)
	return pkt, err
}

// ---- matrix tests (§66 analog for H3) ----

func h3Ctx(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestFakeH3HappyEcho(t *testing.T) {
	e := newFakeH3Edge(t)
	cl := dialH3TestClient(t, e.addrOf(), DefaultSNI, e.pinPub(),
		AuthorityForEndpoint("162.159.198.2", 443),
		[][2]string{{"cf-connect-proto", "cf-connect-ip"}, {"pq-enabled", "false"}})
	if err := cl.readResponse(h3Ctx(t, 3*time.Second)); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if cl.Status != 200 || cl.Colo != "TST" {
		t.Fatalf("status=%d colo=%q", cl.Status, cl.Colo)
	}
	pkt := []byte{0x45, 0x00, 0x00, 0x18, 0xAA, 0xBB}
	for i := 0; i < 3; i++ {
		if err := cl.sendDatagram(pkt); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		got, err := cl.receiveDatagram(h3Ctx(t, 2*time.Second))
		if err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
		if string(got) != string(pkt) {
			t.Fatalf("echo %d mismatch: % x", i, got)
		}
	}
	if n, payloads := e.counters(); n != 1 || len(payloads) != 3 {
		t.Fatalf("server counters: connects=%d payloads=%d", n, len(payloads))
	}
}

func TestFakeH3Reject403(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior(403, false, 0, false)
	cl := dialH3TestClient(t, e.addrOf(), DefaultSNI, e.pinPub(), AuthorityForEndpoint("162.159.198.1", 443), nil)
	if err := cl.readResponse(h3Ctx(t, 3*time.Second)); err != nil {
		t.Fatalf("read: %v", err)
	}
	if cl.Status != 403 {
		t.Fatalf("status=%d want 403", cl.Status)
	}
}

func TestFakeH3SilentDropKeepsConnOpen(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior(200, true, 0, false) // control OK, data swallowed: the DPI class
	cl := dialH3TestClient(t, e.addrOf(), DefaultSNI, e.pinPub(), AuthorityForEndpoint("162.159.198.1", 443), nil)
	if err := cl.readResponse(h3Ctx(t, 3*time.Second)); err != nil || cl.Status != 200 {
		t.Fatalf("control phase: status=%d err=%v", cl.Status, err)
	}
	if err := cl.sendDatagram([]byte{0x45, 0, 0, 8}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_, err := cl.receiveDatagram(h3Ctx(t, 400*time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline-exceeded (silent drop), got %v", err)
	}
	// Connection itself must still be alive (control accepted, no teardown).
	if err := cl.sendDatagram([]byte{0x45, 0, 0, 8}); err != nil {
		t.Fatalf("conn died on silent drop: %v", err)
	}
}

func TestFakeH3TeardownMidStream(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior(200, false, 2, false)
	cl := dialH3TestClient(t, e.addrOf(), DefaultSNI, e.pinPub(), AuthorityForEndpoint("162.159.198.1", 443), nil)
	if err := cl.readResponse(h3Ctx(t, 3*time.Second)); err != nil || cl.Status != 200 {
		t.Fatalf("control phase: %d %v", cl.Status, err)
	}
	pkt := []byte{0x45, 0, 0, 12}
	var lastErr error
	for i := 0; i < 4; i++ {
		if err := cl.sendDatagram(pkt); err != nil {
			lastErr = err
			break
		}
		_, err := cl.receiveDatagram(h3Ctx(t, 1500*time.Millisecond))
		lastErr = err
		if err != nil {
			break
		}
	}
	if lastErr == nil || errors.Is(lastErr, context.DeadlineExceeded) {
		t.Fatalf("teardown must surface as an error, got %v", lastErr)
	}
}

func TestFakeH3HangConnectTimesOutOnBudget(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior(200, false, 0, true)
	cl := dialH3TestClient(t, e.addrOf(), DefaultSNI, e.pinPub(), AuthorityForEndpoint("162.159.198.1", 443), nil)
	err := cl.readResponse(h3Ctx(t, 600*time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hang must be bounded by the client budget, got %v", err)
	}
}

// Wrong pin must fail closed inside VerifyPeerCertificate regardless of how
// quic-go wraps the TLS failure.
func TestFakeH3WrongPinFailClosed(t *testing.T) {
	e := newFakeH3Edge(t)
	stranger := newTestKey(t)
	cl, dialErr, pinErr := tryDialH3TestClient(t, e.addrOf(), DefaultSNI, &stranger.PublicKey,
		AuthorityForEndpoint("162.159.198.2", 443), nil)
	if dialErr == nil {
		t.Fatal("dial with stranger pin must not succeed")
	}
	if !errors.Is(pinErr, ErrPinMismatch) {
		t.Fatalf("pin recorder = %v, want ErrPinMismatch", pinErr)
	}
	_ = cl
}

// A dead UDP path must surface as a bounded handshake timeout — the future
// udp-blocked/handshake-fail ladder classification input (design §6).
func TestFakeH3BlackholeTimesOut(t *testing.T) {
	dead, err := net.ListenPacket("udp4", "127.0.0.1:0") // occupy then release a port
	if err != nil {
		t.Fatal(err)
	}
	port := dead.LocalAddr().(*net.UDPAddr).Port
	dead.Close()
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	k := newTestKey(t)
	_, dialErr, _ := tryDialH3TestClient(t, target, DefaultSNI, &k.PublicKey,
		AuthorityForEndpoint("162.159.198.1", 443), nil)
	if dialErr == nil {
		t.Fatal("blackhole must not complete the handshake")
	}
	msg := dialErr.Error()
	if !strings.Contains(strings.ToLower(msg), "timeout") && !strings.Contains(strings.ToLower(msg), "no recent network activity") {
		t.Fatalf("timeout-class error expected, got: %v", msg)
	}
}
