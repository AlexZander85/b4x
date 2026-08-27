package transportwarp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// fakeServer implements the §66 integration matrix offline: a real HTTP/2
// CONNECT endpoint with configurable failure behaviour, speaking the same
// capsule framing as the production path.
type fakeServer struct {
	t   *testing.T
	ln  net.Listener
	key *ecdsa.PrivateKey

	mu              sync.Mutex
	status          int  // CONNECT response status (default 200)
	dropData        bool // accept control, never echo back (silent-DPI class)
	echoForeignCaps bool
	teardownAfter   int                         // echo N packets then hard-close the stream
	dropEvery       int                         // lossy fixture: drop every Nth capsule (0 = off)
	rejectNext      int                         // refuse the next N CONNECT requests with 500 (flap fixture)
	echoDelay       time.Duration               // artificial per-capsule echo delay (RTT fixture)
	connectDelay    time.Duration               // artificial delay before the CONNECT response headers
	respond         func(payload []byte) []byte // replaces echo when set
	colo            string                      // cf-warp-colo telemetry value served on success
	echoed          int
	capsulesSeen    int
	connects        int
	active          int      // live accepted conns; drives M-01's leak assertion
	payloads        [][]byte // every DATAGRAM payload received, in order
}

// setLossy configures the every-Nth-capsule drop fixture.
func (f *fakeServer) setLossy(n int) {
	f.mu.Lock()
	f.dropEvery = n
	f.mu.Unlock()
}

// setRejectNext makes the next N CONNECT attempts fail with 500.
func (f *fakeServer) setRejectNext(n int) {
	f.mu.Lock()
	f.rejectNext = n
	f.mu.Unlock()
}

// setEchoDelay installs an artificial echo delay (RTT ranking fixture).
func (f *fakeServer) setEchoDelay(d time.Duration) {
	f.mu.Lock()
	f.echoDelay = d
	f.mu.Unlock()
}

// setConnectDelay installs an artificial delay before the CONNECT response
// headers are written (M-01 fixture: lets the client abort a pause that the
// server is still holding open).
func (f *fakeServer) setConnectDelay(d time.Duration) {
	f.mu.Lock()
	f.connectDelay = d
	f.mu.Unlock()
}

// activeConns reports the number of CONNECT handlers currently running.
// A connection leaks (M-01) when the client never closes its h2 conn and the
// handler never returns, keeping this > 0.
func (f *fakeServer) activeConns() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active
}

// setResponder replaces the echo with a computed reply per payload
// (DNS-in-tunnel fixture). Returning nil drops the packet.
func (f *fakeServer) setResponder(fn func(payload []byte) []byte) {
	f.mu.Lock()
	f.respond = fn
	f.mu.Unlock()
}

// receivedPayloads returns a copy of the payload log (oldest first).
func (f *fakeServer) receivedPayloads() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.payloads...)
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	key := newTestKey(t)
	return newFakeServerWithKey(t, key)
}

// newFakeServerWithKey lets a test pin the SAME endpoint key as another
// fixture (e.g. the registration API's served pin) so supervisor-level flows
// pass endpoint pin verification.
func newFakeServerWithKey(t *testing.T, key *ecdsa.PrivateKey) *fakeServer {
	t.Helper()
	return newFakeServerTLS(t, key, []string{"h2"})
}

// newFakeServerALPN builds an endpoint that negotiates the given TLS ALPN
// values (M-03): offering e.g. http/1.1 makes DialSession's ALPN check fire
// and yields an H2-negotiation failure class.
func newFakeServerALPN(t *testing.T, key *ecdsa.PrivateKey, alpn []string) *fakeServer {
	t.Helper()
	return newFakeServerTLS(t, key, alpn)
}

func newFakeServerTLS(t *testing.T, key *ecdsa.PrivateKey, nextProtos []string) *fakeServer {
	t.Helper()
	fs := &fakeServer{t: t, status: 200, key: key, colo: "TEST"}
	certDER := selfSignedDERForTest(t, fs.key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  fs.key,
		}},
		NextProtos: nextProtos,
	})
	if err != nil {
		t.Fatal(err)
	}
	fs.ln = ln
	go fs.serve()
	return fs
}

func (f *fakeServer) addr() netip.AddrPort {
	return netip.MustParseAddrPort(f.ln.Addr().String())
}

func (f *fakeServer) pinPub() *ecdsa.PublicKey { return &f.key.PublicKey }

func (f *fakeServer) setBehavior(status int, dropData bool, foreign bool, teardownAfter int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.dropData, f.echoForeignCaps, f.teardownAfter = status, dropData, foreign, teardownAfter
}

func (f *fakeServer) counters() (connects, capsules int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connects, f.capsulesSeen
}

func (f *fakeServer) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			// Go 1.25: tls.Conn.ConnectionState() no longer forces the
			// handshake; x/net/http2 ServeConn reads it before the first
			// Read and would see a zero Version ("TLS version too low").
			// Complete the handshake explicitly first.
			if tc, ok := c.(*tls.Conn); ok {
				if err := tc.Handshake(); err != nil {
					_ = c.Close()
					return
				}
			}
			h2s := &http2.Server{}
			h2s.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(f.handle)})
		}(conn)
	}
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.connects++
	f.active++
	status, teardownAfter := f.status, f.teardownAfter
	defer func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}()
	connectDelay := f.connectDelay
	if f.rejectNext > 0 {
		f.rejectNext--
		f.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, 1009, "flap fixture")
		return
	}
	f.mu.Unlock()

	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if connectDelay > 0 {
		// Hold the CONNECT response open so a quick-aborting client can
		// outrace it; the raw conn is still alive at the server side.
		select {
		case <-time.After(connectDelay):
		case <-r.Context().Done():
			return
		}
	}
	f.mu.Lock()
	colo := f.colo
	f.mu.Unlock()
	w.Header().Set("cf-warp-colo", colo)
	w.WriteHeader(status)
	if status != http.StatusOK {
		// Return immediately: the h2 server ends the stream (END_STREAM on
		// handler exit). Draining r.Body here would block forever on an
		// open client pipe and starve the error response.
		time.Sleep(20 * time.Millisecond) // let headers reach the client first
		return
	}
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}

	buf := make([]byte, 16<<10)
	var pending []byte
	streamSeq := 0 // capsules seen on THIS stream (for drop-every-N)
	for {
		typ, length, hl, complete := parseCapsuleFrom(pending)
		if !(complete && len(pending) >= hl+length) {
			n, err := r.Body.Read(buf)
			if n > 0 {
				pending = append(pending, buf[:n]...)
			}
			if n == 0 && err != nil {
				return // stream closed by client or aborted
			}
			continue
		}
		payload := append([]byte(nil), pending[hl:hl+length]...)
		pending = pending[hl+length:]
		if typ != 0 {
			continue
		}

		// Re-read behavior flags per capsule so tests can flip them on a
		// LIVE connection (mid-session silent-drop fixtures).
		var doTeardown bool
		var echoDelay time.Duration
		var respFn func(payload []byte) []byte
		dropThis := false
		f.mu.Lock()
		f.capsulesSeen++
		f.payloads = append(f.payloads, append([]byte(nil), payload...))
		doTeardown = teardownAfter > 0 && f.echoed >= teardownAfter
		dropNow := f.dropData
		foreignNow := f.echoForeignCaps
		echoDelay = f.echoDelay
		respFn = f.respond
		if f.dropEvery > 0 {
			streamSeq++
			dropThis = streamSeq%f.dropEvery == 0
		}
		f.echoed++
		f.mu.Unlock()

		if doTeardown {
			_ = r.Body.Close()
			panic(http.ErrAbortHandler) // abrupt mid-stream teardown fixture
		}
		if dropNow {
			continue // swallow payloads: silent-DPI fixture
		}
		if echoDelay > 0 {
			time.Sleep(echoDelay) // RTT ranking fixture; outside the lock
		}
		if dropThis {
			continue // lossy fixture: every Nth capsule vanishes
		}

		outPayload := payload
		if respFn != nil {
			outPayload = respFn(payload)
			if len(outPayload) == 0 {
				continue // responder chose to drop
			}
		}
		if foreignNow {
			frame := AppendVarint(nil, 7) // unknown type must be skipped inbound
			frame = AppendVarint(frame, uint64(len(outPayload)))
			frame = append(frame, outPayload...)
			_, _ = w.Write(frame)
		}
		out := make([]byte, 0, 10+len(outPayload))
		out = AppendVarint(out, 0)
		out = AppendVarint(out, uint64(len(outPayload)))
		out = append(out, outPayload...)
		if _, err := w.Write(out); err != nil {
			return
		}
		if fl != nil {
			fl.Flush()
		}
	}
}

func (f *fakeServer) close() { _ = f.ln.Close() }

// ---- helpers ----

func selfSignedDERForTest(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// parseCapsuleFrom mirrors session-side framing for the server side.
func parseCapsuleFrom(buf []byte) (typ, length, headerLen int, complete bool) {
	if len(buf) == 0 {
		return 0, 0, 0, false
	}
	size1 := 1 << (buf[0] >> 6)
	if len(buf) < size1 {
		return 0, 0, 0, false
	}
	tv := uint64(buf[0] & 0x3f)
	for i := 1; i < size1; i++ {
		tv = tv<<8 | uint64(buf[i])
	}
	rest := buf[size1:]
	if len(rest) == 0 {
		return 0, 0, 0, false
	}
	size2 := 1 << (rest[0] >> 6)
	if len(rest) < size2 {
		return 0, 0, 0, false
	}
	lv := uint64(rest[0] & 0x3f)
	for i := 1; i < size2; i++ {
		lv = lv<<8 | uint64(rest[i])
	}
	return int(tv), int(lv), size1 + size2, true
}
