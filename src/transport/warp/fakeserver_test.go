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
	t    *testing.T
	ln   net.Listener
	key  *ecdsa.PrivateKey

	mu         sync.Mutex
	status     int  // CONNECT response status (default 200)
	dropData   bool // accept control, never echo back (silent-DPI class)
	echoForeignCaps bool
	teardownAfter   int  // echo N packets then hard-close the stream
	echoed     int
	capsulesSeen int
	connects   int
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{t: t, status: 200}
	fs.key = newTestKey(t)
	certDER := selfSignedDERForTest(t, fs.key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  fs.key,
		}},
		NextProtos: []string{"h2"},
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
	status, drop, foreign, teardownAfter := f.status, f.dropData, f.echoForeignCaps, f.teardownAfter
	f.mu.Unlock()

	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
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

		var doTeardown bool
		f.mu.Lock()
		f.capsulesSeen++
		doTeardown = teardownAfter > 0 && f.echoed >= teardownAfter
		f.echoed++
		f.mu.Unlock()

		if doTeardown {
			_ = r.Body.Close()
			panic(http.ErrAbortHandler) // abrupt mid-stream teardown fixture
		}
		if drop {
			continue // swallow payloads: silent-DPI fixture
		}
		if foreign {
			frame := AppendVarint(nil, 7) // unknown type must be skipped inbound
			frame = AppendVarint(frame, uint64(len(payload)))
			frame = append(frame, payload...)
			_, _ = w.Write(frame)
		}
		out := make([]byte, 0, 10+len(payload))
		out = AppendVarint(out, 0)
		out = AppendVarint(out, uint64(len(payload)))
		out = append(out, payload...)
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
