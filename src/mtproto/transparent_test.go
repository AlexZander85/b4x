package mtproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

func TestReservedFirst4(t *testing.T) {
	reserved := [][]byte{
		{0xef, 0x00, 0x00, 0x00},
		{0x48, 0x45, 0x41, 0x44}, // HEAD
		{0x50, 0x4f, 0x53, 0x54}, // POST
		{0x47, 0x45, 0x54, 0x20}, // "GET "
		{0x4f, 0x50, 0x54, 0x49}, // OPTI
		{0x16, 0x03, 0x01, 0x02}, // TLS record header
		{0xdd, 0xdd, 0xdd, 0xdd},
		{0xee, 0xee, 0xee, 0xee},
	}
	for _, b := range reserved {
		if !reservedFirst4(b) {
			t.Errorf("reservedFirst4(% x) = false, want true", b)
		}
	}
	// a plausible random obfuscated prefix must not be flagged
	normal := []byte{0x01, 0x02, 0x03, 0x04}
	if reservedFirst4(normal) {
		t.Errorf("reservedFirst4(% x) = true, want false", normal)
	}
}

func TestValidTransparentDC(t *testing.T) {
	cases := []struct {
		dc   int
		want bool
	}{
		{1, true}, {2, true}, {5, true}, {203, true},
		{-1, true}, {-2, true}, {-5, true}, {-203, true},
		{0, false}, {6, false}, {99, false}, {-99, false},
	}
	for _, c := range cases {
		if got := validTransparentDC(c.dc); got != c.want {
			t.Errorf("validTransparentDC(%d) = %v, want %v", c.dc, got, c.want)
		}
	}
}

func TestPrefixConnReplaysBeforePassthrough(t *testing.T) {
	prefix := []byte("PREFIX")
	body := []byte("BODY")
	pc := &prefixConn{Conn: fakeConn{r: bytes.NewReader(body)}, prefix: append([]byte(nil), prefix...)}

	got, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	want := append(append([]byte(nil), prefix...), body...)
	if !bytes.Equal(got, want) {
		t.Errorf("prefixConn read = %q, want %q", got, want)
	}
}

func TestPrefixConnPartialReadDoesNotLosePrefix(t *testing.T) {
	prefix := []byte("ABCDEF")
	pc := &prefixConn{Conn: fakeConn{r: bytes.NewReader(nil)}, prefix: append([]byte(nil), prefix...)}
	buf := make([]byte, 2)
	var got []byte
	for {
		n, err := pc.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
		if len(got) >= len(prefix) {
			break
		}
	}
	if !bytes.Equal(got, prefix) {
		t.Errorf("got %q, want %q", got, prefix)
	}
}

// fakeConn is a minimal net.Conn backed by a reader (and optional write sink).
type fakeConn struct {
	r io.Reader
	w io.Writer
}

func (c fakeConn) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	return c.r.Read(p)
}
func (c fakeConn) Write(p []byte) (int, error) {
	if c.w == nil {
		return len(p), nil
	}
	return c.w.Write(p)
}
func (c fakeConn) Close() error                       { return nil }
func (c fakeConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (c fakeConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (c fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c fakeConn) SetWriteDeadline(t time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "1.2.3.4:5" }

func newBridge() *TransparentBridge {
	return NewTransparentBridge(&config.Config{})
}

func TestHandleEmptyConnReturnsHandledNil(t *testing.T) {
	// immediate EOF (head==0) -> connection closed, nothing to fail open with
	b := newBridge()
	handled, failover := b.Handle(fakeConn{r: bytes.NewReader(nil)}, net.ParseIP("1.2.3.4"), 443)
	if !handled || failover != nil {
		t.Fatalf("empty conn: got (handled=%v, failover=%v), want (true, nil)", handled, failover)
	}
}

func TestHandleReservedPrefixFailsOpenWithBytes(t *testing.T) {
	// non-obfuscated transport (TLS record header) -> fail open, replay the 4 bytes
	b := newBridge()
	in := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0xaa, 0xbb}
	handled, failover := b.Handle(fakeConn{r: bytes.NewReader(in)}, net.ParseIP("1.2.3.4"), 443)
	if handled {
		t.Fatalf("reserved prefix should not be handled by bridge")
	}
	if failover == nil {
		t.Fatal("reserved prefix: expected failover conn, got nil")
	}
	// failover is the original conn with the 4 read bytes re-prepended, so the
	// whole original stream must be recoverable intact for the direct dial.
	got, _ := io.ReadAll(failover)
	if !bytes.Equal(got, in) {
		t.Errorf("failover replayed % x, want full original stream % x", got, in)
	}
}

func TestHandlePartialReadFailsOpenWithBytes(t *testing.T) {
	// fewer than 4 bytes then EOF -> fail open replaying what arrived
	b := newBridge()
	in := []byte{0x01, 0x02}
	handled, failover := b.Handle(fakeConn{r: bytes.NewReader(in)}, net.ParseIP("1.2.3.4"), 443)
	if handled {
		t.Fatalf("partial read should fail open, not be handled")
	}
	if failover == nil {
		t.Fatal("partial read: expected failover conn, got nil")
	}
	got, _ := io.ReadAll(failover)
	if !bytes.Equal(got, in) {
		t.Errorf("failover replayed % x, want % x", got, in)
	}
}

func TestHandleUnresolvedDCFailsOpenWithFullFrame(t *testing.T) {
	// a full 64-byte obfuscated frame whose decoded DC is invalid and whose
	// source IP maps to no DC -> fail open replaying all 64 bytes.
	b := newBridge()
	frame := make([]byte, obfuscatedFrameLen)
	for i := range frame {
		frame[i] = byte(i + 1) // non-reserved first 4 bytes (0x01..)
	}
	// ensure first4 is not accidentally reserved and byte0 != 0xef
	if reservedFirst4(frame[:4]) {
		t.Fatal("test frame unexpectedly reserved")
	}
	handled, failover := b.Handle(fakeConn{r: bytes.NewReader(frame)}, net.ParseIP("8.8.8.8"), 443)
	if handled {
		t.Fatalf("unresolved DC should fail open, not be handled")
	}
	if failover == nil {
		t.Fatal("unresolved DC: expected failover conn, got nil")
	}
	got, _ := io.ReadAll(failover)
	if len(got) != obfuscatedFrameLen || !bytes.Equal(got, frame) {
		t.Errorf("failover replayed %d bytes, want full %d-byte frame intact", len(got), obfuscatedFrameLen)
	}
}

// parkConn simulates a client that sends nothing within the soft first-byte
// window: every Read honors the deadline set via SetReadDeadline and returns
// a timeout error (0 bytes) when it expires. Once the test pushes delayed
// bytes (closing deliver), Read returns them before the deadline.
type parkConn struct {
	fakeConn
	mu       sync.Mutex
	deadline time.Time
	deliver  chan struct{}
	delayed  []byte
}

func (c *parkConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *parkConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	if d.IsZero() || time.Now().After(d) {
		return 0, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	}
	timer := time.NewTimer(time.Until(d))
	defer timer.Stop()
	select {
	case <-c.deliver:
		c.mu.Lock()
		payload := c.delayed
		c.delayed = nil
		c.mu.Unlock()
		n := copy(p, payload)
		return n, nil
	case <-timer.C:
		return 0, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	}
}

// validObfuscatedFrame builds a 64-byte obfuscated handshake frame whose
// first 4 bytes are non-reserved and whose decoded connection tag is abridged
// with the given DC, using the same AES-CTR scheme the decoder applies.
func validObfuscatedFrame(t *testing.T, dc int) []byte {
	t.Helper()
	frame := make([]byte, obfuscatedFrameLen)
	for i := range frame {
		frame[i] = byte(i + 1) // arbitrary; key=frame[8:40], iv=frame[40:56] stay untouched
	}
	stream, err := newAESCTR(frame[8:40], frame[40:56])
	if err != nil {
		t.Fatalf("newAESCTR: %v", err)
	}
	ks := make([]byte, obfuscatedFrameLen)
	stream.XORKeyStream(ks, ks) // keystream at every offset
	binary.LittleEndian.PutUint32(frame[56:60], connectionTagAbridged^binary.LittleEndian.Uint32(ks[56:60]))
	binary.LittleEndian.PutUint16(frame[60:62], uint16(dc)^binary.LittleEndian.Uint16(ks[60:62]))
	return frame
}

func TestHandleZeroByteParksThenExpires(t *testing.T) {
	// zero bytes within the soft window, then silence up to the hard
	// deadline: the connection is parked (pending token acquired), only
	// observable cleanup happens on expiry, and the pending slot is released.
	observability.Default().Metrics.Reset()
	b := newBridge()
	b.zeroByteSoft = 30 * time.Millisecond
	b.zeroByteHard = 60 * time.Millisecond
	pc := &parkConn{deliver: make(chan struct{})}
	start := time.Now()
	handled, failover := b.Handle(pc, net.ParseIP("1.2.3.4"), 443)
	if !handled || failover != nil {
		t.Fatalf("idle conn: got (handled=%v, failover=%v), want (true, nil) after observable cleanup", handled, failover)
	}
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Errorf("parked conn closed too early: %v (soft+hard windows not honored)", elapsed)
	}
	if got := tgbCounterValue(t, observability.MetricMTProtoIdlePreconnectExpired); got == 0 {
		t.Error("idle_preconnect_expired counter not incremented on hard-deadline cleanup")
	}
	if b.pending.Len() != 0 {
		t.Errorf("pending token not released after expiry: %d slots busy", b.pending.Len())
	}
}

func TestHandleZeroByteDelayedFirstByteContinues(t *testing.T) {
	// a first byte arriving after the soft window must NOT drop the
	// connection: the parked conn is resumed and the handshake continues.
	observability.Default().Metrics.Reset()
	b := newBridge()
	b.zeroByteSoft = 30 * time.Millisecond
	b.zeroByteHard = 500 * time.Millisecond
	pc := &parkConn{deliver: make(chan struct{})}
	go func() {
		time.Sleep(60 * time.Millisecond) // after the soft window
		pc.mu.Lock()
		pc.delayed = []byte{0x16, 0x03, 0x01, 0x02} // reserved TLS-like prefix
		close(pc.deliver)
		pc.mu.Unlock()
	}()
	handled, failover := b.Handle(pc, net.ParseIP("1.2.3.4"), 443)
	if handled {
		t.Fatal("delayed first byte must not be dropped by the bridge")
	}
	if failover == nil {
		t.Fatal("delayed first byte: expected failover conn")
	}
	got, _ := io.ReadAll(failover)
	want := []byte{0x16, 0x03, 0x01, 0x02}
	if !bytes.Equal(got, want) {
		t.Errorf("failover replayed % x, want delayed bytes % x intact", got, want)
	}
	if got := tgbCounterValue(t, observability.MetricMTProtoIdlePreconnectExpired); got != 0 {
		t.Errorf("idle_preconnect_expired must not move when bytes arrive late: %d", got)
	}
	if b.pending.Len() != 0 {
		t.Errorf("pending token not released after handoff: %d slots busy", b.pending.Len())
	}
}

func TestHandleZeroByteOverflowFailsOpen(t *testing.T) {
	// pending budget exhausted -> fail open, never a silent drop, and the
	// overflow carries an explicit budget attribution.
	b := newBridge()
	b.zeroByteSoft = 20 * time.Millisecond
	b.zeroByteHard = 200 * time.Millisecond
	for i := 0; i < 128; i++ {
		if _, err := b.pending.Acquire("client-"+string(rune('a'+i%26))+string(rune('0'+i%10)), time.Now()); err != nil {
			t.Fatalf("pre-fill acquire %d: %v", i, err)
		}
	}
	pc := &parkConn{deliver: make(chan struct{})}
	handled, failover := b.Handle(pc, net.ParseIP("1.2.3.4"), 443)
	if handled {
		t.Fatal("pending overflow must fail open, not be handled")
	}
	if failover == nil {
		t.Fatal("pending overflow: expected failover conn")
	}
	got, _ := io.ReadAll(failover)
	if len(got) != 0 {
		t.Errorf("overflow failover replayed %d bytes, want 0 (nothing was read)", len(got))
	}
}

func TestHandleDialFailureFailsOpenWithFullFrame(t *testing.T) {
	// a valid obfuscated handshake whose primary-route dial fails must not
	// be silently dropped: the full 64-byte frame is handed back so the
	// listener route ladder (worker -> direct) fails open.
	observability.Default().Metrics.Reset()
	b := newBridge()
	orig := dialDC
	dialDC = func(cfg *config.MTProtoConfig, queueCfg config.QueueConfig, dc int, protoTag uint32, pool *wsPool, logID string) (*ObfuscatedConn, string, error) {
		return nil, "", errors.New("forced primary failure")
	}
	t.Cleanup(func() { dialDC = orig })

	frame := validObfuscatedFrame(t, 2)
	handled, failover := b.Handle(fakeConn{r: bytes.NewReader(frame)}, net.ParseIP("8.8.8.8"), 443)
	if handled {
		t.Fatal("dial failure must fail open, not be silently dropped")
	}
	if failover == nil {
		t.Fatal("dial failure: expected failover conn")
	}
	got, _ := io.ReadAll(failover)
	if !bytes.Equal(got, frame) {
		t.Errorf("failover replayed %d bytes, want full %d-byte frame intact", len(got), len(frame))
	}
	if got := tgbCounterValue(t, observability.MetricMTProtoPrimaryFailureSilentDrop); got != 0 {
		t.Errorf("primary_failure_silent_drop must stay 0 after fail-open: %d", got)
	}
	if got := tgbCounterValue(t, observability.MetricMTProtoRouteRecursion); got != 0 {
		t.Errorf("route_recursion must stay 0 for the default plan: %d", got)
	}
}
