package transportwarp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// EH2 matrix: the H3 session lifecycle against the fake edge, mirroring the
// §66 analog — established+echo+trust-gate, udp-blocked, pin-mismatch,
// connect-reject, silent-drop validation, hang, quota-hang, retry-exactly-2.

func h3SessionCfg(t *testing.T, e *fakeH3Edge, mutate func(*H3SessionConfig)) H3SessionConfig {
	t.Helper()
	key := newTestKey(t)
	cfg := H3SessionConfig{
		Endpoint:        netipMustAddrPort(e.addr),
		SNI:             DefaultSNI,
		ClientKey:       key,
		Pin:             e.pinPub(),
		LocalV4:         [4]byte{100, 96, 0, 1},
		HandshakeBudget: 3 * time.Second,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

func netipMustAddrPort(a net.Addr) netip.AddrPort {
	return netip.MustParseAddrPort(a.String())
}

func TestH3SessionEstablishedEchoAndValidate(t *testing.T) {
	e := newFakeH3Edge(t)
	cfg := h3SessionCfg(t, e, nil)
	sess, res, err := DialH3Session(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dial: %v (class=%s)", err, res.FailureClass)
	}
	defer sess.Close()
	if res.Status != 200 || res.Colo != "TST" || res.FailureClass != "" {
		t.Fatalf("result = %+v", res)
	}
	vctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sess.ValidateDataPlane(vctx); err != nil {
		t.Fatalf("data-plane validation failed: %v", err)
	}
	pkt := []byte{0x45, 0x00, 0x00, 0x14, 0x01, 0x02}
	if err := sess.WritePacket(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := sess.ReadPacket(vctx)
	if err != nil || string(got) != string(pkt) {
		t.Fatalf("echo: % x %v", got, err)
	}
	c := sess.Counters()
	if c.TxPackets < 3 || c.RxPackets < 3 { // probes + explicit packet
		t.Fatalf("counters = %+v", c)
	}
}

func TestH3SessionUDPBlockedClass(t *testing.T) {
	dead, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := dead.LocalAddr().(*net.UDPAddr).Port
	dead.Close()

	e := newFakeH3Edge(t) // only for a pinned key fixture; target is the dead port
	cfg := h3SessionCfg(t, e, nil)
	cfg.Endpoint = netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(port))
	start := time.Now()
	_, res, derr := DialH3Session(context.Background(), cfg)
	if derr == nil {
		t.Fatal("blackhole must fail")
	}
	if res.FailureClass != FailureUDPEgressBlocked {
		t.Fatalf("class=%s want udp-egress-blocked (err=%v)", res.FailureClass, derr)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("udp-blocked must return fast, took %v", elapsed)
	}
}

func TestH3SessionPinMismatchFailClosed(t *testing.T) {
	stranger := newTestKey(t)
	e := newFakeH3Edge(t)
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) { c.Pin = &stranger.PublicKey })
	_, res, err := DialH3Session(context.Background(), cfg)
	if err == nil {
		t.Fatal("wrong pin must fail")
	}
	if res.FailureClass != FailureTLSPin {
		t.Fatalf("class=%s want tls-pin-mismatch", res.FailureClass)
	}
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("error chain lost pin mismatch: %v", err)
	}
}

func TestH3SessionConnectRejected403(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior(403, false, 0, false)
	cfg := h3SessionCfg(t, e, nil)
	_, res, err := DialH3Session(context.Background(), cfg)
	if err == nil {
		t.Fatal("403 must fail")
	}
	if res.Status != 403 || res.FailureClass != FailureConnectReject {
		t.Fatalf("res=%+v class=%s", res, res.FailureClass)
	}
}

func TestH3SessionSilentDropValidationTimeout(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior(200, true, 0, false)
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) {
		c.ValidateWindow = 900 * time.Millisecond
		c.ProbeInterval = 200 * time.Millisecond
	})
	sess, res, err := DialH3Session(context.Background(), cfg)
	if err != nil {
		t.Fatalf("control phase must succeed before validation: %v (%s)", err, res.FailureClass)
	}
	defer sess.Close()
	vctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
 verr := sess.ValidateDataPlane(vctx)
	if verr == nil {
		t.Fatal("silent drop must fail validation")
	}
	if !errors.Is(verr, ErrValidationTimeout) {
		t.Fatalf("want validation-timeout semantics, got %v", verr)
	}
	select {
	case <-sess.Done():
	default:
		t.Fatal("validation timeout must tear the session down")
	}
}

func TestH3SessionHangConnectBudgetFires(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior(200, false, 0, true)
	// PATCH-02: silence detection is driven by ResponseBudget — the
	// independent stall timer (B-H4) — not by the attempt budget remainder.
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) {
		c.HandshakeBudget = 5 * time.Second
		c.ResponseBudget = 700 * time.Millisecond
	})
	_, res, err := DialH3Session(context.Background(), cfg)
	if err == nil {
		t.Fatal("hang must fail on budget")
	}
	if res.FailureClass != FailureConnectTimeo {
		t.Fatalf("class=%s want connect-ip-timeout", res.FailureClass)
	}
}

// PATCH-02 (design B-H4): the response window must NOT inherit the handshake
// budget remainder — a fast handshake followed by silence gets the FULL
// ResponseBudget, not whatever is left of HandshakeBudget.
func TestH3ResponseBudgetNotInheritedFromHandshakeRemainder(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior(200, false, 0, true)
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) {
		c.HandshakeBudget = 2 * time.Second
		c.ResponseBudget = 5 * time.Second
	})
	_, res, err := DialH3Session(context.Background(), cfg)
	if err == nil {
		t.Fatal("hang must fail on response budget")
	}
	if res.FailureClass != FailureConnectTimeo {
		t.Fatalf("class=%s want connect-ip-timeout", res.FailureClass)
	}
	// Pre-fix behavior: the 2s attempt budget fired the timeout (≈2000ms).
	// The window now runs its full length from the CONNECT write.
	if res.DurationMS < 4500 {
		t.Fatalf("duration=%dms, want the full ~5s response window (not the handshake remainder)", res.DurationMS)
	}
}

// PATCH-02: a late (but valid) answer beyond the response window is a
// FailureConnectTimeo — the handshake completed, so the class must not
// slide into the handshake failure family.
func TestH3ResponseBudgetDeadlineThenLateAnswer(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior(200, false, 0, false)
	e.setDelayResponse(1200 * time.Millisecond)
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) {
		c.HandshakeBudget = 5 * time.Second
		c.ResponseBudget = 400 * time.Millisecond
	})
	_, res, err := DialH3Session(context.Background(), cfg)
	if err == nil {
		t.Fatal("late answer must miss the response window")
	}
	if res.FailureClass != FailureConnectTimeo {
		t.Fatalf("class=%s want connect-ip-timeout", res.FailureClass)
	}
}

func TestH3SessionOpenBiQuotaHang(t *testing.T) {
	e := newFakeH3EdgeOpts(t, func(f *fakeH3Edge) { f.quotaZeroStreams = true })
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) {
		c.OpenStreamBudet = 400 * time.Millisecond // real budget is 10s (design §4)
	})
	_, res, err := DialH3Session(context.Background(), cfg)
	if err == nil {
		t.Fatal("quota hang must fail on open-stream budget")
	}
	if res.FailureClass != FailureQUICStreamQuotaHang {
		t.Fatalf("class=%s want quic-stream-quota-hang", res.FailureClass)
	}
}

// Clean remote shutdown (AppError 0) belongs to the retriable family:
// exactly one reconnect attempt follows (design §4 / usque loop of 2).
func TestH3SessionRetriesExactlyTwiceOnCleanKill(t *testing.T) {
	e := newFakeH3EdgeOpts(t, func(f *fakeH3Edge) { f.killImmediately = true })
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) { c.HandshakeBudget = 2 * time.Second })
	_, res, err := DialH3Session(context.Background(), cfg)
	if err == nil {
		t.Fatal("kill fixture must never establish")
	}
	if res.FailureClass != FailureQUICProtocolViolation {
		t.Fatalf("class=%s want quic-protocol-violation", res.FailureClass)
	}
	if n := e.acceptCount(); n != 2 {
		t.Fatalf("attempts = %d, want exactly 2", n)
	}
}

// Classifier unit coverage with synthetic errors (no live conn needed).
func TestH3RetryClassification(t *testing.T) {
	retriable := []error{
		&quic.TransportError{Remote: true, ErrorCode: quic.ProtocolViolation},
		&quic.TransportError{Remote: true, ErrorCode: quic.NoError},
		&quic.ApplicationError{Remote: true}, // AppError 0
		&quic.IdleTimeoutError{},
		wrapErr(net.ErrClosed),
	}
	for i, err := range retriable {
		if !isRetriableH3Failure(err) {
			t.Errorf("case %d %v: want retriable", i, err)
		}
	}
	nonRetriable := []error{
		&quic.ApplicationError{Remote: true, ErrorCode: 49},
		errors.New("tls: access denied"),
	}
	for i, err := range nonRetriable {
		if isRetriableH3Failure(err) {
			t.Errorf("case %d %v: want non-retriable", i, err)
		}
	}
	localViolation := &quic.TransportError{Remote: false, ErrorCode: quic.ProtocolViolation}
	if isRetriableH3Failure(localViolation) {
		t.Error("local PROTOCOL_VIOLATION must not be retriable")
	}
}

type wrapErrT struct{ error }

func wrapErr(e error) error { return wrapErrT{e} }

// wrapErrT unwrapping for the chain test.
func (w wrapErrT) Unwrap() error { return w.error }
