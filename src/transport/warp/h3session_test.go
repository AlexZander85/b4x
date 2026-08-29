package transportwarp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
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

// ---- PATCH-10 (M-5): local socket errors are never network verdicts ----

func TestClassifyUDPListenError(t *testing.T) {
	local := []error{
		&net.OpError{Op: "listen", Err: &os.SyscallError{Syscall: "socket", Err: syscall.EPERM}},
		&net.OpError{Op: "listen", Err: &os.SyscallError{Syscall: "bind", Err: syscall.EACCES}},
		&net.OpError{Op: "listen", Err: &os.SyscallError{Syscall: "bind", Err: syscall.EADDRNOTAVAIL}},
		&net.OpError{Op: "listen", Err: &os.SyscallError{Syscall: "bind", Err: syscall.EADDRINUSE}},
		&net.OpError{Op: "listen", Err: &os.SyscallError{Syscall: "socket", Err: syscall.EAFNOSUPPORT}},
		// wrapped deeper: OpError -> SyscallError -> syscall via fmt
		fmt.Errorf("udp listen: %w", &net.OpError{Op: "listen", Err: &os.SyscallError{Syscall: "bind", Err: syscall.EPERM}}),
	}
	for i, err := range local {
		if got := classifyUDPListenError(err); got != FailureLocalSocket {
			t.Fatalf("case %d: class = %s, want %s", i, got, FailureLocalSocket)
		}
	}
	other := []error{
		errors.New("some exotic failure"),
		&net.OpError{Op: "listen", Err: &os.SyscallError{Syscall: "socket", Err: errors.New("oom-ish")}},
		nil,
	}
	for i, err := range other {
		if got := classifyUDPListenError(err); got != FailureUDPEgressBlocked {
			t.Fatalf("other case %d: class = %s, want %s", i, got, FailureUDPEgressBlocked)
		}
	}
}

// The ladder must treat a local-socket verdict like the pin family: no
// switch, no H2 masking, no gate poisoning.
func TestLadderLocalSocketErrorDoesNotSwitch(t *testing.T) {
	h := newSupHarness(t)
	scfg := ladderKeyMaterial(t, h)
	var ctr h3AttemptCounter
	h2Calls := 0
	d, _ := newTestLadder(t, func(c *LadderConfig) {
		c.DialH3 = ctr.fail(FailureLocalSocket)
		c.DialH2 = func(context.Context, SessionConfig) (*Session, ConnectResult, error) {
			h2Calls++
			return nil, ConnectResult{}, errors.New("h2 must not be attempted")
		}
	})
	ctx := context.Background()
	for gen := 1; gen <= 2; gen++ {
		_, att, err := d.Dial(ctx, scfg)
		if err == nil || att.Transport != TransportH3 || len(att.Events) != 0 {
			t.Fatalf("gen %d: att=%+v err=%v", gen, att, err)
		}
	}
	if h2Calls != 0 {
		t.Fatalf("H2 attempted on a local fault %d times", h2Calls)
	}
	if m := d.Metrics(); m.FallbackToH2 != 0 || m.Switches != 0 || m.H3Blocked {
		t.Fatalf("metrics = %+v — the gate must stay untouched", m)
	}
}

// ---- PATCH-11 (M-6): quic error types classify via errors.As ----

func TestClassifyQuicErrorTypes(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("dial: %w", err) }
	idle := &quic.IdleTimeoutError{}
	hsTO := &quic.HandshakeTimeoutError{}
	ssReset := &quic.StatelessResetError{}

	for name, err := range map[string]error{"idle": idle, "handshake-timeout": hsTO, "stateless-reset": ssReset} {
		if !isRetriableH3Failure(wrap(err)) {
			t.Fatalf("%s: must be retriable (was dead-code before PATCH-11)", name)
		}
		if got := classifyH3HandshakeError(wrap(err)); got != FailureUDPEgressBlocked {
			t.Fatalf("%s: handshake class = %s", name, got)
		}
	}
	if got := classifyH3ResponseError(wrap(idle)); got != FailureQUICProtocolViolation {
		t.Fatalf("response idle class = %s, want %s", got, FailureQUICProtocolViolation)
	}
}

// ---- PATCH-12 (M-17): remote CRYPTO_ERROR 0x131 is a pin verdict ----

func TestHandshakeCryptoAccessDeniedIsPinVerdict(t *testing.T) {
	remote := fmt.Errorf("dial: %w", &quic.TransportError{
		ErrorCode: quic.TransportErrorCode(0x131), Remote: true,
	})
	if got := classifyH3HandshakeError(remote); got != FailureTLSPin {
		t.Fatalf("remote 0x131 class = %s, want %s", got, FailureTLSPin)
	}
	// Never retriable, never a switch class: fail-closed.
	if isRetriableH3Failure(remote) {
		t.Fatal("pin verdict must not be retriable")
	}
	if isLadderSwitchClass(FailureTLSPin) {
		t.Fatal("pin verdict must not switch transports")
	}
	// Local (non-remote) 0x131 is a local crypto problem, not an identity verdict.
	local := fmt.Errorf("dial: %w", &quic.TransportError{
		ErrorCode: quic.TransportErrorCode(0x131), Remote: false,
	})
	if got := classifyH3HandshakeError(local); got == FailureTLSPin {
		t.Fatal("local 0x131 must not be a pin verdict")
	}
}

// ---- PATCH-13 (M-16): defaults match the design KPI ----

func TestH3Defaults(t *testing.T) {
	cfg := H3SessionConfig{}
	cfg.fillDefaults()
	if cfg.HandshakeBudget != DefaultHandshakeBudget {
		t.Fatalf("HandshakeBudget default = %v, want %v", cfg.HandshakeBudget, DefaultHandshakeBudget)
	}
	if cfg.ResponseBudget != DefaultH3ResponseBudget {
		t.Fatalf("ResponseBudget default = %v, want %v", cfg.ResponseBudget, DefaultH3ResponseBudget)
	}
	if cfg.HandshakeBudget != 10*time.Second {
		t.Fatalf("HandshakeBudget = %v, want the KPI 10s bound", cfg.HandshakeBudget)
	}
}

// ---- PATCH-19 (M-8 / B-H3): ironclad-lite E2EProbe slot ----

// TestE2EProbeSlotFailsValidation: a configured probe runs inside the
// validation window; its failure fails the validation (fail-closed); with a
// nil probe the behavior is byte-identical to the pre-slot baseline.
func TestE2EProbeSlotFailsValidation(t *testing.T) {
	e := newFakeH3Edge(t)
	probeRan := false
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) {
		c.E2EProbe = func(ctx context.Context, sess *H3Session) error {
			probeRan = true
			return errors.New("inner path silent end-to-end")
		}
	})
	sess, res, err := DialH3Session(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dial: %v (class=%s)", err, res.FailureClass)
	}
	defer sess.Close()
	vctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	verr := sess.ValidateDataPlane(vctx)
	if verr == nil {
		t.Fatal("validation must fail when the e2e probe fails")
	}
	if !strings.Contains(verr.Error(), FailureValidation) || !strings.Contains(verr.Error(), "e2e probe") {
		t.Fatalf("verdict = %v, want the validation-family e2e class", verr)
	}
	if !probeRan {
		t.Fatal("the probe never ran")
	}
	select {
	case <-sess.Done():
	default:
		t.Fatal("a failed validation must tear the session down")
	}
}

// TestE2EProbeSlotNilIsBaseline: the nil probe is the disabled default.
func TestE2EProbeSlotNilIsBaseline(t *testing.T) {
	e := newFakeH3Edge(t)
	cfg := h3SessionCfg(t, e, nil)
	sess, res, err := DialH3Session(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dial: %v (class=%s)", err, res.FailureClass)
	}
	defer sess.Close()
	vctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sess.ValidateDataPlane(vctx); err != nil {
		t.Fatalf("nil probe changed the baseline validation: %v", err)
	}
}

// ---- PATCH-21 (M-13): pooled uplink frames are byte-exact and race-free ----

// TestWritePacketPoolRoundTrip hammers the pooled datagram path: 1000
// ping-pong round trips against the echo edge must deliver every packet
// byte-for-byte (no use-after-put corruption, no truncation), green under
// -race as well. Stop-and-wait keeps the primary queue's honest
// drop-instead-of-block discipline out of the way of the corruption check.
func TestWritePacketPoolRoundTrip(t *testing.T) {
	e := newFakeH3Edge(t)
	cfg := h3SessionCfg(t, e, nil)
	sess, res, err := DialH3Session(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dial: %v (class=%s)", err, res.FailureClass)
	}
	defer sess.Close()

	vctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for i := 0; i < 1000; i++ {
		want := testV4Packet(20 + i%600) // varying sizes across the pool
		if err := sess.WritePacket(want); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got, rerr := sess.ReadPacket(vctx)
		if rerr != nil {
			t.Fatalf("echo %d: %v", i, rerr)
		}
		if string(got) != string(want) {
			t.Fatalf("packet %d corrupted (pool reuse race?)", i)
		}
	}
}
