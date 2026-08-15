package discovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/observability"
)

func completeTracker(policy ProbePolicy, body int64) ProbeOutcome {
	tracker := NewProbeTracker(policy)
	tracker.MarkDNSResolved()
	tracker.MarkTCPConnected()
	tracker.MarkTLSResponse(TLSResponseServerHello)
	tracker.MarkHTTPHeaders(http.StatusOK)
	tracker.ObserveBodyAt(body)
	tracker.MarkBodyComplete()
	return tracker.Finish()
}

func TestProbeOutcomeLayeredBodyThresholds(t *testing.T) {
	policy := DefaultProbePolicy()
	cases := []struct {
		name      string
		body      int64
		verdict   DiagnosticVerdict
		signature TransferFailureSignature
	}{
		{name: "8 KiB", body: 8 << 10, verdict: DiagnosticBodyTruncated, signature: FailureBodyTruncated},
		{name: "16 KiB", body: 16 << 10, verdict: DiagnosticBodyTruncated, signature: FailureNear16KiB},
		{name: "32 KiB", body: 32 << 10, verdict: DiagnosticAvailable, signature: FailureNone},
		{name: "128 KiB", body: 128 << 10, verdict: DiagnosticAvailable, signature: FailureNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outcome := completeTracker(policy, tc.body)
			if outcome.Verdict != tc.verdict || outcome.FailureSignature != tc.signature {
				t.Fatalf("unexpected outcome: %+v", outcome)
			}
			if outcome.BodyBytes != tc.body {
				t.Fatalf("body bytes changed: %+v", outcome)
			}
			if tc.verdict == DiagnosticBodyTruncated && (!outcome.FailureOffsetKnown || outcome.FailureOffset != tc.body) {
				t.Fatalf("body failure offset was not exact: %+v", outcome)
			}
		})
	}
}

func TestProbeOutcomeResetBeforeTLSAndTLSAlert(t *testing.T) {
	reset := NewProbeTracker(DefaultProbePolicy())
	reset.MarkDNSResolved()
	reset.MarkTCPConnected()
	reset.MarkTCPReset()
	resetOutcome := reset.Finish()
	if resetOutcome.Verdict != DiagnosticDPIRest || resetOutcome.FailureSignature != FailureBeforeTLS {
		t.Fatalf("reset before TLS was not classified at TLS layer: %+v", resetOutcome)
	}
	if !resetOutcome.FailureOffsetKnown || resetOutcome.FailureOffset != 0 {
		t.Fatalf("reset offset not persisted: %+v", resetOutcome)
	}

	alert := NewProbeTracker(DefaultProbePolicy())
	alert.MarkDNSResolved()
	alert.MarkTCPConnected()
	alert.MarkTLSResponse(TLSResponseAlert)
	alertOutcome := alert.Finish()
	if alertOutcome.Verdict != DiagnosticTLSResponseOnly || alertOutcome.FailureSignature != FailureNone {
		t.Fatalf("TLS Alert was treated as transport silence: %+v", alertOutcome)
	}
}

func TestProbeOutcomeMidstreamResetStallAndSlowValid(t *testing.T) {
	reset := NewProbeTracker(DefaultProbePolicy())
	reset.MarkDNSResolved()
	reset.MarkTCPConnected()
	reset.MarkTLSResponse(TLSResponseServerHello)
	reset.MarkHTTPHeaders(http.StatusOK)
	reset.ObserveBodyAt(12345)
	reset.MarkTCPReset()
	resetOutcome := reset.Finish()
	if resetOutcome.Verdict != DiagnosticMidstreamReset || resetOutcome.FailureOffset != 12345 {
		t.Fatalf("midstream reset not exact: %+v", resetOutcome)
	}

	stall := NewProbeTracker(DefaultProbePolicy())
	stall.MarkDNSResolved()
	stall.MarkTCPConnected()
	stall.MarkTLSResponse(TLSResponseServerHello)
	stall.MarkHTTPHeaders(http.StatusOK)
	stall.ObserveBodyAt(8192)
	stall.MarkStall()
	stallOutcome := stall.Finish()
	if stallOutcome.Verdict != DiagnosticThrottled || stallOutcome.FailureSignature != FailureStall {
		t.Fatalf("stall was not throttled: %+v", stallOutcome)
	}

	fixed := clock.NewFixed(time.Unix(100, 0))
	slow := NewProbeTracker(ProbePolicy{Clock: fixed, MinThroughputBps: 1000})
	slow.MarkDNSResolved()
	slow.MarkTCPConnected()
	fixed.Advance(time.Second)
	slow.MarkTLSResponse(TLSResponseServerHello)
	slow.MarkHTTPHeaders(http.StatusOK)
	fixed.Advance(2 * time.Second)
	slow.ObserveBodyAt(32 << 10)
	slow.MarkBodyComplete()
	fixed.Advance(time.Second)
	slowOutcome := slow.Finish()
	if slowOutcome.Verdict != DiagnosticAvailable || slowOutcome.ThroughputBps <= 0 || slowOutcome.TTFB != time.Second {
		t.Fatalf("slow but valid flow was rejected: %+v", slowOutcome)
	}
}

func TestMarkHTTPProbeErrorTLSStageMarksTCPConnected(t *testing.T) {
	// TLS-layer failures must keep the TCP-connected marker so the
	// classifier reports the real stage (tls/dpi_drop) instead of lying
	// with tcp_connect/ip_block_suspected when the TSPU drops the SNI.
	handshake := NewProbeTracker(DefaultProbePolicy())
	markHTTPProbeError(handshake, tlsHandshakeTimeoutError{})
	outcome := handshake.Finish()
	if !outcome.TCPConnected || !outcome.TimedOut {
		t.Fatalf("TLS handshake timeout lost TCP-connected marker: %+v", outcome)
	}
	if outcome.Verdict != DiagnosticDPIDrop || outcome.FailureStage != "tls" || outcome.FailureSignature != FailureBeforeTLS {
		t.Fatalf("TLS handshake timeout misclassified: %+v", outcome)
	}

	alert := NewProbeTracker(DefaultProbePolicy())
	markHTTPProbeError(alert, errors.New(`Get "https://googlevideo.com": remote error: tls: unexpected message`))
	outcome = alert.Finish()
	if !outcome.TCPConnected || outcome.TLSResponseType != TLSResponseAlert {
		t.Fatalf("peer TLS alert lost TCP/response marker: %+v", outcome)
	}
	if outcome.Verdict != DiagnosticTLSResponseOnly || outcome.FailureStage != "tls" {
		t.Fatalf("peer TLS alert misclassified: %+v", outcome)
	}

	headers := NewProbeTracker(DefaultProbePolicy())
	markHTTPProbeError(headers, errors.New(`Get "https://googlevideo.com": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`))
	outcome = headers.Finish()
	if !outcome.TCPConnected {
		t.Fatalf("post-request timeout lost TCP-connected marker: %+v", outcome)
	}

	// A real SYN drop (dial timeout, no TLS markers) must stay at the
	// tcp_connect layer so ip_block_suspected remains an honest verdict.
	dial := NewProbeTracker(DefaultProbePolicy())
	markHTTPProbeError(dial, &url.Error{Op: "Get", URL: "https://googlevideo.com", Err: &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("64.233.161.106"), Port: 443}, Err: timeoutError{}}})
	outcome = dial.Finish()
	if outcome.TCPConnected {
		t.Fatalf("dial timeout was marked TCP-connected: %+v", outcome)
	}
	if outcome.Verdict != DiagnosticIPBlockSuspected || outcome.FailureStage != "tcp_connect" {
		t.Fatalf("dial timeout misclassified: %+v", outcome)
	}
}

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }
func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }

func TestRunHTTPProbeHTTPErrorBodyAndReadCap(t *testing.T) {
	body := bytes.Repeat([]byte("b"), 128<<10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	outcome := RunHTTPProbe(context.Background(), HTTPProbeRequest{URL: server.URL, Policy: ProbePolicy{ReadCap: 32 << 10, BodySuccessThreshold: 24 << 10}})
	if outcome.Verdict != DiagnosticAvailable || outcome.HTTPStatus != http.StatusBadGateway || outcome.BodyBytes != 32<<10 || !outcome.BodyCapped {
		t.Fatalf("HTTP error with bounded body was misclassified: %+v", outcome)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRunHTTPProbeDNSResetAndStall(t *testing.T) {
	dnsClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "youtube.invalid"}
	})}
	dnsOutcome := RunHTTPProbe(context.Background(), HTTPProbeRequest{URL: "https://youtube.invalid/", Client: dnsClient})
	if dnsOutcome.Verdict != DiagnosticDNSFailure || dnsOutcome.FailureSignature != FailureDNS {
		t.Fatalf("DNS failure was not classified at DNS layer: %+v", dnsOutcome)
	}

	resetClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("transport: %w", syscall.ECONNRESET)
	})}
	resetOutcome := RunHTTPProbe(context.Background(), HTTPProbeRequest{URL: "https://youtube.invalid/", Client: resetClient})
	if resetOutcome.Verdict != DiagnosticDPIRest {
		t.Fatalf("connect reset was not classified: %+v", resetOutcome)
	}

	stallClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: errReadCloser{err: timeoutError{}}}, nil
	})}
	stallOutcome := RunHTTPProbe(context.Background(), HTTPProbeRequest{URL: "https://youtube.invalid/", Client: stallClient})
	if stallOutcome.Verdict != DiagnosticThrottled {
		t.Fatalf("body stall was not classified: %+v", stallOutcome)
	}
}

type errReadCloser struct{ err error }

func (e errReadCloser) Read([]byte) (int, error) { return 0, e.err }
func (e errReadCloser) Close() error             { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "read timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestProbeOutcomeBoundedEvidenceAndFuzzSurface(t *testing.T) {
	tracker := NewProbeTracker(DefaultProbePolicy())
	for i := 0; i < 32; i++ {
		tracker.AddEvidence(observability.EvidenceSummary{Source: "dns", SetID: "set", DomainID: "example.com"})
	}
	outcome := tracker.Finish()
	if len(outcome.EvidenceSummary) != 16 {
		t.Fatalf("evidence was not bounded: %d", len(outcome.EvidenceSummary))
	}
}

func FuzzProbeTrackerNeverPanics(f *testing.F) {
	f.Add(int64(0), int64(8<<10), true, false)
	f.Add(int64(16<<10), int64(128<<10), false, true)
	f.Fuzz(func(t *testing.T, first, second int64, reset, stall bool) {
		tracker := NewProbeTracker(DefaultProbePolicy())
		tracker.MarkDNSResolved()
		tracker.MarkTCPConnected()
		tracker.MarkTLSResponse(TLSResponseServerHello)
		tracker.MarkHTTPHeaders(http.StatusOK)
		if first < 0 {
			first = 0
		}
		if second < first {
			second = first
		}
		tracker.ObserveBodyAt(first)
		tracker.ObserveBodyAt(second)
		if reset {
			tracker.MarkTCPReset()
		}
		if stall {
			tracker.MarkStall()
		}
		_ = tracker.Finish()
	})
}

func BenchmarkProbeTrackerFinish(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tracker := NewProbeTracker(DefaultProbePolicy())
		tracker.MarkDNSResolved()
		tracker.MarkTCPConnected()
		tracker.MarkTLSResponse(TLSResponseServerHello)
		tracker.MarkHTTPHeaders(http.StatusOK)
		tracker.ObserveBodyAt(32 << 10)
		tracker.MarkBodyComplete()
		_ = tracker.Finish()
	}
}

var _ io.ReadCloser = errReadCloser{}
