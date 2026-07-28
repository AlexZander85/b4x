package discovery

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/observability"
)

type TLSResponseType string

const (
	TLSResponseNone        TLSResponseType = "none"
	TLSResponseServerHello TLSResponseType = "server_hello"
	TLSResponseAlert       TLSResponseType = "alert"
	TLSResponseOther       TLSResponseType = "other"
)

type TransferFailureSignature string

const (
	FailureNone               TransferFailureSignature = "none"
	FailureDNS                TransferFailureSignature = "dns"
	FailureBeforeTCP          TransferFailureSignature = "before_tcp"
	FailureBeforeTLS          TransferFailureSignature = "before_tls"
	FailureAfterTLSBeforeBody TransferFailureSignature = "after_tls_before_body"
	FailureNear16KiB          TransferFailureSignature = "near_16k"
	FailureMidstreamReset     TransferFailureSignature = "midstream_reset"
	FailureStall              TransferFailureSignature = "stall"
	FailureThroughputClamp    TransferFailureSignature = "throughput_clamp"
	FailureBodyTruncated      TransferFailureSignature = "body_truncated"
)

type DiagnosticVerdict string

const (
	DiagnosticAvailable            DiagnosticVerdict = "available"
	DiagnosticDNSFailure           DiagnosticVerdict = "dns_failure"
	DiagnosticIPBlockSuspected     DiagnosticVerdict = "ip_block_suspected"
	DiagnosticDPIRest              DiagnosticVerdict = "dpi_reset"
	DiagnosticDPIDrop              DiagnosticVerdict = "dpi_drop"
	DiagnosticTLSProfileSpecific   DiagnosticVerdict = "tls_profile_specific"
	DiagnosticResolverSpecific     DiagnosticVerdict = "resolver_specific"
	DiagnosticIPFamilySpecific     DiagnosticVerdict = "ip_family_specific"
	DiagnosticBodyTruncated        DiagnosticVerdict = "body_truncated"
	DiagnosticMidstreamReset       DiagnosticVerdict = "midstream_reset"
	DiagnosticThrottled            DiagnosticVerdict = "throttled"
	DiagnosticClassifierUnresolved DiagnosticVerdict = "classifier_unresolved"
	DiagnosticCaptureIncomplete    DiagnosticVerdict = "capture_path_incomplete"
	DiagnosticTLSResponseOnly      DiagnosticVerdict = "tls_response_only"
)

type ProbeOutcome struct {
	TargetProfile        string                          `json:"target_profile,omitempty"`
	DNSResolved          bool                            `json:"dns_resolved"`
	TCPConnected         bool                            `json:"tcp_connected"`
	TCPReset             bool                            `json:"tcp_reset"`
	TimedOut             bool                            `json:"timed_out"`
	TLSResponseType      TLSResponseType                 `json:"tls_response_type"`
	HTTPHeaders          bool                            `json:"http_headers"`
	HTTPStatus           int                             `json:"http_status"`
	TTFB                 time.Duration                   `json:"ttfb"`
	BodyBytes            int64                           `json:"body_bytes"`
	FailureOffset        int64                           `json:"failure_offset"`
	FailureOffsetKnown   bool                            `json:"failure_offset_known"`
	ThroughputBps        int64                           `json:"throughput_bps"`
	Retransmissions      int                             `json:"retransmissions"`
	FlowRetries          int                             `json:"flow_retries"`
	PacketAmplification  float64                         `json:"packet_amplification"`
	CPUTime              time.Duration                   `json:"cpu_time"`
	Verdict              DiagnosticVerdict               `json:"verdict"`
	FailureSignature     TransferFailureSignature        `json:"failure_signature"`
	FailureStage         string                          `json:"failure_stage,omitempty"`
	BodyCapped           bool                            `json:"body_capped"`
	ReadCap              int64                           `json:"read_cap"`
	BodySuccessThreshold int64                           `json:"body_success_threshold"`
	Duration             time.Duration                   `json:"duration"`
	StartedAt            time.Time                       `json:"started_at"`
	CompletedAt          time.Time                       `json:"completed_at"`
	EvidenceSummary      []observability.EvidenceSummary `json:"evidence_summary,omitempty"`
}

type ProbePolicy struct {
	TargetProfile        string
	ReadCap              int64
	BodySuccessThreshold int64
	Near16KiBMin         int64
	Near16KiBMax         int64
	MinThroughputBps     int64
	StallTimeout         time.Duration
	Clock                clock.Clock
}

func DefaultProbePolicy() ProbePolicy {
	return ProbePolicy{ReadCap: 1 << 20, BodySuccessThreshold: 32 << 10, Near16KiBMin: 14 << 10, Near16KiBMax: 18 << 10, StallTimeout: 10 * time.Second, Clock: clock.RealClock{}}
}

func (p ProbePolicy) normalized() ProbePolicy {
	d := DefaultProbePolicy()
	if p.ReadCap <= 0 {
		p.ReadCap = d.ReadCap
	}
	if p.BodySuccessThreshold <= 0 {
		p.BodySuccessThreshold = d.BodySuccessThreshold
	}
	if p.Near16KiBMin <= 0 {
		p.Near16KiBMin = d.Near16KiBMin
	}
	if p.Near16KiBMax < p.Near16KiBMin {
		p.Near16KiBMax = d.Near16KiBMax
	}
	if p.StallTimeout <= 0 {
		p.StallTimeout = d.StallTimeout
	}
	if p.Clock == nil {
		p.Clock = d.Clock
	}
	return p
}

type ProbeTracker struct {
	mu            sync.Mutex
	policy        ProbePolicy
	outcome       ProbeOutcome
	firstResponse time.Time
	lastProgress  time.Time
	bodyComplete  bool
	stall         bool
	finished      bool
}

func NewProbeTracker(policy ProbePolicy) *ProbeTracker {
	policy = policy.normalized()
	now := policy.Clock.Now()
	return &ProbeTracker{policy: policy, outcome: ProbeOutcome{TargetProfile: policy.TargetProfile, TLSResponseType: TLSResponseNone, FailureSignature: FailureNone, ReadCap: policy.ReadCap, BodySuccessThreshold: policy.BodySuccessThreshold, StartedAt: now}, lastProgress: now}
}

func (t *ProbeTracker) MarkDNSResolved() {
	t.withLock(func() { t.outcome.DNSResolved = true })
}

func (t *ProbeTracker) MarkTCPConnected() {
	t.withLock(func() { t.outcome.TCPConnected = true })
}

func (t *ProbeTracker) MarkTCPReset() {
	t.withLock(func() {
		t.outcome.TCPReset = true
		t.markFailureOffsetLocked(t.outcome.BodyBytes)
	})
}

func (t *ProbeTracker) MarkTimeout() {
	t.withLock(func() {
		t.outcome.TimedOut = true
		t.markFailureOffsetLocked(t.outcome.BodyBytes)
	})
}

func (t *ProbeTracker) MarkTLSResponse(response TLSResponseType) {
	t.withLock(func() {
		t.outcome.TLSResponseType = response
		t.markFirstResponseLocked()
	})
}

func (t *ProbeTracker) MarkHTTPHeaders(status int) {
	t.withLock(func() {
		t.outcome.HTTPHeaders = true
		t.outcome.HTTPStatus = status
		t.markFirstResponseLocked()
	})
}

// ObserveBodyAt records the highest sequential stream offset observed. The
// caller supplies the end offset, so a reset/stall can retain the exact byte
// boundary instead of a rounded 16 KiB label.
func (t *ProbeTracker) ObserveBodyAt(endOffset int64) {
	t.withLock(func() {
		if endOffset > t.outcome.BodyBytes {
			t.outcome.BodyBytes = endOffset
			t.lastProgress = t.policy.Clock.Now()
			if t.firstResponse.IsZero() {
				t.markFirstResponseLocked()
			}
		}
	})
}

func (t *ProbeTracker) MarkBodyComplete() {
	t.withLock(func() { t.bodyComplete = true })
}

func (t *ProbeTracker) MarkStall() {
	t.withLock(func() {
		t.stall = true
		t.markFailureOffsetLocked(t.outcome.BodyBytes)
	})
}

func (t *ProbeTracker) SetFailureOffset(offset int64) {
	t.withLock(func() { t.markFailureOffsetLocked(offset) })
}

func (t *ProbeTracker) SetRetransmissions(value int) {
	t.withLock(func() { t.outcome.Retransmissions = maxInt(value, 0) })
}

func (t *ProbeTracker) SetFlowRetries(value int) {
	t.withLock(func() { t.outcome.FlowRetries = maxInt(value, 0) })
}

func (t *ProbeTracker) SetPacketAmplification(value float64) {
	t.withLock(func() {
		if value >= 0 {
			t.outcome.PacketAmplification = value
		}
	})
}

func (t *ProbeTracker) SetCPUTime(value time.Duration) {
	t.withLock(func() {
		if value >= 0 {
			t.outcome.CPUTime = value
		}
	})
}

func (t *ProbeTracker) AddEvidence(summary observability.EvidenceSummary) {
	t.withLock(func() {
		if len(t.outcome.EvidenceSummary) >= 16 || strings.TrimSpace(summary.Source) == "" {
			return
		}
		summary.SetID = observability.RedactIdentifier(summary.SetID)
		summary.DomainID = observability.RedactDomain(summary.DomainID)
		t.outcome.EvidenceSummary = append(t.outcome.EvidenceSummary, summary)
	})
}

func (t *ProbeTracker) Finish() ProbeOutcome {
	if t == nil {
		return ProbeOutcome{Verdict: DiagnosticCaptureIncomplete, FailureSignature: FailureBeforeTCP}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.finished {
		t.finished = true
		t.outcome.CompletedAt = t.policy.Clock.Now()
		t.outcome.Duration = t.outcome.CompletedAt.Sub(t.outcome.StartedAt)
		if t.outcome.Duration < 0 {
			t.outcome.Duration = 0
		}
		if !t.firstResponse.IsZero() {
			t.outcome.TTFB = t.firstResponse.Sub(t.outcome.StartedAt)
		}
		if t.outcome.Duration > 0 {
			t.outcome.ThroughputBps = int64(float64(t.outcome.BodyBytes) / t.outcome.Duration.Seconds())
		}
		if !t.outcome.FailureOffsetKnown && t.hasFailureLocked() {
			t.markFailureOffsetLocked(t.outcome.BodyBytes)
		}
		t.classifyLocked()
		labels := map[string]string{"verdict": string(t.outcome.Verdict)}
		if t.policy.TargetProfile != "" {
			labels["target_profile"] = t.policy.TargetProfile
		}
		observability.Default().Metrics.Inc(observability.MetricDiscoveryProbe, labels, 1)
		if t.outcome.FailureOffsetKnown {
			observability.Default().Metrics.Observe(observability.MetricDiscoveryFailureOffset, map[string]string{"verdict": string(t.outcome.Verdict)}, float64(t.outcome.FailureOffset))
		}
		observability.Default().RecordProbeOutcome(observability.ProbeOutcomeSummary{
			TargetProfile: t.outcome.TargetProfile,
			Verdict:       string(t.outcome.Verdict),
			FailureStage:  t.outcome.FailureStage,
			FailureOffset: t.outcome.FailureOffset,
			BodyBytes:     uint64(maxInt64(t.outcome.BodyBytes, 0)),
			ThroughputBPS: uint64(maxInt64(t.outcome.ThroughputBps, 0)),
		})
	}
	return cloneProbeOutcome(t.outcome)
}

func (t *ProbeTracker) withLock(fn func()) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.finished {
		fn()
	}
}

func (t *ProbeTracker) markFirstResponseLocked() {
	if t.firstResponse.IsZero() {
		t.firstResponse = t.policy.Clock.Now()
	}
}

func (t *ProbeTracker) markFailureOffsetLocked(offset int64) {
	if offset < 0 {
		return
	}
	t.outcome.FailureOffset = offset
	t.outcome.FailureOffsetKnown = true
}

func (t *ProbeTracker) hasFailureLocked() bool {
	return t.outcome.TCPReset || t.outcome.TimedOut || t.stall || (!t.bodyComplete && !t.outcome.BodyCapped)
}

func (t *ProbeTracker) classifyLocked() {
	o := &t.outcome
	if !o.DNSResolved {
		o.Verdict, o.FailureSignature, o.FailureStage = DiagnosticDNSFailure, FailureDNS, "dns"
		return
	}
	if !o.TCPConnected {
		o.FailureStage = "tcp_connect"
		if o.TimedOut {
			o.Verdict, o.FailureSignature = DiagnosticIPBlockSuspected, FailureBeforeTCP
		} else if o.TCPReset {
			o.Verdict, o.FailureSignature = DiagnosticDPIRest, FailureBeforeTCP
		} else {
			o.Verdict, o.FailureSignature = DiagnosticCaptureIncomplete, FailureBeforeTCP
		}
		return
	}
	if o.TLSResponseType == TLSResponseNone {
		o.FailureStage = "tls"
		if o.TCPReset {
			o.Verdict, o.FailureSignature = DiagnosticDPIRest, FailureBeforeTLS
		} else if o.TimedOut || t.stall {
			o.Verdict, o.FailureSignature = DiagnosticDPIDrop, FailureBeforeTLS
		} else {
			o.Verdict, o.FailureSignature = DiagnosticTLSProfileSpecific, FailureBeforeTLS
		}
		return
	}
	if o.TLSResponseType == TLSResponseAlert && !o.HTTPHeaders {
		o.Verdict, o.FailureStage, o.FailureSignature = DiagnosticTLSResponseOnly, "tls", FailureNone
		return
	}
	if !o.HTTPHeaders {
		o.FailureStage = "http_headers"
		if o.TCPReset {
			o.Verdict, o.FailureSignature = DiagnosticDPIRest, FailureAfterTLSBeforeBody
		} else if o.TimedOut || t.stall {
			o.Verdict, o.FailureSignature = DiagnosticDPIDrop, FailureAfterTLSBeforeBody
		} else {
			o.Verdict, o.FailureSignature = DiagnosticCaptureIncomplete, FailureAfterTLSBeforeBody
		}
		return
	}
	if o.TCPReset {
		o.FailureStage = "body"
		if t.near16KiBLocked() {
			o.Verdict, o.FailureSignature = DiagnosticBodyTruncated, FailureNear16KiB
		} else {
			o.Verdict, o.FailureSignature = DiagnosticMidstreamReset, FailureMidstreamReset
		}
		return
	}
	if o.TimedOut || t.stall {
		o.Verdict, o.FailureStage, o.FailureSignature = DiagnosticThrottled, "body", FailureStall
		return
	}
	if o.BodyBytes < t.policy.BodySuccessThreshold && !o.BodyCapped {
		o.FailureStage = "body"
		t.markFailureOffsetLocked(o.BodyBytes)
		if t.near16KiBLocked() {
			o.FailureSignature = FailureNear16KiB
		} else if o.BodyBytes == 0 {
			o.FailureSignature = FailureAfterTLSBeforeBody
		} else {
			o.FailureSignature = FailureBodyTruncated
		}
		o.Verdict = DiagnosticBodyTruncated
		return
	}
	if t.policy.MinThroughputBps > 0 && o.ThroughputBps < t.policy.MinThroughputBps {
		o.Verdict, o.FailureStage, o.FailureSignature = DiagnosticThrottled, "throughput", FailureThroughputClamp
		return
	}
	o.Verdict, o.FailureSignature = DiagnosticAvailable, FailureNone
}

func (t *ProbeTracker) near16KiBLocked() bool {
	return t.outcome.BodyBytes >= t.policy.Near16KiBMin && t.outcome.BodyBytes <= t.policy.Near16KiBMax
}

func cloneProbeOutcome(in ProbeOutcome) ProbeOutcome {
	in.EvidenceSummary = append([]observability.EvidenceSummary(nil), in.EvidenceSummary...)
	return in
}

type HTTPProbeRequest struct {
	URL    string
	Client *http.Client
	Policy ProbePolicy
}

// RunHTTPProbe is a bounded diagnostic probe. It never promotes a strategy or
// changes production config; it only translates the observed layers into a
// structured outcome.
func RunHTTPProbe(ctx context.Context, request HTTPProbeRequest) ProbeOutcome {
	if ctx == nil {
		ctx = context.Background()
	}
	tracker := NewProbeTracker(request.Policy)
	parsed, err := url.Parse(strings.TrimSpace(request.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return tracker.Finish()
	}
	client := request.Client
	if client == nil {
		client = &http.Client{}
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return tracker.Finish()
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		markHTTPProbeError(tracker, err)
		return tracker.Finish()
	}
	defer response.Body.Close()
	tracker.MarkDNSResolved()
	tracker.MarkTCPConnected()
	if strings.EqualFold(parsed.Scheme, "https") {
		tracker.MarkTLSResponse(TLSResponseServerHello)
	} else {
		tracker.MarkTLSResponse(TLSResponseOther)
	}
	tracker.MarkHTTPHeaders(response.StatusCode)
	readCap := request.Policy.normalized().ReadCap
	buf := make([]byte, 32*1024)
	for tracker.currentBodyBytes() < readCap {
		remaining := readCap - tracker.currentBodyBytes()
		if int64(len(buf)) > remaining {
			buf = buf[:remaining]
		}
		n, readErr := response.Body.Read(buf)
		if n > 0 {
			tracker.ObserveBodyAt(tracker.currentBodyBytes() + int64(n))
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				tracker.MarkBodyComplete()
			} else {
				markHTTPProbeError(tracker, readErr)
			}
			break
		}
		if n == 0 {
			tracker.MarkStall()
			break
		}
	}
	if tracker.currentBodyBytes() >= readCap {
		tracker.markCapped()
	}
	return tracker.Finish()
}

func markHTTPProbeError(tracker *ProbeTracker, err error) {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "no such host") || strings.Contains(message, "temporary failure in name resolution") {
		return
	}
	tracker.MarkDNSResolved()
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		tracker.MarkTimeout()
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) {
		tracker.MarkTimeout()
		return
	}
	if errors.Is(err, syscall.ECONNRESET) || strings.Contains(message, "connection reset") {
		tracker.MarkTCPConnected()
		tracker.MarkTCPReset()
		return
	}
	if strings.Contains(message, "connection refused") {
		tracker.MarkTCPReset()
	}
}

func (t *ProbeTracker) currentBodyBytes() int64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.outcome.BodyBytes
}

func (t *ProbeTracker) markCapped() {
	t.withLock(func() { t.outcome.BodyCapped = true })
}

func maxInt(value, minimum int) int {
	if value < minimum {
		return minimum
	}
	return value
}

func maxInt64(value, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}
