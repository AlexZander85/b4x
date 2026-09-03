package nfq

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/observability"
	"github.com/florianl/go-nfqueue"
)

// Linux NFQA_SKB_INFO flags from include/uapi/linux/netfilter/nfnetlink_queue.h.
// Keep them local because go-nfqueue v1 exposes SkbInfo as raw bytes.
const (
	nfqaSKBCsumNotReady    uint32 = 1 << 0
	nfqaSKBGSO             uint32 = 1 << 1
	nfqaSKBCsumNotVerified uint32 = 1 << 2
)

// OffloadMetadata is the immutable NFQUEUE capture envelope used by the
// classifier and executor. Lengths refer to the copied userspace payload and
// the original skb length reported by NFQA_CAP_LEN.
type OffloadMetadata struct {
	IsGSO               bool   `json:"is_gso"`
	ChecksumNotReady    bool   `json:"checksum_not_ready"`
	ChecksumNotVerified bool   `json:"checksum_not_verified"`
	PayloadLength       uint32 `json:"payload_length"`
	OriginalLength      uint32 `json:"original_length"`
	Truncated           bool   `json:"truncated"`
}

// GSOCapabilityLevel is deliberately more precise than a boolean so the API
// never reports an unvalidated kernel path as production-ready.
type GSOCapabilityLevel string

const (
	GSOCapabilityUnsupported          GSOCapabilityLevel = "unsupported"
	GSOCapabilitySupportedUnvalidated GSOCapabilityLevel = "supported-unvalidated"
	GSOCapabilityObserveOnly          GSOCapabilityLevel = "observe-only"
	GSOCapabilityClassifyReady        GSOCapabilityLevel = "classify-ready"
	GSOCapabilityFullActionReady      GSOCapabilityLevel = "full-action-ready"
	GSOCapabilityFailed               GSOCapabilityLevel = "failed"
)

type GSOCapabilityStatus struct {
	Level        GSOCapabilityLevel `json:"level"`
	Reason       string             `json:"reason,omitempty"`
	LastObserved time.Time          `json:"last_observed,omitempty"`
	LastMetadata OffloadMetadata    `json:"last_metadata"`
}

func defaultGSOCapabilityStatus() GSOCapabilityStatus {
	return GSOCapabilityStatus{
		Level:  GSOCapabilitySupportedUnvalidated,
		Reason: "userspace supports NFQA_CFG_F_GSO; target kernel path not validated",
	}
}

// DecodeOffloadMetadata constructs the capture envelope from the attributes
// made available by go-nfqueue. Missing attributes preserve fail-open behavior.
func DecodeOffloadMetadata(a nfqueue.Attribute) OffloadMetadata {
	var metadata OffloadMetadata
	if a.Payload != nil {
		metadata.PayloadLength = uint32(len(*a.Payload))
	}
	metadata.OriginalLength = metadata.PayloadLength
	if a.CapLen != nil {
		metadata.OriginalLength = *a.CapLen
		if metadata.OriginalLength < metadata.PayloadLength {
			// A malformed/inconsistent attribute must not make a copied packet look
			// shorter than the bytes actually delivered to userspace.
			metadata.OriginalLength = metadata.PayloadLength
		}
	}
	metadata.Truncated = metadata.OriginalLength > metadata.PayloadLength

	flags := decodeSKBInfo(a.SkbInfo)
	metadata.IsGSO = flags&nfqaSKBGSO != 0
	metadata.ChecksumNotReady = flags&nfqaSKBCsumNotReady != 0
	metadata.ChecksumNotVerified = flags&nfqaSKBCsumNotVerified != 0
	return metadata
}

func decodeSKBInfo(raw *[]byte) uint32 {
	if raw == nil || len(*raw) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32((*raw)[:4])
}

func (w *Worker) observeOffloadMetadata(metadata OffloadMetadata) {
	if w == nil {
		return
	}
	status := w.GSOCapabilityStatus()
	status.LastMetadata = metadata
	status.LastObserved = time.Now()
	if status.Level == "" {
		status = defaultGSOCapabilityStatus()
		status.LastMetadata = metadata
		status.LastObserved = time.Now()
	}
	w.gsoCapability.Store(status)
	if metadata.IsGSO {
		w.observeGSOReadinessMetadata(metadata)
		mode := requestedGSOMode(w.getConfig())
		observability.Default().Metrics.Inc(observability.MetricNFQueueGSOPackets, map[string]string{"direction": "unknown", "mode": mode}, 1)
		observability.Default().Metrics.Inc(observability.MetricNFQueueGSOBytes, map[string]string{"direction": "unknown"}, uint64(metadata.OriginalLength))
		if metadata.Truncated {
			observability.Default().Metrics.Inc(observability.MetricNFQueueGSOTruncated, nil, 1)
		}
		if metadata.ChecksumNotReady {
			observability.Default().Metrics.Inc(observability.MetricNFQueueGSOCsumNotReady, nil, 1)
		}
		observability.Default().Trace.Record(observability.TraceEvent{Timestamp: status.LastObserved, Kind: "nfqueue_gso_metadata", Fields: map[string]string{
			"mode": mode, "payload_length": fmt.Sprintf("%d", metadata.PayloadLength), "original_length": fmt.Sprintf("%d", metadata.OriginalLength),
			"truncated": fmt.Sprintf("%t", metadata.Truncated), "checksum_not_ready": fmt.Sprintf("%t", metadata.ChecksumNotReady),
			"checksum_not_verified": fmt.Sprintf("%t", metadata.ChecksumNotVerified),
		}})
	}
}

func (w *Worker) GSOCapabilityStatus() GSOCapabilityStatus {
	if w == nil {
		return GSOCapabilityStatus{Level: GSOCapabilityUnsupported, Reason: "worker unavailable"}
	}
	if value := w.gsoCapability.Load(); value != nil {
		return value.(GSOCapabilityStatus)
	}
	return defaultGSOCapabilityStatus()
}

func (w *Worker) setGSOCapabilityStatus(level GSOCapabilityLevel, reason string) {
	if w == nil {
		return
	}
	status := w.GSOCapabilityStatus()
	status.Level = level
	status.Reason = reason
	w.gsoCapability.Store(status)
}
