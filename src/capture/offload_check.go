package capture

import "fmt"

type QueueCounterSnapshot struct {
	QueueTotal uint64
	QueueDrops uint64
	UserDrops  uint64
}

type OffloadCheckInput struct {
	EnvelopeActive        bool
	OutgoingSeen          bool
	IncomingProgressSeen  bool
	ProcessedMarkVerified bool
	Before                QueueCounterSnapshot
	After                 QueueCounterSnapshot
}

type OffloadReport struct {
	CaptureEnvelopeActive      bool     `json:"capture_envelope_active"`
	IncomingProgressVisible    bool     `json:"incoming_progress_visible"`
	ProcessedMarkVerified      bool     `json:"processed_mark_verified"`
	FlowOffloadBypassSuspected bool     `json:"flow_offload_bypass_suspected"`
	QueueDelta                 uint64   `json:"queue_delta"`
	QueueDrops                 uint64   `json:"queue_drop"`
	UserDrops                  uint64   `json:"user_drop"`
	Status                     string   `json:"status"`
	Reasons                    []string `json:"reasons,omitempty"`
}

// EvaluateOffload is deliberately conservative. A missing observation is
// reported as insufficient data; bypass is suspected only after an outgoing
// packet is seen but no incoming progress appears while queue counters remain
// unchanged. This avoids turning a quiet/idle target into a false alarm.
func EvaluateOffload(input OffloadCheckInput) OffloadReport {
	report := OffloadReport{
		CaptureEnvelopeActive:   input.EnvelopeActive,
		IncomingProgressVisible: input.IncomingProgressSeen,
		ProcessedMarkVerified:   input.ProcessedMarkVerified,
		QueueDelta:              counterDelta(input.Before.QueueTotal, input.After.QueueTotal),
		QueueDrops:              counterDelta(input.Before.QueueDrops, input.After.QueueDrops),
		UserDrops:               counterDelta(input.Before.UserDrops, input.After.UserDrops),
	}

	if !input.EnvelopeActive {
		report.Status = "disabled"
		report.Reasons = append(report.Reasons, "capture envelope is not active")
		return report
	}
	if !input.OutgoingSeen || !input.IncomingProgressSeen {
		report.Status = "insufficient_observations"
		if !input.OutgoingSeen {
			report.Reasons = append(report.Reasons, "test flow outgoing packet not observed")
		}
		if !input.IncomingProgressSeen {
			report.Reasons = append(report.Reasons, "test flow incoming progress not observed")
		}
		if report.QueueDelta == 0 {
			report.Reasons = append(report.Reasons, "queue counter did not advance")
		}
		return report
	}
	if !input.ProcessedMarkVerified {
		report.Status = "mark_verification_failed"
		report.Reasons = append(report.Reasons, "processed mark bypass was not verified")
		return report
	}
	if report.QueueDelta == 0 {
		report.FlowOffloadBypassSuspected = true
		report.Status = "suspected_bypass"
		report.Reasons = append(report.Reasons, "outgoing test packet seen but queue counters did not advance")
		return report
	}
	report.Status = "ok"
	report.Reasons = append(report.Reasons, fmt.Sprintf("queue counter advanced by %d", report.QueueDelta))
	return report
}

func counterDelta(before, after uint64) uint64 {
	if after < before {
		// Counter reset/restart is not evidence of a negative delta.
		return 0
	}
	return after - before
}
