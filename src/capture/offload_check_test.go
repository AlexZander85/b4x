package capture

import "testing"

func TestEvaluateOffloadConservativeStates(t *testing.T) {
	tests := []struct {
		name      string
		input     OffloadCheckInput
		status    string
		suspected bool
	}{
		{
			name:   "disabled",
			input:  OffloadCheckInput{},
			status: "disabled",
		},
		{
			name:   "not enough observations",
			input:  OffloadCheckInput{EnvelopeActive: true, OutgoingSeen: true},
			status: "insufficient_observations",
		},
		{
			name:      "bypass suspected",
			input:     OffloadCheckInput{EnvelopeActive: true, OutgoingSeen: true, IncomingProgressSeen: true, ProcessedMarkVerified: true},
			status:    "suspected_bypass",
			suspected: true,
		},
		{
			name:   "healthy counters",
			input:  OffloadCheckInput{EnvelopeActive: true, OutgoingSeen: true, IncomingProgressSeen: true, ProcessedMarkVerified: true, Before: QueueCounterSnapshot{QueueTotal: 10}, After: QueueCounterSnapshot{QueueTotal: 12}},
			status: "ok",
		},
		{
			name:   "mark verification",
			input:  OffloadCheckInput{EnvelopeActive: true, OutgoingSeen: true, IncomingProgressSeen: true},
			status: "mark_verification_failed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateOffload(tc.input)
			if got.Status != tc.status || got.FlowOffloadBypassSuspected != tc.suspected {
				t.Fatalf("report = %+v", got)
			}
		})
	}
}

func TestEvaluateOffloadCounterResetDoesNotUnderflow(t *testing.T) {
	report := EvaluateOffload(OffloadCheckInput{
		EnvelopeActive:        true,
		OutgoingSeen:          true,
		IncomingProgressSeen:  true,
		ProcessedMarkVerified: true,
		Before:                QueueCounterSnapshot{QueueTotal: 20},
		After:                 QueueCounterSnapshot{QueueTotal: 1},
	})
	if report.QueueDelta != 0 || !report.FlowOffloadBypassSuspected {
		t.Fatalf("counter reset report = %+v", report)
	}
}
