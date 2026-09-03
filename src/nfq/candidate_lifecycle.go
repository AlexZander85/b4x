package nfq

import (
	"fmt"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
	"github.com/daniellavrushin/b4/observability"
)

func recordCandidateDisposition(flow classifier.FlowKey, provisional *config.SetConfig, host string, source classifier.EvidenceSource, disposition classifier.CandidateDisposition, eligible []string) {
	provisionalID := ""
	if provisional != nil {
		provisionalID = classifierSetID(provisional)
	}
	setLabel := observability.RedactIdentifier(provisionalID)
	observability.Default().Metrics.Inc(observability.MetricCrossServiceCandidate, map[string]string{"source": source.String(), "set": setLabel}, 1)
	switch disposition {
	case classifier.CandidateContradicted:
		observability.Default().Metrics.Inc(observability.MetricCrossServiceRevoked, map[string]string{"reason": "hostname_contradiction"}, 1)
		recordCrossServiceFailure(flow, diagnostics.SignalProvisionalSetRevokedBySNI, "clear hostname contradicted provisional service candidate")
	case classifier.CandidateAmbiguous:
		observability.Default().Metrics.Inc(observability.MetricCrossServiceAmbiguous, map[string]string{"reason": "equal_strength_candidates"}, 1)
		recordCrossServiceFailure(flow, diagnostics.SignalSharedIPAmbiguous, "shared destination produced equal-strength service candidates")
	}
	observability.Default().Trace.Record(observability.TraceEvent{
		Timestamp: time.Now(), FlowID: fmt.Sprintf("%v", flow), Kind: "capture_candidate_disposition",
		Fields: map[string]string{
			"provisional_set": setLabel,
			"hostname":        observability.RedactIdentifier(strings.ToLower(strings.TrimSpace(host))),
			"source":          source.String(),
			"disposition":     string(disposition),
			"eligible_sets":   fmt.Sprintf("%d", len(eligible)),
		},
	})
}

func recordCrossServiceFailure(flow classifier.FlowKey, signal diagnostics.FailureSignal, reason string) {
	flow = flow.Normalize()
	if flow.Client.IsZero() || !flow.DstIP.IsValid() || flow.DstPort == 0 {
		return
	}
	_, _ = diagnostics.Default().Observe(diagnostics.FailureObservation{
		Signal: signal, Client: flow.Client, DestinationIP: flow.DstIP, DestinationPort: flow.DstPort,
		Protocol: flow.Proto, ObservedAt: time.Now(), Reason: reason,
	})
}
