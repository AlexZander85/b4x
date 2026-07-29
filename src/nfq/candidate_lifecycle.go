package nfq

import (
	"fmt"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

func recordCandidateDisposition(flow classifier.FlowKey, provisional *config.SetConfig, host string, source classifier.EvidenceSource, disposition classifier.CandidateDisposition, eligible []string) {
	provisionalID := ""
	if provisional != nil {
		provisionalID = classifierSetID(provisional)
	}
	observability.Default().Trace.Record(observability.TraceEvent{
		Timestamp: time.Now(), FlowID: fmt.Sprintf("%v", flow), Kind: "capture_candidate_disposition",
		Fields: map[string]string{
			"provisional_set": observability.RedactIdentifier(provisionalID),
			"hostname":        observability.RedactIdentifier(strings.ToLower(strings.TrimSpace(host))),
			"source":          source.String(),
			"disposition":     string(disposition),
			"eligible_sets":   fmt.Sprintf("%d", len(eligible)),
		},
	})
}
