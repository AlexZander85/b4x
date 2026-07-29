package nfq

import (
	"fmt"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/observability"
)

func classifierDomainOnlyMode(cfg *config.Config) classifier.DomainOnlyMode {
	if cfg == nil {
		return classifier.DomainLegacy
	}
	switch strings.TrimSpace(cfg.System.Classifier.DomainOnlyMode) {
	case config.DomainStrict:
		return classifier.DomainStrict
	case config.DomainScopedHints:
		return classifier.DomainScopedHints
	case config.DomainDisabled:
		return classifier.DomainDisabled
	default:
		return classifier.DomainLegacy
	}
}

func classifierDecisionEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	return cfg.System.Classifier.Flags.ClassifierV2Enabled ||
		classifierDomainOnlyMode(cfg) != classifier.DomainLegacy ||
		cfg.System.Classifier.Flags.ScopedDNSHintsEnabled ||
		cfg.System.Classifier.Flags.QUICToTCPHandoffEnabled
}

func classifierSetIsDomainOnly(cfg *config.Config, setID string) bool {
	if cfg == nil || strings.TrimSpace(setID) == "" {
		return false
	}
	set := cfg.GetSetById(setID)
	if set == nil {
		for _, candidate := range cfg.Sets {
			if candidate != nil && candidate.Name == setID {
				set = candidate
				break
			}
		}
	}
	return set != nil && set.Targets.DomainOnly
}

func classifierSetDomainPolicy(cfg *config.Config, setID string) classifier.DomainPolicy {
	if cfg == nil {
		return classifier.DomainPolicyLegacy
	}
	set := cfg.GetSetById(setID)
	if set == nil {
		for _, candidate := range cfg.Sets {
			if candidate != nil && candidate.Name == setID {
				set = candidate
				break
			}
		}
	}
	switch cfg.EffectiveDomainPolicy(set) {
	case config.DomainPolicyStrict:
		return classifier.DomainPolicyStrict
	case config.DomainPolicyScopedHints:
		return classifier.DomainPolicyScopedHints
	case config.DomainPolicyDisabled:
		return classifier.DomainPolicyDisabled
	default:
		return classifier.DomainPolicyLegacy
	}
}

func classifierSetID(set *config.SetConfig) string {
	if set == nil {
		return ""
	}
	if id := strings.TrimSpace(set.Id); id != "" {
		return id
	}
	return strings.TrimSpace(set.Name)
}

func (w *Worker) decideNFQEvidence(cfg *config.Config, pkt *pktInfo, port uint16, proto uint8, input ...classifier.Evidence) classifier.ClassificationDecision {
	return w.decideNFQEvidenceWithMetadata(cfg, pkt, port, proto, classifier.TLSMetadata{}, input...)
}

func (w *Worker) decideNFQEvidenceWithMetadata(cfg *config.Config, pkt *pktInfo, port uint16, proto uint8, tlsMetadata classifier.TLSMetadata, input ...classifier.Evidence) classifier.ClassificationDecision {
	if cfg == nil || pkt == nil {
		return classifier.Decide(classifier.DecisionContext{Now: time.Now(), TLSMetadata: tlsMetadata}, input, classifier.DefaultConfidenceThresholds)
	}
	client, _ := dnsClientKey(pkt.src, pkt.srcMac)
	flow := classifier.NewFlowKey(client, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), 0, port, proto)
	now := time.Now()
	for i := range input {
		if input[i].Client.IsZero() {
			input[i].Client = client
		}
		if !input[i].DestinationIP.IsValid() {
			input[i].DestinationIP = netIPToAddr(pkt.dst)
		}
		if input[i].DestinationPort == 0 {
			input[i].DestinationPort = port
		}
		if input[i].L4Proto == 0 {
			input[i].L4Proto = proto
		}
		if input[i].SourceDevice == "" {
			input[i].SourceDevice = pkt.srcMac
		}
		if input[i].CreatedAt.IsZero() {
			input[i].CreatedAt = now
		}
	}
	return classifier.Decide(classifier.DecisionContext{
		Now:                now,
		Client:             client,
		ConfigGen:          dnsHintConfigGeneration(cfg),
		DestinationPort:    port,
		L4Proto:            proto,
		SourceDevice:       pkt.srcMac,
		TLSMetadata:        tlsMetadata,
		FlowKey:            flow,
		DomainOnlyMode:     classifierDomainOnlyMode(cfg),
		DomainOnlySet:      func(setID string) bool { return classifierSetIsDomainOnly(cfg, setID) },
		DomainPolicyForSet: func(setID string) classifier.DomainPolicy { return classifierSetDomainPolicy(cfg, setID) },
	}, input, classifier.DefaultConfidenceThresholds)
}

func traceNFQDecision(decision classifier.ClassificationDecision, set *config.SetConfig, strategy string) {
	evidence := make([]string, 0, len(decision.Candidates))
	for _, candidate := range decision.Candidates {
		evidence = append(evidence, candidate.Source.String()+":"+candidate.SetID+":"+candidate.Domain)
	}
	selected := "none"
	if decision.Selected != nil {
		selected = decision.Selected.Source.String() + ":" + decision.Selected.SetID
	}
	setName := ""
	if set != nil {
		setName = set.Name
	}
	log.Tracef("classifier decision phase=%s evidence=%v selected=%s confidence=%d corroborated=%t ech=%t host_markers=%t conflicts=%d domain_only=%s/%s set=%s strategy=%s reason=%s",
		decision.Phase, evidence, selected, decision.Confidence, decision.Corroborated, decision.ECHPresent, decision.CanUseHostMarkers(), len(decision.Conflicts), decision.DomainOnlyMode, decision.DomainOnlyResult, setName, strategy, decision.Reason)
	recordObservabilityDecision(decision, strategy)
}

func recordObservabilityDecision(decision classifier.ClassificationDecision, strategy string) {
	selectedSource := "none"
	selectedSet := ""
	if decision.Selected != nil {
		selectedSource = decision.Selected.Source.String()
		selectedSet = decision.Selected.SetID
	}
	labels := map[string]string{"phase": decision.Phase.String(), "source": selectedSource}
	observability.Default().Metrics.Inc(observability.MetricClassifierDecisions, labels, 1)
	observability.Default().Metrics.Observe(observability.MetricClassifierConfidence, labels, float64(decision.Confidence))
	if decision.Phase == classifier.PhaseAmbiguous {
		observability.Default().Metrics.Inc(observability.MetricClassifierAmbiguous, map[string]string{"reason": "multiple-candidates"}, 1)
	}
	if decision.ECHPresent {
		echSource := selectedSource
		observability.Default().Metrics.Inc(observability.MetricECHClientHello, map[string]string{"source": echSource}, 1)
		if !decision.CanUseHostMarkers() {
			observability.Default().Metrics.Inc(observability.MetricECHFallback, map[string]string{"source": echSource}, 1)
		}
	}
	for _, candidate := range decision.Candidates {
		observability.Default().Metrics.Inc(observability.MetricClassifierEvidence, map[string]string{"source": candidate.Source.String()}, 1)
		observability.Default().RecordEvidence(observability.EvidenceSummary{
			Source:     candidate.Source.String(),
			SetID:      candidate.SetID,
			DomainID:   candidate.Domain,
			Confidence: candidate.Confidence,
			ECH:        decision.ECHPresent || candidate.ECHRelated,
			Fresh:      candidate.ExpiresAt.IsZero() || candidate.ExpiresAt.After(time.Now()),
		})
	}
	identity := "unresolved"
	if decision.FlowKey.Client.SourceIP.IsValid() {
		identity = "ip-only"
		if decision.FlowKey.Client.SourceMAC != [6]byte{} {
			identity = "full"
		}
	}
	observability.Default().Trace.Record(observability.TraceEvent{
		Timestamp: time.Now(),
		ClientID:  fmt.Sprintf("%v", decision.FlowKey.Client),
		FlowID:    fmt.Sprintf("%v", decision.FlowKey),
		Kind:      "classifier_decision",
		Fields: map[string]string{
			"client_identity": identity,
			"phase":           decision.Phase.String(),
			"selected_source": selectedSource,
			"set_id":          observability.RedactIdentifier(selectedSet),
			"confidence":      fmt.Sprintf("%d", decision.Confidence),
			"candidate_count": fmt.Sprintf("%d", len(decision.Candidates)),
			"corroborated":    fmt.Sprintf("%t", decision.Corroborated),
			"ech":             fmt.Sprintf("%t", decision.ECHPresent),
			"host_markers":    fmt.Sprintf("%t", decision.CanUseHostMarkers()),
			"conflicts":       fmt.Sprintf("%d", len(decision.Conflicts)),
			"domain_only":     string(decision.DomainOnlyMode),
			"domain_result":   decision.DomainOnlyResult,
			"strategy":        strategy,
			"reason":          decision.Reason,
		},
	})
}

func (w *Worker) allowNFQDomainDecision(cfg *config.Config, pkt *pktInfo, port uint16, proto uint8, set *config.SetConfig, source classifier.EvidenceSource, domain string, domainEvidence bool, strategy string) bool {
	return w.allowNFQDomainDecisionWithMetadata(cfg, pkt, port, proto, set, source, domain, domainEvidence, strategy, classifier.TLSMetadata{})
}

func (w *Worker) allowNFQDomainDecisionWithMetadata(cfg *config.Config, pkt *pktInfo, port uint16, proto uint8, set *config.SetConfig, source classifier.EvidenceSource, domain string, domainEvidence bool, strategy string, tlsMetadata classifier.TLSMetadata) bool {
	if set == nil || !classifierDecisionEnabled(cfg) {
		return true
	}
	decision := w.decideNFQEvidenceWithMetadata(cfg, pkt, port, proto, tlsMetadata, classifier.Evidence{
		Source:         source,
		Domain:         domain,
		SetID:          classifierSetID(set),
		Confidence:     0,
		DomainEvidence: domainEvidence,
		Reason:         "NFQ packet decision integration",
	})
	traceNFQDecision(decision, set, strategy)
	if decision.Phase == classifier.PhaseAmbiguous {
		if client, ok := dnsClientKey(pkt.src, pkt.srcMac); ok {
			_, _ = diagnostics.Default().Observe(diagnostics.FailureObservation{
				Signal:          diagnostics.SignalClassifierAmbiguous,
				Client:          client,
				DestinationIP:   netIPToAddr(pkt.dst),
				DestinationPort: port,
				Protocol:        proto,
				Reason:          decision.Reason,
			})
		}
	}
	policy := classifierSetDomainPolicy(cfg, classifierSetID(set))
	if policy == classifier.DomainPolicyDisabled || !set.Targets.DomainOnly {
		return true
	}
	if !decision.CanClassify(classifier.DefaultConfidenceThresholds) || decision.Selected == nil || decision.Selected.SetID != classifierSetID(set) {
		return false
	}
	candidateEvidence := classifier.Evidence{
		Source: source, Client: decision.FlowKey.Client, DestinationIP: netIPToAddr(pkt.dst), DestinationPort: port,
		L4Proto: proto, SourceDevice: pkt.srcMac, Domain: domain, SetID: classifierSetID(set),
		Confidence: decision.Confidence, DomainEvidence: domainEvidence, CreatedAt: time.Now(), ConfigGen: decision.ConfigGen,
		Reason: "NFQ capture candidate",
	}
	candidate := classifier.CandidateFromEvidence(decision.FlowKey, candidateEvidence)
	auth, ok := classifier.AuthorizeCandidate(candidate, *decision.Selected, policy, decision.Final || decision.Selected.Source == classifier.EvidenceQUICSNI || decision.Selected.Source == classifier.EvidenceDNSAnswer || decision.Selected.Source == classifier.EvidenceDNSHTTPS, time.Now())
	if ok {
		observability.Default().Trace.Record(observability.TraceEvent{Timestamp: time.Now(), FlowID: fmt.Sprintf("%v", decision.FlowKey), Kind: "action_authorization", Fields: map[string]string{"authorization_id": auth.ID, "set_id": observability.RedactIdentifier(auth.SetID), "source": auth.EvidenceSource.String(), "policy": string(auth.DomainPolicy)}})
	}
	return ok
}
