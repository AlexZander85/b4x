package nfq

import (
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
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
	if cfg == nil || pkt == nil {
		return classifier.Decide(classifier.DecisionContext{Now: time.Now()}, input, classifier.DefaultConfidenceThresholds)
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
		Now:             now,
		Client:          client,
		ConfigGen:       dnsHintConfigGeneration(cfg),
		DestinationPort: port,
		L4Proto:         proto,
		SourceDevice:    pkt.srcMac,
		FlowKey:         flow,
		DomainOnlyMode:  classifierDomainOnlyMode(cfg),
		DomainOnlySet:   func(setID string) bool { return classifierSetIsDomainOnly(cfg, setID) },
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
	log.Tracef("classifier decision phase=%s evidence=%v selected=%s confidence=%d domain_only=%s/%s set=%s strategy=%s reason=%s",
		decision.Phase, evidence, selected, decision.Confidence, decision.DomainOnlyMode, decision.DomainOnlyResult, setName, strategy, decision.Reason)
}

func (w *Worker) allowNFQDomainDecision(cfg *config.Config, pkt *pktInfo, port uint16, proto uint8, set *config.SetConfig, source classifier.EvidenceSource, domain string, domainEvidence bool, strategy string) bool {
	if set == nil || !classifierDecisionEnabled(cfg) || classifierDomainOnlyMode(cfg) == classifier.DomainLegacy {
		return true
	}
	decision := w.decideNFQEvidence(cfg, pkt, port, proto, classifier.Evidence{
		Source:         source,
		Domain:         domain,
		SetID:          classifierSetID(set),
		Confidence:     0,
		DomainEvidence: domainEvidence,
		Reason:         "NFQ packet decision integration",
	})
	traceNFQDecision(decision, set, strategy)
	if classifierDomainOnlyMode(cfg) == classifier.DomainDisabled || !set.Targets.DomainOnly {
		return true
	}
	return decision.CanClassify(classifier.DefaultConfidenceThresholds) && decision.Selected != nil && decision.Selected.SetID == classifierSetID(set)
}
