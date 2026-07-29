package nfq

import (
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

func (w *Worker) observeScopedLearnedObservation(cfg *config.Config, pkt *pktInfo, port uint16, proto uint8, host string, set *config.SetConfig, source classifier.EvidenceSource) {
	if w == nil || w.dnsHints == nil || cfg == nil || pkt == nil || set == nil || host == "" {
		return
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return
	}
	now := time.Now()
	observation := classifier.ScopedLearnedObservation{
		Client: client, DestinationIP: netIPToAddr(pkt.dst), L4Proto: proto, Domain: host,
		SetID: classifierSetID(set), Source: source, Confidence: 50, CreatedAt: now,
		ExpiresAt: now.Add(90 * time.Second), ConfigGen: dnsHintConfigGeneration(cfg),
	}
	if err := w.dnsHints.Observe(observation.Evidence()); err != nil {
		observability.Default().Metrics.Inc("legacy_scope_rejected_total", map[string]string{"path": "scoped_observation"}, 1)
	}
}
