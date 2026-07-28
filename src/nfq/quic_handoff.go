package nfq

import (
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
)

const quicTCPHandoffTTL = 90 * time.Second

func (w *Worker) observeQUICHandoff(cfg *config.Config, pkt *pktInfo, destinationPort uint16, host string, set *config.SetConfig) {
	w.observeQUICHandoffAt(cfg, pkt, destinationPort, host, set, time.Now())
}

// observeQUICHandoff stores both the source-scoped UDP QUIC SNI evidence and
// its short-lived TCP fallback mirror. It intentionally does not call the
// legacy global learned-IP path.
func (w *Worker) observeQUICHandoffAt(cfg *config.Config, pkt *pktInfo, destinationPort uint16, host string, set *config.SetConfig, now time.Time) {
	if cfg == nil || !cfg.System.Classifier.Flags.QUICToTCPHandoffEnabled || w.dnsHints == nil || pkt == nil || set == nil || host == "" {
		return
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return
	}
	setID := set.Id
	if setID == "" {
		setID = set.Name
	}
	for _, protocol := range []uint8{17, 6} {
		if protocol == 17 && !set.MatchesUDPDPort(destinationPort) {
			continue
		}
		if protocol == 6 && !set.MatchesTCPDPort(destinationPort) {
			continue
		}
		evidence := classifier.Evidence{
			Source:          classifier.EvidenceQUICSNI,
			Client:          client,
			DestinationIP:   netIPToAddr(pkt.dst),
			DestinationPort: destinationPort,
			L4Proto:         protocol,
			SourceDevice:    pkt.srcMac,
			Domain:          host,
			SetID:           setID,
			Confidence:      94,
			DomainEvidence:  true,
			CreatedAt:       now,
			ExpiresAt:       now.Add(quicTCPHandoffTTL),
			ConfigGen:       dnsHintConfigGeneration(cfg),
			Reason:          "source-scoped QUIC SNI with TCP fallback mirror",
		}
		_ = w.dnsHints.Observe(evidence)
		diagnostics.Default().UpdateEvidence(client, evidence.DestinationIP, destinationPort, protocol, []classifier.Evidence{evidence})
	}
}
