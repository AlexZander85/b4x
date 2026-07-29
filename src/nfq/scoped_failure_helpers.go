package nfq

import (
	"strings"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
)

func scopedFailureKey(cfg *config.Config, pkt *pktInfo, port uint16, proto uint8, set *config.SetConfig, domain string) (classifier.ScopedFailureKey, bool) {
	if cfg == nil || pkt == nil || set == nil || strings.TrimSpace(domain) == "" {
		return classifier.ScopedFailureKey{}, false
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return classifier.ScopedFailureKey{}, false
	}
	return classifier.ScopedFailureKey{Client: client, DestinationIP: netIPToAddr(pkt.dst), DestinationPort: port, L4Proto: proto, SetID: classifierSetID(set), DomainKey: domain, ConfigGen: dnsHintConfigGeneration(cfg)}, true
}
func scopedEscalationKey(cfg *config.Config, pkt *pktInfo, set *config.SetConfig, domain string) (classifier.ScopedEscalationKey, bool) {
	if cfg == nil || pkt == nil || set == nil || strings.TrimSpace(domain) == "" {
		return classifier.ScopedEscalationKey{}, false
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return classifier.ScopedEscalationKey{}, false
	}
	return classifier.ScopedEscalationKey{Client: client, DomainKey: domain, SetID: classifierSetID(set), ConfigGen: dnsHintConfigGeneration(cfg)}, true
}
