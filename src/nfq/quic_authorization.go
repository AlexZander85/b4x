package nfq

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

type quicActionGate struct {
	ID         string
	Authorized bool
	SetID      string
	Source     classifier.EvidenceSource
	Reason     string
}

func newQUICActionGate(cfg *config.Config, pkt *pktInfo, sport, dport uint16, set *config.SetConfig, source classifier.EvidenceSource, authorized bool, reason string) quicActionGate {
	gate := quicActionGate{Authorized: authorized, SetID: classifierSetID(set), Source: source, Reason: reason}
	if cfg == nil || pkt == nil || set == nil {
		return gate
	}
	client, _ := dnsClientKey(pkt.src, pkt.srcMac)
	flow := classifier.NewFlowKey(client, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), sport, dport, 17)
	sum := sha256.Sum256([]byte(fmt.Sprintf("%v|%s|%d|%s", flow, gate.SetID, dnsHintConfigGeneration(cfg), source.String())))
	gate.ID = hex.EncodeToString(sum[:8])
	observability.Default().Trace.Record(observability.TraceEvent{
		Timestamp: time.Now(), FlowID: fmt.Sprintf("%v", flow), Kind: "quic_action_authorization",
		Fields: map[string]string{"authorization_id": gate.ID, "set_id": observability.RedactIdentifier(gate.SetID), "source": source.String(), "result": fmt.Sprintf("%t", authorized), "reason": strings.TrimSpace(reason)},
	})
	return gate
}

func quicSetCanUseGlobalFallback(cfg *config.Config, set *config.SetConfig) bool {
	if set == nil {
		return false
	}
	return !set.Targets.DomainOnly || classifierSetDomainPolicy(cfg, classifierSetID(set)) == classifier.DomainPolicyDisabled
}
