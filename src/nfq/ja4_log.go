package nfq

import (
	"fmt"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/sni"
)

// JA4 logging of classified client ClientHellos (Часть 3 П.5; nova-tls
// ja4.rs reference). Read-only: one line per flow, classified sets only, so
// doomed-class fingerprints (phone Cronet ECH GREASE) land next to working
// ones (PC Firefox/clean paths). Answers "does TSPU cut by ECH presence or
// by client signature" once JA4 strings are compared against flow fates.

const (
	ja4FlowTTL  = 15 * time.Minute
	ja4MaxFlows = 1024
)

type ja4Store struct {
	mu    sync.Mutex
	flows map[string]time.Time
}

func newJA4Store() *ja4Store {
	return &ja4Store{flows: make(map[string]time.Time)}
}

func (s *ja4Store) first(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.flows[key]; seen {
		return false
	}
	if len(s.flows) >= ja4MaxFlows {
		for k, ts := range s.flows {
			if now.Sub(ts) > ja4FlowTTL {
				delete(s.flows, k)
			}
		}
	}
	if len(s.flows) >= ja4MaxFlows {
		return false // hard cap: skip rather than churn
	}
	s.flows[key] = now
	return true
}

func (w *Worker) ja4ObserveHandshake(pkt *pktInfo, raw []byte, set *config.SetConfig) {
	if w == nil || w.ja4 == nil || pkt == nil || set == nil || len(raw) < 6 || pkt.ver != IPv4 {
		return
	}
	var pi PacketInfo
	var ok bool
	if pi, ok = ExtractPacketInfoV4(raw); !ok || len(pi.Payload) < 6 {
		return
	}
	meta := sni.ParseTLSClientHelloMetadata(pi.Payload)
	if !meta.Complete && meta.ParseError != "" {
		return
	}
	sport := uint16(raw[pi.IPHdrLen])<<8 | uint16(raw[pi.IPHdrLen+1])
	dport := uint16(raw[pi.IPHdrLen+2])<<8 | uint16(raw[pi.IPHdrLen+3])
	key := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
	now := time.Now()
	if !w.ja4.first(key, now) {
		return
	}
	hello, err := sni.ParseJA4ClientHello(pi.Payload)
	if err != nil {
		log.Tracef("[ja4] parse failed %s: %v", key, err)
		return
	}
	log.Warnf("[ja4] src=%s dst=%s mac=%s set=%s ech=%t ch=%dB ja4=%s",
		pkt.srcStr, pkt.dstStr, pkt.srcMac, setName(set), meta.ECHPresent, len(pi.Payload), hello.JA4())
}
