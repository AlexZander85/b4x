package nfq

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/quic"
)

func (w *Worker) observePPEPassiveRaw(cfg *config.Config, raw []byte) {
	if w == nil || cfg == nil || len(raw) == 0 {
		return
	}
	pkt, ok := w.parseIPHeaders(raw)
	if !ok {
		return
	}
	switch pkt.proto {
	case 6:
		tcp := pkt.raw[pkt.ihl:]
		if len(tcp) < TCPHeaderMinLen {
			return
		}
		headerLen := int((tcp[12]>>4)&0x0f) * 4
		if headerLen < TCPHeaderMinLen || len(tcp) < headerLen {
			return
		}
		w.observePPEPassiveTCP(cfg, pkt, binary.BigEndian.Uint16(tcp[0:2]), binary.BigEndian.Uint16(tcp[2:4]), tcp, tcp[headerLen:])
	case 17:
		udp := pkt.raw[pkt.ihl:]
		if len(udp) < UDPHeaderLen {
			return
		}
		w.observePPEPassiveUDP(cfg, pkt, binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]), udp[UDPHeaderLen:])
	}
}

type ppePassiveObserver interface {
	Observe(ppe.PassiveObservation)
}

type ppePassiveObserverHolder struct{ observer ppePassiveObserver }

func (w *Worker) SetPPEPassiveObserver(observer ppePassiveObserver) {
	if w == nil {
		return
	}
	if observer == nil {
		w.ppePassiveObserver.Store(nil)
		return
	}
	w.ppePassiveObserver.Store(&ppePassiveObserverHolder{observer: observer})
}

func (p *Pool) SetPPEPassiveObserver(observer ppePassiveObserver) {
	if p == nil {
		return
	}
	for _, worker := range p.Workers {
		worker.SetPPEPassiveObserver(observer)
	}
}

func (w *Worker) observePPEPassiveTCP(cfg *config.Config, pkt *pktInfo, sport, dport uint16, tcp, payload []byte) {
	holder := w.ppePassiveObserver.Load()
	if holder == nil || holder.observer == nil || cfg == nil || pkt == nil || len(tcp) < TCPHeaderMinLen {
		return
	}
	incoming := cfg.IsTCPPort(sport) && containsPPEPort(cfg.System.Classifier.Runtime.Capture.PPE.TCPPorts, sport)
	outgoing := cfg.IsTCPPort(dport) && containsPPEPort(cfg.System.Classifier.Runtime.Capture.PPE.TCPPorts, dport)
	if !incoming && !outgoing {
		return
	}
	flags := tcp[13]
	observation := ppe.PassiveObservation{
		FlowID: flowHash(pkt, sport, dport, incoming, "tcp"), Family: packetFamily(pkt), Protocol: "tcp",
		Direction: ppe.PassiveOutgoing, Sequence: binary.BigEndian.Uint32(tcp[4:8]), HasSequence: true,
		SYN: flags&0x02 != 0, ACK: flags&0x10 != 0, RST: flags&0x04 != 0,
		PayloadBytes: len(payload), ObservedAt: time.Now(),
	}
	if incoming {
		observation.Direction = ppe.PassiveIncoming
	}
	holder.observer.Observe(observation)
}

func (w *Worker) observePPEPassiveUDP(cfg *config.Config, pkt *pktInfo, sport, dport uint16, payload []byte) {
	holder := w.ppePassiveObserver.Load()
	if holder == nil || holder.observer == nil || cfg == nil || pkt == nil {
		return
	}
	incoming := containsPPEPort(cfg.System.Classifier.Runtime.Capture.PPE.UDPPorts, sport)
	outgoing := containsPPEPort(cfg.System.Classifier.Runtime.Capture.PPE.UDPPorts, dport)
	if !incoming && !outgoing {
		return
	}
	observation := ppe.PassiveObservation{
		FlowID: flowHash(pkt, sport, dport, incoming, "udp"), Family: packetFamily(pkt), Protocol: "udp",
		Direction: ppe.PassiveOutgoing, PayloadBytes: len(payload), QUIC: quic.LooksLikeQUIC(payload), ObservedAt: time.Now(),
	}
	if incoming {
		observation.Direction = ppe.PassiveIncoming
	}
	holder.observer.Observe(observation)
}

func containsPPEPort(ports []uint16, port uint16) bool {
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func packetFamily(pkt *pktInfo) string {
	if pkt != nil && pkt.ver == IPv6 {
		return "ipv6"
	}
	return "ipv4"
}

func flowHash(pkt *pktInfo, sport, dport uint16, incoming bool, protocol string) string {
	clientIP, serverIP := pkt.srcStr, pkt.dstStr
	clientPort, serverPort := sport, dport
	if incoming {
		clientIP, serverIP = pkt.dstStr, pkt.srcStr
		clientPort, serverPort = dport, sport
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s:%d|%s:%d", packetFamily(pkt), protocol, clientIP, clientPort, serverIP, serverPort)))
	return hex.EncodeToString(sum[:12])
}
