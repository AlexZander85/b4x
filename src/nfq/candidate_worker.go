package nfq

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/sock"
	"github.com/florianl/go-nfqueue"
)

// StartCandidate binds a dedicated candidate queue. It uses the same packet
// processor as production but wraps it with bounded flow-only canary
// accounting. Packet payloads are never retained by the monitor.
func (w *Worker) StartCandidate() error {
	cfg := w.getConfig()
	mark := cfg.Queue.Mark
	s, err := sock.NewSenderWithMark(int(capture.ProcessedMarkFor(mark)))
	if err != nil {
		return err
	}
	w.sock = s
	cs, err := sock.NewSenderWithMark(int(capture.ProcessedMarkFor(mark)) | engine.ClientMark)
	if err != nil {
		s.Close()
		return err
	}
	w.clientSock = cs

	q, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      w.qnum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
	})
	if err != nil {
		return err
	}
	w.q = q
	if cfg.Queue.IPv4Enabled {
		if err := pfBind(q.Con, syscall.AF_INET); err != nil {
			log.Warnf("candidate nfqueue PF_BIND AF_INET: %v", err)
		}
	}
	if cfg.Queue.IPv6Enabled {
		if err := pfBind(q.Con, syscall.AF_INET6); err != nil {
			log.Warnf("candidate nfqueue PF_BIND AF_INET6: %v", err)
		}
	}

	w.wg.Add(1)
	go w.gc(cfg)
	w.wg.Add(1)
	go func() {
		pid := os.Getpid()
		log.Tracef("candidate NFQ bound pid=%d queue=%d", pid, w.qnum)
		defer w.wg.Done()
		_ = q.RegisterWithErrorFunc(w.ctx,
			func(a nfqueue.Attribute) int { return w.handleCandidatePacket(q, a, mark) },
			func(e error) int { return w.handleNfqError(e) },
		)
	}()
	return nil
}

func (w *Worker) handleCandidatePacket(q *nfqueue.Nfqueue, a nfqueue.Attribute, mark uint) int {
	var pkt *pktInfo
	if a.PacketID != nil && a.Payload != nil && len(*a.Payload) > 0 &&
		(a.Mark == nil || !capture.IsProcessedMark(uint32(*a.Mark), mark)) && w.matchesInterface(a) {
		if parsed, ok := w.parseIPHeaders(*a.Payload); ok {
			pkt = parsed
			if w.canary != nil {
				w.canary.Observe(pkt, w.getConfig())
			}
		}
	}
	result := w.handlePacket(q, a, mark)
	if pkt != nil && w.canary != nil {
		if set := w.candidateSetForPacket(pkt); set != nil {
			target, _ := w.candidateSet.Load().(string)
			if target != "" && set.Id == target {
				w.canary.MarkEligible(pkt, w.getConfig())
			}
		}
	}
	return result
}

func (w *Worker) candidateSetForPacket(pkt *pktInfo) *config.SetConfig {
	if w == nil || pkt == nil {
		return nil
	}
	cfg := w.getConfig()
	matcher := w.getMatcher()
	if matched, set := matcher.MatchIPWithSource(pkt.dst, pkt.srcMac); matched {
		return set
	}
	if len(pkt.raw) < pkt.ihl+4 {
		return nil
	}
	sport := binary.BigEndian.Uint16(pkt.raw[pkt.ihl : pkt.ihl+2])
	dport := binary.BigEndian.Uint16(pkt.raw[pkt.ihl+2 : pkt.ihl+4])
	if pkt.proto == 6 && w.connTracker != nil {
		key := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
		if set := w.connTracker.GetSetForOutgoing(key); set != nil {
			return set
		}
	}
	if hintSet, ok := w.matchScopedDNSHint(cfg, pkt, sport, dport, pkt.proto); ok {
		return hintSet
	}
	return nil
}

func (t *connStateTracker) GetSetForOutgoing(connKey string) *config.SetConfig {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	info := t.conns[connKey]
	if info == nil {
		return nil
	}
	return info.set
}
