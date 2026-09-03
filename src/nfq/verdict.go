package nfq

import (
	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/sock"
	"github.com/florianl/go-nfqueue"
)

type verdictCtx struct {
	id       uint32
	q        *nfqueue.Nfqueue
	verdict  engine.PacketVerdict
	offload  OffloadMetadata
	queuedTo uint16
}

const nfQueueBaseVerdict = 3

func nfQueueVerdictFor(queue uint16) int {
	return int((uint32(queue) << 16) | nfQueueBaseVerdict)
}

func (vc *verdictCtx) queueTo(queue uint16) int {
	if vc == nil || queue == 0 {
		return 0
	}
	vc.queuedTo = queue
	if vc.q != nil {
		if err := vc.q.SetVerdict(vc.id, nfQueueVerdictFor(queue)); err != nil {
			log.Tracef("failed to queue packet %d to NFQUEUE %d: %v", vc.id, queue, err)
		}
	}
	return 0
}

func (vc *verdictCtx) accept() int {
	vc.verdict = engine.VerdictAccept
	if vc.q != nil {
		if err := vc.q.SetVerdict(vc.id, nfqueue.NfAccept); err != nil {
			log.Tracef("failed to set verdict on packet %d: %v", vc.id, err)
		}
	}
	return 0
}

func (vc *verdictCtx) drop() bool {
	vc.verdict = engine.VerdictDrop
	if vc.q != nil {
		if err := vc.q.SetVerdict(vc.id, nfqueue.NfDrop); err != nil {
			log.Tracef("failed to set drop verdict on packet %d: %v", vc.id, err)
			return false
		}
	}
	return true
}

func (w *Worker) InitSender() error {
	if w.sock != nil {
		return nil
	}
	cfg := w.getConfig()
	reinjectMark := int(capture.ProcessedMarkFor(cfg.Queue.Mark))
	tun := cfg.Queue.Mode == "tun"
	if tun {
		reinjectMark |= engine.ReinjectMarkBit
	}
	// In tun mode the TUN interface owns the traffic path, so raw sockets stay
	// unbound; in nfq mode pin injections to the configured WAN uplink.
	device := ""
	if !tun {
		device = cfg.Queue.OutDevice()
	}
	s, err := sock.NewSenderWithMarkDevice(reinjectMark, device)
	if err != nil {
		return err
	}
	w.sock = s
	if tun {
		cs, err := sock.NewSenderWithMark(engine.ClientMark)
		if err != nil {
			w.sock.Close()
			w.sock = nil
			return err
		}
		w.clientSock = cs
	} else {
		cs, err := sock.NewSenderWithMarkDevice(reinjectMark|engine.ClientMark, device)
		if err != nil {
			w.sock.Close()
			w.sock = nil
			return err
		}
		w.clientSock = cs
	}
	return nil
}

func (w *Worker) clientSender() *sock.Sender {
	if w.clientSock != nil {
		return w.clientSock
	}
	return w.sock
}

func (w *Worker) ProcessPacket(raw []byte) engine.PacketVerdict {
	if len(raw) == 0 {
		return engine.VerdictAccept
	}
	vc := &verdictCtx{
		verdict: engine.VerdictAccept,
		offload: OffloadMetadata{PayloadLength: uint32(len(raw)), OriginalLength: uint32(len(raw))},
	}
	w.dispatch(vc, raw)
	return vc.verdict
}
