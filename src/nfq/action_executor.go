package nfq

import (
	"context"
	"encoding/binary"
	"errors"
	"net"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/log"
)

// packetInjector is the minimal raw-packet port consumed by the centralized
// action executor path. *sock.Sender implements it; tests substitute a fake
// so the executor can be verified without raw sockets.
type packetInjector interface {
	SendIPv4(packet []byte, dst net.IP) error
	SendIPv6(packet []byte, dst net.IP) error
}

// executorSenderAdapter bridges the nfq raw injector to action.PacketSender.
// The provenance mark is already applied to the socket via SO_MARK at
// construction time, so the adapter only routes the built packet by version.
type executorSenderAdapter struct {
	injector packetInjector
	dst      net.IP
	v6       bool
}

func (a *executorSenderAdapter) Send(packet []byte, processedMark uint32) error {
	if a == nil || a.injector == nil {
		return errors.New("raw injector unavailable")
	}
	if a.v6 {
		return a.injector.SendIPv6(packet, a.dst)
	}
	return a.injector.SendIPv4(packet, a.dst)
}

// executeActionPlan runs the centralized action pipeline (plan + executor) for
// a normal TCP packet on the no-fragmentation path. It is strictly fail-open:
// any planning, validation, or send failure returns false so the caller keeps
// the legacy direct-send behavior. Returns true only when the executor applied
// every planned write.
func (w *Worker) executeActionPlan(ctx context.Context, raw []byte, dst net.IP, v6 bool) bool {
	if w == nil || w.actionSender == nil || w.actionMark == 0 {
		return false
	}
	if len(raw) < 40 {
		return false
	}
	ipHdrLen := 40
	if !v6 {
		ipHdrLen = int((raw[0] & 0x0F) * 4)
	}
	if len(raw) < ipHdrLen+20 {
		return false
	}
	tcpHdrLen := int((raw[ipHdrLen+12] >> 4) * 4)
	payloadStart := ipHdrLen + tcpHdrLen
	if payloadStart < ipHdrLen+20 || payloadStart >= len(raw) {
		return false
	}
	payload := raw[payloadStart:]
	if len(payload) == 0 {
		return false
	}
	seq := binary.BigEndian.Uint32(raw[ipHdrLen+4 : ipHdrLen+8])

	plan, err := action.Plan(action.PlanInput{
		BaseSequence:  seq,
		Payload:       payload,
		MTU:           1500,
		IPHeaderLen:   ipHdrLen,
		TCPHeaderLen:  tcpHdrLen,
		ProcessedMark: w.actionMark,
	})
	if err != nil || !plan.Valid {
		log.Tracef("action plan unavailable for %s injection: %v (plan.Valid=%t) - legacy send", netAddr(dst, v6), err, plan.Valid)
		return false
	}

	exec := action.NewExecutor(action.ExecutorConfig{
		MTU:           1500,
		MaxWrites:     16,
		MaxBytes:      64 * 1024,
		ProcessedMark: w.actionMark,
	}, &executorSenderAdapter{injector: w.actionSender, dst: dst, v6: v6})
	result := exec.ExecuteContext(ctx, raw, plan)
	if result.Applied {
		log.Tracef("action executor applied %d write(s), %d byte(s) for %s", result.Sent, result.Bytes, netAddr(dst, v6))
		return true
	}
	log.Tracef("action executor failed open for %s (reason=%q) - legacy send", netAddr(dst, v6), result.Reason)
	return false
}

func netAddr(dst net.IP, v6 bool) string {
	if dst == nil {
		return "?"
	}
	if v6 {
		return dst.String() + " (v6)"
	}
	return dst.String() + " (v4)"
}
