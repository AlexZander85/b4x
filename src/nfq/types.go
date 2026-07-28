package nfq

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/dhcp"
	"github.com/daniellavrushin/b4/lab"
	"github.com/daniellavrushin/b4/sock"
	"github.com/florianl/go-nfqueue"
)

type Segment struct {
	Data []byte
	Seq  uint32
}

type Pool struct {
	Workers     []*Worker
	configMu    sync.Mutex
	Dhcp        *dhcp.Manager
	stopCleanup chan struct{}
	state       *runtimeState
	tunSrc      *tunSrcResolver
}

type PacketInfo struct {
	IPHdrLen     int
	TCPHdrLen    int
	PayloadStart int
	PayloadLen   int
	Payload      []byte
	Seq0         uint32
	ID0          uint16
	IsIPv6       bool
}

type Worker struct {
	packetsProcessed uint64
	lastOverflowLog  int64
	cfg              atomic.Value
	qnum             uint16
	ctx              context.Context
	cancel           context.CancelFunc
	q                *nfqueue.Nfqueue
	wg               sync.WaitGroup
	matcher          atomic.Value
	sock             *sock.Sender
	clientSock       *sock.Sender
	ipToMac          atomic.Value
	tlsCache         *tlsInfoCache
	connTracker      *connStateTracker
	destState        *destStateTracker
	srcResolver      *tunSrcResolver
	dnsHints         *classifier.HostHintStore
	tcpReassembly    *classifier.TCPReassemblyStore
	tcpHold          *TCPHoldStore
	clientHelloSink  atomic.Pointer[clientHelloSinkHolder]
}

type clientHelloSinkHolder struct {
	sink lab.SegmentSink
}

// SetClientHelloSink attaches an observe-only laboratory bridge. A full sink
// is handled as diagnostic loss by the sink implementation and never delays
// packet processing or changes the production verdict.
func (w *Worker) SetClientHelloSink(sink lab.SegmentSink) {
	if w == nil {
		return
	}
	if sink == nil {
		w.clientHelloSink.Store(nil)
		return
	}
	w.clientHelloSink.Store(&clientHelloSinkHolder{sink: sink})
}

func (w *Worker) getClientHelloSink() lab.SegmentSink {
	if w == nil {
		return nil
	}
	holder := w.clientHelloSink.Load()
	if holder == nil {
		return nil
	}
	return holder.sink
}

func (p *Pool) SetClientHelloSink(sink lab.SegmentSink) {
	if p == nil {
		return
	}
	for _, worker := range p.Workers {
		worker.SetClientHelloSink(sink)
	}
}
