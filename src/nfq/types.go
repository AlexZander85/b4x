package nfq

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/dhcp"
	"github.com/daniellavrushin/b4/lab"
	"github.com/daniellavrushin/b4/routing"
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
	canary      *CanaryMonitor
	candidate   bool
	ownsState   bool
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
	packetsProcessed   uint64
	lastOverflowLog    int64
	cfg                atomic.Value
	qnum               uint16
	candidate          bool
	ctx                context.Context
	cancel             context.CancelFunc
	q                  *nfqueue.Nfqueue
	wg                 sync.WaitGroup
	matcher            atomic.Value
	sock               *sock.Sender
	clientSock         *sock.Sender
	ipToMac            atomic.Value
	tlsCache           *tlsInfoCache
	connTracker        *connStateTracker
	destState          *destStateTracker
	scopedFailures     *scopedFailureState
	routeBindings      *routing.BindingStore
	fallback           *routing.FallbackManager
	decisions          *routing.DecisionStore
	srcResolver        *tunSrcResolver
	dnsHints           *classifier.HostHintStore
	tcpReassembly      *classifier.TCPReassemblyStore
	tcpHold            *TCPHoldStore
	clientHelloClaims  *clientHelloDecisionClaimStore
	canary             *CanaryMonitor
	candidateSet       atomic.Value // string; target set for candidate accounting
	clientHelloSink    atomic.Pointer[clientHelloSinkHolder]
	fakeProfileSource  atomic.Pointer[fakeProfileSourceHolder]
	ppePassiveObserver atomic.Pointer[ppePassiveObserverHolder]
	gsoCapability      atomic.Value // GSOCapabilityStatus
	gsoPassTokens      *GSOPassTokenStore
	actionTokens       *action.ActionTokenStore
	actionSender       packetInjector // raw injector for the centralized action executor (nil until Start)
	actionMark         uint32         // processed provenance mark used for action plans
	passiveRST         *PassiveRSTStore
	normalizerQueue    uint16
	normalizer         bool
	gsoReadinessMu     sync.Mutex
	gsoReadinessEv     GSOReadinessEvidence
	gsoReadinessSnap   GSOReadinessSnapshot
	gsoInstanceID      string
}

type clientHelloSinkHolder struct {
	sink lab.SegmentSink
}

// FakeProfileSource is the lab-profile loader interface consumed by the Level C
// fake techniques. The interface lives in nfq (not discovery) so the compiled
// profile catalog can implement it without creating an import cycle.
type FakeProfileSource interface {
	// SelectFakeProfile returns the best verified fake profile for a real
	// target. The second return value reports availability; a miss must fail
	// the caller open to its legacy path.
	SelectFakeProfile(target string) (lab.CompiledArtifact, bool)
}

type fakeProfileSourceHolder struct {
	source FakeProfileSource
}

// SetFakeProfileSource binds the compiled fake profile loader used by Level C
// fake techniques. A nil source keeps the fake strategies fail-open while the
// interface stays reachable in the packet path.
func (w *Worker) SetFakeProfileSource(source FakeProfileSource) {
	if w == nil {
		return
	}
	if source == nil {
		w.fakeProfileSource.Store(nil)
		return
	}
	w.fakeProfileSource.Store(&fakeProfileSourceHolder{source: source})
}

func (w *Worker) getFakeProfileSource() FakeProfileSource {
	holder := w.fakeProfileSource.Load()
	if holder == nil {
		return nil
	}
	return holder.source
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

// SetFakeProfileSource binds the compiled fake profile source to every worker
// so Level C fake techniques can load verified profiles at plan time.
func (p *Pool) SetFakeProfileSource(source FakeProfileSource) {
	if p == nil {
		return
	}
	for _, worker := range p.Workers {
		worker.SetFakeProfileSource(source)
	}
}
