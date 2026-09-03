package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/nfq"
	"github.com/daniellavrushin/b4/tables"
)

// runtimeSandboxBackend is the production adapter for the existing discovery
// runtime. It owns the private config snapshot and the matching NFQUEUE pool;
// the sandbox manager owns the lease and calls this adapter outside its lock.
type runtimeSandboxBackend struct {
	mu           sync.Mutex
	cfg          config.Config
	pool         *nfq.Pool
	ownerPortIDs map[uint16]uint32
}

func newRuntimeSandboxBackend(cfg config.Config) *runtimeSandboxBackend {
	return &runtimeSandboxBackend{cfg: cfg}
}

func (b *runtimeSandboxBackend) Apply(ctx context.Context, spec SandboxSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if spec.HasSourcePortRange() {
		return fmt.Errorf("runtime discovery backend does not support source-port steering")
	}
	if err := tables.ApplyDiscoverySteeringRules(&b.cfg, uint(spec.FlowMark), uint(spec.ProcessedMark), int(spec.QueueStart), int(spec.QueueThreads)); err != nil {
		return err
	}
	discoveryCfg := b.cfg.Clone()
	discoveryCfg.Queue.StartNum = int(spec.QueueStart)
	discoveryCfg.Queue.Threads = int(spec.QueueThreads)
	discoveryCfg.Queue.Mark = uint(spec.ProcessedMark)
	discoveryCfg.Queue.IsDiscovery = true
	discoveryCfg.System.Tables.SkipSetup = true
	for _, set := range discoveryCfg.Sets {
		set.DNS = config.DNSConfig{}
	}
	p := nfq.NewPool(discoveryCfg)
	if err := p.Start(); err != nil {
		tables.ClearDiscoverySteeringRules(&b.cfg, uint(spec.FlowMark), uint(spec.ProcessedMark))
		return fmt.Errorf("start discovery NFQUEUE pool: %w", err)
	}
	// nfq.Worker.Start returns before RegisterWithErrorFunc binds the queue
	// (the bind happens in a worker goroutine). Wait until the sandbox
	// queues appear in /proc/net/netfilter/nfnetlink_queue, otherwise an
	// immediate Readiness check reports the queues as missing.
	//
	// Note: the proc table exposes the netlink portid of the bound socket,
	// not the process pid. Only the first socket of a process happens to
	// have portid == pid; comparing every sandbox queue against
	// os.Getpid() therefore produces false owner mismatches. The sandbox
	// queue numbers are exclusive to this process (nothing else binds
	// them on the router), so queue presence is sufficient to prove the
	// bind completed.
	queueNumbers := make([]uint16, 0, spec.QueueThreads)
	for i := uint16(0); i < spec.QueueThreads; i++ {
		queueNumbers = append(queueNumbers, spec.QueueStart+i)
	}
	deadline := time.Now().Add(5 * time.Second)
	var lastReport capture.QueueReadinessReport
	for {
		report := capture.CheckQueueReadiness(capture.OSProcFS{}, capture.QueueReadinessSpec{
			QueueNumbers: queueNumbers,
		})
		lastReport = report
		if report.Ready {
			break
		}
		if time.Now().After(deadline) {
			p.Stop()
			tables.ClearDiscoverySteeringRules(&b.cfg, uint(spec.FlowMark), uint(spec.ProcessedMark))
			return fmt.Errorf("discovery NFQUEUE pool queues %v not ready within 5s: %s", queueNumbers, runtimeReadinessReason(report))
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The proc table exposes the netlink portid of the bound socket, which
	// only equals the process pid for the process's first socket. Learn the
	// actual portid from the table: these queue numbers are exclusive to
	// this process (nothing else binds them), so the first appearance is
	// necessarily our own worker. Readiness later verifies the owner
	// against the learned portids.
	ownerPortIDs := make(map[uint16]uint32, len(queueNumbers))
	for _, state := range lastReport.Queues {
		ownerPortIDs[state.QueueNumber] = state.PortID
	}
	b.mu.Lock()
	b.pool = p
	b.ownerPortIDs = ownerPortIDs
	b.mu.Unlock()
	return nil
}

func (b *runtimeSandboxBackend) Readiness(ctx context.Context, spec SandboxSpec) (QueueReadiness, error) {
	if err := ctx.Err(); err != nil {
		return QueueReadiness{}, err
	}
	b.mu.Lock()
	p := b.pool
	ownerPortIDs := b.ownerPortIDs
	b.mu.Unlock()
	if p == nil {
		return QueueReadiness{Stale: true, Reason: "NFQUEUE pool is not active"}, nil
	}
	queueNumbers := make([]uint16, 0, spec.QueueThreads)
	for i := uint16(0); i < spec.QueueThreads; i++ {
		queueNumbers = append(queueNumbers, spec.QueueStart+i)
	}
	report := capture.CheckQueueReadiness(capture.OSProcFS{}, capture.QueueReadinessSpec{
		QueueNumbers: queueNumbers,
	})
	queues := make([]QueueOwnerState, 0, len(report.Queues))
	ownerVerified := true
	for _, state := range report.Queues {
		expected, known := ownerPortIDs[state.QueueNumber]
		if !known || state.PortID != expected {
			ownerVerified = false
		}
		queues = append(queues, QueueOwnerState{QueueNumber: state.QueueNumber, OwnerPortID: state.PortID, Expected: expected, Present: true})
	}
	ready := report.Ready && ownerVerified
	return QueueReadiness{
		CheckedAt:     report.CheckedAt,
		Ready:         ready,
		OwnerVerified: ownerVerified,
		Stale:         !report.QueueTableFound || len(report.MissingQueues) > 0,
		Queues:        queues,
		Reason:        runtimeReadinessReason(report),
	}, nil
}

func runtimeReadinessReason(report capture.QueueReadinessReport) string {
	if len(report.Errors) > 0 {
		return report.Errors[0]
	}
	if len(report.MissingQueues) > 0 {
		return fmt.Sprintf("missing queues: %v", report.MissingQueues)
	}
	if len(report.OwnerMismatches) > 0 {
		return fmt.Sprintf("queue owner mismatch: %v", report.OwnerMismatches)
	}
	if !report.Ready {
		return "queue readiness requirements not met"
	}
	return "queue owner verified"
}

func (b *runtimeSandboxBackend) Cleanup(ctx context.Context, spec SandboxSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	p := b.pool
	b.pool = nil
	b.mu.Unlock()
	if p != nil {
		p.Stop()
	}
	tables.ClearDiscoverySteeringRules(&b.cfg, uint(spec.FlowMark), uint(spec.ProcessedMark))
	return nil
}

func (b *runtimeSandboxBackend) Pool() *nfq.Pool {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pool
}
