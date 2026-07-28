package discovery

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/nfq"
	"github.com/daniellavrushin/b4/tables"
)

// runtimeSandboxBackend is the production adapter for the existing discovery
// runtime. It owns the private config snapshot and the matching NFQUEUE pool;
// the sandbox manager owns the lease and calls this adapter outside its lock.
type runtimeSandboxBackend struct {
	mu   sync.Mutex
	cfg  config.Config
	pool *nfq.Pool
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
	b.mu.Lock()
	b.pool = p
	b.mu.Unlock()
	return nil
}

func (b *runtimeSandboxBackend) Readiness(ctx context.Context, spec SandboxSpec) (QueueReadiness, error) {
	if err := ctx.Err(); err != nil {
		return QueueReadiness{}, err
	}
	b.mu.Lock()
	p := b.pool
	b.mu.Unlock()
	if p == nil {
		return QueueReadiness{Stale: true, Reason: "NFQUEUE pool is not active"}, nil
	}
	queueNumbers := make([]uint16, 0, spec.QueueThreads)
	for i := uint16(0); i < spec.QueueThreads; i++ {
		queueNumbers = append(queueNumbers, spec.QueueStart+i)
	}
	report := capture.CheckQueueReadiness(capture.OSProcFS{}, capture.QueueReadinessSpec{
		QueueNumbers:        queueNumbers,
		ExpectedOwnerPortID: uint32(os.Getpid()),
		RequireOwner:        true,
	})
	queues := make([]QueueOwnerState, 0, len(report.Queues))
	for _, state := range report.Queues {
		queues = append(queues, QueueOwnerState{QueueNumber: state.QueueNumber, OwnerPortID: state.PortID, Expected: uint32(os.Getpid()), Present: true})
	}
	return QueueReadiness{
		CheckedAt:     report.CheckedAt,
		Ready:         report.Ready,
		OwnerVerified: report.OwnerVerified,
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
