package nfq

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
)

// GSOQueueTopology owns the listeners for one prospective generation. Firewall
// ownership is intentionally external so workers can be proven ready before a
// single packet is steered to them.
type GSOQueueTopology struct {
	mu         sync.Mutex
	plan       capture.GSOTopologyPlan
	cfg        *config.Config
	primary    *Pool
	normalizer *Pool
	startedP   bool
	startedN   bool
	closed     bool
}

func NewGSOQueueTopology(cfg *config.Config, plan capture.GSOTopologyPlan) (*GSOQueueTopology, error) {
	if cfg == nil {
		return nil, errors.New("GSO queue topology config is nil")
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	primaryCfg := cfg.Clone()
	primaryCfg.Queue.StartNum = int(plan.Production.Start)
	primaryCfg.Queue.Threads = int(plan.Production.Threads)
	primaryCfg.System.Tables.SkipSetup = true
	var normalizerQueue uint16
	if plan.Normalizer.Enabled {
		normalizerQueue = plan.Normalizer.Start
	}
	primary := NewGSOPrimaryPool(primaryCfg, normalizerQueue)
	var normalizer *Pool
	if plan.Normalizer.Enabled {
		normalizerCfg := cfg.Clone()
		normalizerCfg.Queue.StartNum = int(plan.Normalizer.Start)
		normalizerCfg.Queue.Threads = int(plan.Normalizer.Threads)
		normalizerCfg.System.Tables.SkipSetup = true
		normalizerCfg.Queue.IsDiscovery = false
		normalizer = NewGSONormalizerPool(normalizerCfg, primary)
		if normalizer == nil {
			primary.Stop()
			return nil, errors.New("construct GSO normalizer pool")
		}
	}
	return &GSOQueueTopology{plan: plan, cfg: cfg.Clone(), primary: primary, normalizer: normalizer}, nil
}

func (t *GSOQueueTopology) StartSecondary(ctx context.Context) error {
	if t == nil {
		return errors.New("GSO topology is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("GSO topology is closed")
	}
	if t.normalizer == nil || t.startedN {
		return nil
	}
	if err := t.normalizer.Start(); err != nil {
		return fmt.Errorf("start GSO normalizer queues: %w", err)
	}
	t.startedN = true
	return nil
}

func (t *GSOQueueTopology) StartClassifier(ctx context.Context) error {
	if t == nil || t.primary == nil {
		return errors.New("GSO classifier topology is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("GSO topology is closed")
	}
	if t.plan.Normalizer.Enabled && !t.startedN {
		return errors.New("normalizer queues must start before GSO classifier queues")
	}
	if t.startedP {
		return nil
	}
	t.primary.StartDHCP(t.cfg)
	if err := t.primary.Start(); err != nil {
		return fmt.Errorf("start GSO classifier queues: %w", err)
	}
	t.startedP = true
	return nil
}

func (t *GSOQueueTopology) Readiness(role capture.TopologyQueueRole) capture.QueueReadinessReport {
	if t == nil {
		return capture.QueueReadinessReport{Errors: []string{"GSO topology is nil"}}
	}
	rangeSpec, ok := t.plan.Range(role)
	if !ok || !rangeSpec.Enabled {
		return capture.QueueReadinessReport{Ready: true, QueueTableFound: true, OwnerVerified: true}
	}
	return capture.CheckQueueReadiness(capture.OSProcFS{}, capture.QueueReadinessSpec{
		QueueNumbers: rangeSpec.Numbers(), ExpectedOwnerPortID: uint32(os.Getpid()), RequireOwner: true,
	})
}

func (t *GSOQueueTopology) Primary() *Pool {
	if t == nil {
		return nil
	}
	return t.primary
}

func (t *GSOQueueTopology) Plan() capture.GSOTopologyPlan {
	if t == nil {
		return capture.GSOTopologyPlan{}
	}
	return t.plan
}

func (t *GSOQueueTopology) ReleaseHeldUnchanged(reason string) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, pool := range []*Pool{t.primary, t.normalizer} {
		if pool == nil {
			continue
		}
		for _, worker := range pool.Workers {
			if worker.tcpHold != nil {
				count += worker.tcpHold.ReleaseAll(reason)
			}
		}
	}
	return count
}

func (t *GSOQueueTopology) InvalidateTokens() int {
	if t == nil || t.primary == nil || t.primary.state == nil {
		return 0
	}
	count := 0
	if t.primary.state.gsoPassTokens != nil {
		count += t.primary.state.gsoPassTokens.Clear()
	}
	if t.primary.state.actionTokens != nil {
		count += t.primary.state.actionTokens.Clear()
	}
	return count
}

func (t *GSOQueueTopology) Close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	primary, normalizer := t.primary, t.normalizer
	t.primary, t.normalizer = nil, nil
	t.mu.Unlock()
	if primary != nil {
		primary.Stop()
	}
	if normalizer != nil {
		normalizer.Stop()
	}
}
