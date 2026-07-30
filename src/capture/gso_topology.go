package capture

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/packetmark"
)

// TopologyQueueRole names an owned NFQUEUE range. The roles are deliberately
// distinct even when a role is idle so config validation can reject future
// collisions before any listener or firewall rule is installed.
type TopologyQueueRole string

const (
	TopologyQueueProduction TopologyQueueRole = "production"
	TopologyQueueDiscovery  TopologyQueueRole = "discovery"
	TopologyQueueCandidate  TopologyQueueRole = "candidate"
	TopologyQueueNormalizer TopologyQueueRole = "normalizer"
)

type QueueRange struct {
	Role    TopologyQueueRole `json:"role"`
	Start   uint16            `json:"start"`
	Threads uint16            `json:"threads"`
	Enabled bool              `json:"enabled"`
}

func (r QueueRange) End() uint16 {
	if r.Threads == 0 {
		return r.Start
	}
	return r.Start + r.Threads - 1
}

func (r QueueRange) Numbers() []uint16 {
	if !r.Enabled || r.Threads == 0 {
		return nil
	}
	out := make([]uint16, 0, r.Threads)
	for i := uint16(0); i < r.Threads; i++ {
		out = append(out, r.Start+i)
	}
	return out
}

func (r QueueRange) overlaps(other QueueRange) bool {
	// Disabled roles remain reserved so a later mode switch cannot collide
	// with already-owned production/candidate/discovery ranges.
	if r.Threads == 0 || other.Threads == 0 {
		return false
	}
	return r.Start <= other.End() && other.Start <= r.End()
}

type FamilyCapability struct {
	IPv4 bool `json:"ipv4"`
	IPv6 bool `json:"ipv6"`
}

// GSOTopologyPlan is immutable runtime topology input. It contains only queue,
// resource and mark ownership facts; live queue handles remain transaction-local.
type GSOTopologyPlan struct {
	Production             QueueRange       `json:"production"`
	Discovery              QueueRange       `json:"discovery"`
	Candidate              QueueRange       `json:"candidate"`
	Normalizer             QueueRange       `json:"normalizer"`
	Families               FamilyCapability `json:"families"`
	QueueBypass            bool             `json:"queue_bypass"`
	NormalizerMechanism    string           `json:"normalizer_mechanism"`
	EstimatedWorkers       int              `json:"estimated_workers"`
	EstimatedMemoryBytes   int64            `json:"estimated_memory_bytes"`
	MaxWorkers             int              `json:"max_workers"`
	MaxMemoryBytes         int64            `json:"max_memory_bytes"`
	RequiresRuleTransition bool             `json:"requires_rule_transition"`
}

func (p GSOTopologyPlan) Ranges() []QueueRange {
	return []QueueRange{p.Production, p.Discovery, p.Candidate, p.Normalizer}
}

func (p GSOTopologyPlan) Range(role TopologyQueueRole) (QueueRange, bool) {
	for _, r := range p.Ranges() {
		if r.Role == role {
			return r, true
		}
	}
	return QueueRange{}, false
}

func (p GSOTopologyPlan) Validate() error {
	if !p.QueueBypass {
		return errors.New("GSO topology requires queue-bypass fail-open behavior")
	}
	if !p.Families.IPv4 && !p.Families.IPv6 {
		return errors.New("GSO topology requires at least one IP family")
	}
	if p.Production.Role != TopologyQueueProduction || !p.Production.Enabled || p.Production.Threads == 0 {
		return errors.New("production queue range is unavailable")
	}
	for _, r := range p.Ranges() {
		if !r.Enabled {
			continue
		}
		if r.Threads == 0 {
			return fmt.Errorf("%s queue range has no workers", r.Role)
		}
		if uint32(r.Start)+uint32(r.Threads)-1 > 65535 {
			return fmt.Errorf("%s queue range overflows uint16", r.Role)
		}
	}
	ranges := p.Ranges()
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[i].overlaps(ranges[j]) {
				return fmt.Errorf("NFQUEUE ranges overlap: %s=%d-%d %s=%d-%d",
					ranges[i].Role, ranges[i].Start, ranges[i].End(), ranges[j].Role, ranges[j].Start, ranges[j].End())
			}
		}
	}
	if p.EstimatedWorkers > p.MaxWorkers {
		return fmt.Errorf("GSO topology worker budget exceeded: %d > %d", p.EstimatedWorkers, p.MaxWorkers)
	}
	if p.EstimatedMemoryBytes > p.MaxMemoryBytes {
		return fmt.Errorf("GSO topology memory budget exceeded: %d > %d", p.EstimatedMemoryBytes, p.MaxMemoryBytes)
	}
	if p.Normalizer.Enabled && p.NormalizerMechanism != config.GSONormalizerDirectQueue {
		return fmt.Errorf("normalizer mechanism %q is not target-certified", p.NormalizerMechanism)
	}
	return nil
}

func PlanGSOTopology(cfg *config.Config) (GSOTopologyPlan, error) {
	if cfg == nil {
		return GSOTopologyPlan{}, errors.New("GSO topology config is nil")
	}
	if cfg.Queue.StartNum < 0 || cfg.Queue.Threads < 1 {
		return GSOTopologyPlan{}, errors.New("production queue range is invalid")
	}
	nfq := cfg.System.Classifier.Runtime.Capture.NFQueue
	production, err := queueRangeFromOffset(TopologyQueueProduction, cfg.Queue.StartNum, cfg.Queue.Threads, 0, cfg.Queue.Threads, true)
	if err != nil {
		return GSOTopologyPlan{}, err
	}
	discovery, err := queueRangeFromOffset(TopologyQueueDiscovery, cfg.Queue.StartNum, cfg.Queue.Threads, nfq.DiscoveryQueueOffset, nfq.DiscoveryThreads, true)
	if err != nil {
		return GSOTopologyPlan{}, err
	}
	candidate, err := queueRangeFromOffset(TopologyQueueCandidate, cfg.Queue.StartNum, cfg.Queue.Threads, cfg.System.Classifier.Runtime.Capture.CandidateQueueOffset, 1, true)
	if err != nil {
		return GSOTopologyPlan{}, err
	}
	normalizerEnabled := nfq.NormalizeForMutation && (nfq.GSOMode == config.GSOModeClassify || nfq.GSOMode == config.GSOModeFull)
	normalizer, err := queueRangeFromOffset(TopologyQueueNormalizer, cfg.Queue.StartNum, cfg.Queue.Threads, nfq.NormalizerQueueOffset, nfq.NormalizerThreads, normalizerEnabled)
	if err != nil {
		return GSOTopologyPlan{}, err
	}
	workers := int(production.Threads + discovery.Threads + candidate.Threads)
	if normalizer.Enabled {
		workers += int(normalizer.Threads)
	}
	perWorker := int64(cfg.System.Classifier.Runtime.Reassembly.MaxBytesTotal +
		cfg.System.Classifier.Runtime.HoldReplay.MaxBytesTotal + nfq.MaxGSOBytes + 256*1024)
	if perWorker < 256*1024 {
		perWorker = 256 * 1024
	}
	plan := GSOTopologyPlan{
		Production: production, Discovery: discovery, Candidate: candidate, Normalizer: normalizer,
		Families:    FamilyCapability{IPv4: cfg.Queue.IPv4Enabled, IPv6: cfg.Queue.IPv6Enabled},
		QueueBypass: cfg.System.Classifier.Runtime.Capture.QueueBypass, NormalizerMechanism: nfq.NormalizerMechanism,
		EstimatedWorkers: workers, EstimatedMemoryBytes: perWorker * int64(workers),
		MaxWorkers: nfq.MaxTopologyWorkers, MaxMemoryBytes: int64(nfq.MaxTopologyMemoryBytes),
		RequiresRuleTransition: normalizer.Enabled || nfq.GSOMode != config.GSOModeOff,
	}
	if err := plan.Validate(); err != nil {
		return GSOTopologyPlan{}, err
	}
	return plan, nil
}

func queueRangeFromOffset(role TopologyQueueRole, base, productionThreads, offset, threads int, enabled bool) (QueueRange, error) {
	start := base
	if role != TopologyQueueProduction {
		start = base + productionThreads + offset
	}
	if start < 0 || threads < 1 || start+threads-1 > 65535 {
		return QueueRange{}, fmt.Errorf("%s queue range is out of bounds: start=%d threads=%d", role, start, threads)
	}
	return QueueRange{Role: role, Start: uint16(start), Threads: uint16(threads), Enabled: enabled}, nil
}

// TransientMarkAllocator leases one-bit packet marks from a caller-supplied
// free mask. It never uses the processed or canary contract and never silently
// reuses an owned bit. Direct-queue normalization does not need a lease.
type TransientMarkAllocator struct {
	free     uint32
	reserved uint32
	leases   map[string]uint32
}

func NewTransientMarkAllocator(additionalReserved uint32) *TransientMarkAllocator {
	reserved := packetmark.ProcessedMask | packetmark.CanaryControlMask | additionalReserved
	return &TransientMarkAllocator{free: ^reserved, reserved: reserved, leases: make(map[string]uint32)}
}

func (a *TransientMarkAllocator) Reserve(owner string) (uint32, error) {
	if a == nil {
		return 0, errors.New("transient mark allocator is nil")
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return 0, errors.New("transient mark owner is empty")
	}
	if mark := a.leases[owner]; mark != 0 {
		return mark, nil
	}
	for bit := uint(31); ; bit-- {
		mark := uint32(1) << bit
		if a.free&mark != 0 {
			a.free &^= mark
			a.leases[owner] = mark
			return mark, nil
		}
		if bit == 0 {
			break
		}
	}
	return 0, errors.New("no transient packet mark is available")
}

func (a *TransientMarkAllocator) Release(owner string) {
	if a == nil {
		return
	}
	if mark := a.leases[owner]; mark != 0 {
		delete(a.leases, owner)
		if mark&a.reserved == 0 {
			a.free |= mark
		}
	}
}

func (a *TransientMarkAllocator) Snapshot() map[string]uint32 {
	out := make(map[string]uint32, len(a.leases))
	for owner, mark := range a.leases {
		out[owner] = mark
	}
	return out
}

func SortedQueueNumbers(plan GSOTopologyPlan) []uint16 {
	var out []uint16
	for _, r := range plan.Ranges() {
		out = append(out, r.Numbers()...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// GSOTopologyChanged identifies settings that are fixed when an NFQUEUE socket
// or its firewall ownership is created. These changes cannot be applied by a
// config-pointer swap.
func GSOTopologyChanged(active, candidate *config.Config) bool {
	if active == nil || candidate == nil {
		return true
	}
	a, b := active.System.Classifier.Runtime.Capture, candidate.System.Classifier.Runtime.Capture
	return active.Queue.StartNum != candidate.Queue.StartNum || active.Queue.Threads != candidate.Queue.Threads ||
		active.Queue.IPv4Enabled != candidate.Queue.IPv4Enabled || active.Queue.IPv6Enabled != candidate.Queue.IPv6Enabled ||
		a.QueueBypass != b.QueueBypass || a.CandidateQueueOffset != b.CandidateQueueOffset || a.NFQueue != b.NFQueue
}

// PlanGSOTopologyTransition allocates the next generation entirely outside the
// current generation's reserved ranges. This permits secondary and classifier
// listeners to prove readiness before the atomic rule switch.
func PlanGSOTopologyTransition(active, candidate *config.Config) (GSOTopologyPlan, error) {
	if active == nil || candidate == nil {
		return GSOTopologyPlan{}, errors.New("GSO topology transition requires active and candidate configs")
	}
	oldPlan, err := PlanGSOTopology(active)
	if err != nil {
		return GSOTopologyPlan{}, fmt.Errorf("active topology: %w", err)
	}
	maxEnd := uint16(0)
	for _, r := range oldPlan.Ranges() {
		if r.End() > maxEnd {
			maxEnd = r.End()
		}
	}
	if maxEnd == 65535 {
		return GSOTopologyPlan{}, errors.New("no queue range remains for next topology generation")
	}
	next := candidate.Clone()
	next.Queue.StartNum = int(maxEnd) + 1
	plan, err := PlanGSOTopology(next)
	if err != nil {
		return GSOTopologyPlan{}, fmt.Errorf("next topology: %w", err)
	}
	for _, oldRange := range oldPlan.Ranges() {
		for _, newRange := range plan.Ranges() {
			if oldRange.overlaps(newRange) {
				return GSOTopologyPlan{}, fmt.Errorf("next topology overlaps active %s and %s queues", oldRange.Role, newRange.Role)
			}
		}
	}
	plan.RequiresRuleTransition = true
	return plan, nil
}
