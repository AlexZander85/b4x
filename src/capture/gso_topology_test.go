package capture

import (
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/packetmark"
)

func TestPlanGSOTopologyAllocatesDisjointRoleRanges(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Queue.StartNum = 537
	cfg.Queue.Threads = 4
	cfg.Queue.IPv6Enabled = true
	cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode = config.GSOModeClassify
	plan, err := PlanGSOTopology(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Production.Start != 537 || plan.Production.End() != 540 {
		t.Fatalf("production range=%+v", plan.Production)
	}
	if plan.Discovery.Start != 541 || plan.Candidate.Start != 542 || plan.Normalizer.Start != 543 {
		t.Fatalf("role ranges not deterministic: %+v", plan)
	}
	if !plan.Normalizer.Enabled || !plan.QueueBypass || !plan.Families.IPv4 || !plan.Families.IPv6 {
		t.Fatalf("unsafe plan: %+v", plan)
	}
	if got := SortedQueueNumbers(plan); len(got) != 7 {
		t.Fatalf("queue count=%d numbers=%v", len(got), got)
	}
}

func TestPlanGSOTopologyRejectsOverlapBoundsAndBudgets(t *testing.T) {
	cases := map[string]func(*config.Config){
		"candidate-discovery-overlap": func(cfg *config.Config) { cfg.System.Classifier.Runtime.Capture.CandidateQueueOffset = 0 },
		"normalizer-overlap":          func(cfg *config.Config) { cfg.System.Classifier.Runtime.Capture.NFQueue.NormalizerQueueOffset = 1 },
		"queue-overflow":              func(cfg *config.Config) { cfg.Queue.StartNum = 65534; cfg.Queue.Threads = 2 },
		"worker-budget":               func(cfg *config.Config) { cfg.System.Classifier.Runtime.Capture.NFQueue.MaxTopologyWorkers = 4 },
		"memory-budget": func(cfg *config.Config) {
			cfg.System.Classifier.Runtime.Capture.NFQueue.MaxTopologyMemoryBytes = 8 * 1024 * 1024
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := config.NewConfig()
			cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode = config.GSOModeClassify
			mutate(&cfg)
			if _, err := PlanGSOTopology(&cfg); err == nil {
				t.Fatal("invalid topology accepted")
			}
		})
	}
}

func TestPlanGSOTopologyOffDoesNotReserveNormalizerWorker(t *testing.T) {
	cfg := config.NewConfig()
	plan, err := PlanGSOTopology(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Normalizer.Enabled {
		t.Fatalf("off mode enabled normalizer: %+v", plan.Normalizer)
	}
	if plan.EstimatedWorkers != cfg.Queue.Threads+2 {
		t.Fatalf("workers=%d", plan.EstimatedWorkers)
	}
}

func TestTransientMarkAllocatorNeverUsesSharedContracts(t *testing.T) {
	extra := uint32(1 << 23)
	allocator := NewTransientMarkAllocator(extra)
	first, err := allocator.Reserve("gso-normalizer")
	if err != nil {
		t.Fatal(err)
	}
	second, err := allocator.Reserve("topology-switch")
	if err != nil {
		t.Fatal(err)
	}
	reserved := packetmark.ProcessedMask | packetmark.CanaryControlMask | extra
	if first == second || first&reserved != 0 || second&reserved != 0 {
		t.Fatalf("leased marks overlap: first=%#x second=%#x reserved=%#x", first, second, reserved)
	}
	if repeat, _ := allocator.Reserve("gso-normalizer"); repeat != first {
		t.Fatalf("owner lease changed: %#x -> %#x", first, repeat)
	}
	allocator.Release("gso-normalizer")
	third, err := allocator.Reserve("replacement")
	if err != nil || third == 0 {
		t.Fatalf("released mark not reusable: %#x %v", third, err)
	}
}

func TestPlanGSOTopologyTransitionDoubleBuffersAllQueues(t *testing.T) {
	active := config.NewConfig()
	candidate := active.CloneForRuntimeUpdate()
	candidate.System.Classifier.Runtime.Capture.NFQueue.GSOMode = config.GSOModeClassify
	oldPlan, err := PlanGSOTopology(&active)
	if err != nil {
		t.Fatal(err)
	}
	next, err := PlanGSOTopologyTransition(&active, candidate)
	if err != nil {
		t.Fatal(err)
	}
	for _, oldRange := range oldPlan.Ranges() {
		for _, nextRange := range next.Ranges() {
			if oldRange.overlaps(nextRange) {
				t.Fatalf("overlap old=%+v next=%+v", oldRange, nextRange)
			}
		}
	}
	if next.Production.Start <= oldPlan.Normalizer.End() {
		t.Fatalf("next production not double buffered: old=%+v next=%+v", oldPlan, next)
	}
}

func TestPlanGSOTopologyFamilyMatrix(t *testing.T) {
	for _, tc := range []struct {
		name   string
		v4, v6 bool
	}{
		{"ipv4-only", true, false}, {"ipv6-only", false, true}, {"dual-stack", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.NewConfig()
			cfg.Queue.IPv4Enabled, cfg.Queue.IPv6Enabled = tc.v4, tc.v6
			plan, err := PlanGSOTopology(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Families.IPv4 != tc.v4 || plan.Families.IPv6 != tc.v6 {
				t.Fatalf("families=%+v", plan.Families)
			}
		})
	}
	cfg := config.NewConfig()
	cfg.Queue.IPv4Enabled, cfg.Queue.IPv6Enabled = false, false
	if _, err := PlanGSOTopology(&cfg); err == nil {
		t.Fatal("empty family matrix accepted")
	}
}
