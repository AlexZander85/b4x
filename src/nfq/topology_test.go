package nfq

import (
	"testing"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
)

func TestGSOQueueTopologySharesTokenStateAndConfiguresRoles(t *testing.T) {
	cfg := config.NewConfig()
	cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode = config.GSOModeClassify
	plan, err := capture.PlanGSOTopology(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	topology, err := NewGSOQueueTopology(&cfg, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer topology.Close()
	if topology.primary == nil || topology.normalizer == nil {
		t.Fatal("topology pools missing")
	}
	if topology.primary.state != topology.normalizer.state {
		t.Fatal("primary and normalizer do not share runtime state")
	}
	for _, worker := range topology.primary.Workers {
		if worker.normalizer || worker.normalizerQueue != plan.Normalizer.Start {
			t.Fatalf("primary worker role=%+v", worker)
		}
	}
	for _, worker := range topology.normalizer.Workers {
		if !worker.normalizer || worker.normalizerQueue != 0 {
			t.Fatalf("secondary worker role=%+v", worker)
		}
	}
	if topology.normalizer.Dhcp != nil {
		t.Fatal("secondary topology started duplicate DHCP ownership")
	}
}

func TestGSOQueueTopologyOffHasNoSecondaryPool(t *testing.T) {
	cfg := config.NewConfig()
	plan, err := capture.PlanGSOTopology(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	topology, err := NewGSOQueueTopology(&cfg, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer topology.Close()
	if topology.normalizer != nil {
		t.Fatal("off mode allocated normalizer pool")
	}
}
