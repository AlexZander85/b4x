package nfq

import (
	"net"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestRegisterLearnedRoute_SkipsDomainOnly(t *testing.T) {
	prev := RoutingLearnIPFunc
	defer func() { RoutingLearnIPFunc = prev }()

	var calls int
	RoutingLearnIPFunc = func(cfg *config.Config, set *config.SetConfig, ip net.IP) {
		calls++
	}

	cfg := &config.Config{}
	dst := net.ParseIP("1.2.3.4")

	set := config.NewSetConfig()
	set.Name = "cdn"
	set.Enabled = true
	set.Routing.Enabled = true
	set.Targets.DomainOnly = true
	registerLearnedRoute(cfg, &set, dst)
	if calls != 0 {
		t.Errorf("domain-only set must not register a learned route, got %d calls", calls)
	}

	set.Targets.DomainOnly = false
	registerLearnedRoute(cfg, &set, dst)
	if calls != 1 {
		t.Errorf("non-domain-only set must register a learned route, got %d calls", calls)
	}
}

func TestRegisterEscalatedRouteSkipsDomainOnlySharedEndpoint(t *testing.T) {
	prev := RoutingHandleDNSFunc
	defer func() { RoutingHandleDNSFunc = prev }()
	var calls int
	RoutingHandleDNSFunc = func(cfg *config.Config, set *config.SetConfig, ips []net.IP) { calls++ }
	cfg := &config.Config{}
	set := config.NewSetConfig()
	set.Name = "youtube-next"
	set.Enabled = true
	set.Routing.Enabled = true
	set.Targets.DomainOnly = true
	registerEscalatedRoute(cfg, &set, net.ParseIP("203.0.113.4"))
	if calls != 0 {
		t.Fatalf("domain-scoped escalation created destination-global route: %d", calls)
	}
}
