package nfq

import (
	"net"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/routing"
)

// fallbackTestConfig returns a production-shaped config: fallback enabled with
// a proxy policy and isolation metadata (marks + rule table), plus a TProxy
// routing set that exercises the authorized transactional route path.
func fallbackTestConfig() *config.Config {
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	fb := config.DefaultClassifierRuntimeConfig.Fallback
	fb.Enabled = true
	fb.Policy = config.FallbackProxy
	fb.ProxyRouteID = "proxy-a"
	fb.BypassMark = 1 << 29
	fb.GenericMark = 1 << 28
	fb.RuleTable = 100
	cfg.System.Classifier.Runtime.Fallback = fb
	cfg.System.Classifier.Runtime.Capture.ProcessedMarkMask = 1 << 27
	cfg.Queue.Mark = 7
	return &cfg
}

func fallbackTestSet() *config.SetConfig {
	set := config.NewSetConfig()
	set.Id = "youtube"
	set.Name = "youtube"
	set.Enabled = true
	set.Targets.DomainOnly = true
	set.Routing.Enabled = true
	set.Routing.Mode = config.RoutingModeProxy
	return &set
}

func fallbackTestPkt() *pktInfo {
	return &pktInfo{
		ver:    4,
		proto:  capture.ProtocolTCP,
		src:    net.ParseIP("192.0.2.10"),
		dst:    net.ParseIP("198.51.100.1"),
		srcStr: "192.0.2.10",
		dstStr: "198.51.100.1",
		srcMac: "02:00:00:00:00:01",
	}
}

func TestFallbackRouteConfigMapping(t *testing.T) {
	cfg := fallbackTestConfig()
	rc := fallbackRouteConfig(cfg.System.Classifier.Runtime.Fallback, cfg.Queue.Mark)
	if !rc.Enabled {
		t.Fatal("fallback must be enabled")
	}
	if rc.Policy != routing.UnknownRouteProxy {
		t.Fatalf("policy=%v want proxy", rc.Policy)
	}
	if rc.ProxyRouteID != "proxy-a" {
		t.Fatalf("proxy route id=%q", rc.ProxyRouteID)
	}
	if rc.BypassMark != 1<<29 || rc.GenericMark != 1<<28 || rc.RuleTable != 100 {
		t.Fatalf("isolation metadata mismatch: %+v", rc)
	}
	if !rc.Capabilities.ProxyTCP || !rc.Capabilities.IPv4 {
		t.Fatalf("capability matrix must carry defaults: %+v", rc.Capabilities)
	}
	if rc.ProcessedMark != capture.ProcessedMarkFor(7) {
		t.Fatalf("processed mark=%d", rc.ProcessedMark)
	}
	if rc.Cooldown != 30*time.Second || rc.LastGoodTTL != 5*time.Minute {
		t.Fatalf("durations not converted: %+v", rc)
	}
}

func TestNewFallbackManagerFailClosed(t *testing.T) {
	// Disabled fallback -> no manager, no error.
	cfg := config.NewConfig()
	cfg.System.Classifier.Runtime.Fallback = config.DefaultClassifierRuntimeConfig.Fallback // Enabled=false
	m, err := newFallbackManager(&cfg)
	if err != nil || m != nil {
		t.Fatalf("disabled fallback manager=%v err=%v", m, err)
	}
	// Proxy policy without a proxy route id -> fail closed with error.
	cfg.System.Classifier.Runtime.Fallback.Enabled = true
	cfg.System.Classifier.Runtime.Fallback.Policy = config.FallbackProxy
	cfg.System.Classifier.Runtime.Fallback.ProxyRouteID = ""
	m, err = newFallbackManager(&cfg)
	if err == nil || m != nil {
		t.Fatalf("invalid fallback must fail closed: manager=%v err=%v", m, err)
	}
	// Valid enabled config -> manager built.
	good := fallbackTestConfig()
	m, err = newFallbackManager(good)
	if err != nil || m == nil {
		t.Fatalf("valid fallback manager=%v err=%v", m, err)
	}
}

func TestBindAuthorizedRouteConsultsFallbackOnlyAfterAuthorization(t *testing.T) {
	cfg := fallbackTestConfig()
	set := fallbackTestSet()
	worker := NewWorkerWithQueue(cfg, 0)
	worker.routeBindings = routing.NewBindingStore(routing.BindingCapabilities{ExactFlow: true}, 32)
	fallback, err := newFallbackManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	worker.fallback = fallback

	// Unauthorized flow must be rejected before the fallback manager is ever
	// consulted: no binding, no fallback decision.
	observability.Default().Metrics.Reset()
	ok := worker.bindAuthorizedRoute(cfg, fallbackTestPkt(), 12345, 443, capture.ProtocolTCP, set, "youtube.com", classifier.EvidencePacketSNI, 50, false)
	if ok {
		t.Fatal("unauthorized route must be rejected")
	}
	if got := hardGateCounterValue(t, observability.MetricFallbackDecision); got != 0 {
		t.Fatalf("fallback consulted without authorization: metric=%d", got)
	}

	// Authorized flow commits the transactional binding first, then consults
	// the fallback manager inside the same authorized scope.
	observability.Default().Metrics.Reset()
	worker.decisions = routing.NewDecisionStore(0, 0, nil)
	ok = worker.bindAuthorizedRoute(cfg, fallbackTestPkt(), 12345, 443, capture.ProtocolTCP, set, "youtube.com", classifier.EvidencePacketSNI, 50, true)
	if !ok {
		t.Fatal("authorized route must bind")
	}
	if got := hardGateCounterValue(t, observability.MetricFallbackDecision); got == 0 {
		t.Fatal("fallback manager was not consulted after authorization")
	}
	if got := hardGateCounterValue(t, observability.MetricRouteBinding); got == 0 {
		t.Fatal("authorized route binding was not recorded")
	}
	// FB-23: the decision produced by the authorized path must be retained
	// for the transport adapters (SOCKS5/TUN) — written to the shared store,
	// never re-decided by an adapter.
	if n := worker.decisions.Len(); n == 0 {
		t.Fatal("authorized fallback decision was not stored for transport adapters")
	}
}

func TestBindAuthorizedRouteWithoutFallbackKeepsLegacyBehavior(t *testing.T) {
	cfg := fallbackTestConfig()
	set := fallbackTestSet()
	worker := NewWorkerWithQueue(cfg, 0)
	worker.routeBindings = routing.NewBindingStore(routing.BindingCapabilities{ExactFlow: true}, 32)
	// No fallback manager (e.g. fallback disabled): binding still works.
	observable := hardGateCounterValue(t, observability.MetricRouteBinding)
	ok := worker.bindAuthorizedRoute(cfg, fallbackTestPkt(), 12345, 443, capture.ProtocolTCP, set, "youtube.com", classifier.EvidencePacketSNI, 50, true)
	if !ok {
		t.Fatal("authorized route must bind without fallback")
	}
	if got := hardGateCounterValue(t, observability.MetricRouteBinding); got <= observable {
		t.Fatal("route binding metric did not move")
	}
}
