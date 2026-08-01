package ppe

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestRedactProductRuleHidesManagedSet(t *testing.T) {
	got := redactProductRule("-A B4_PPE_PRE -m set --match-set secret_clients src -p tcp -j PPE", "secret_clients")
	if got == "" || got == "-A B4_PPE_PRE -m set --match-set secret_clients src -p tcp -j PPE" {
		t.Fatalf("managed source set was not redacted: %q", got)
	}
	if want := "<managed-source-set>"; !containsText(got, want) {
		t.Fatalf("redaction marker missing: %q", got)
	}
}

func TestFunctionalVerdictMappingDoesNotPromoteLimitedPass(t *testing.T) {
	if got := functionalVerdictFor(VerdictPASSWithLimitations); got != FunctionalInconclusive {
		t.Fatalf("limited PASS mapped to %q", got)
	}
	if got := functionalVerdictFor(VerdictPASS); got != FunctionalPass {
		t.Fatalf("PASS mapped to %q", got)
	}
}

func containsText(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestExecuteIdempotentCoalescesConcurrentMutation(t *testing.T) {
	service := &ProductService{idempotency: make(map[string]*productIdempotencyEntry)}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls int
	operation := func() (ProductStatus, error) {
		calls++
		close(started)
		<-release
		return ProductStatus{Effective: "per-flow-exclusion"}, nil
	}
	firstDone := make(chan ProductStatus, 1)
	secondDone := make(chan ProductStatus, 1)
	go func() { status, _ := service.ExecuteIdempotent("same", operation); firstDone <- status }()
	<-started
	go func() { status, _ := service.ExecuteIdempotent("same", operation); secondDone <- status }()
	close(release)
	first, second := <-firstDone, <-secondDone
	if calls != 1 || first.Effective != second.Effective {
		t.Fatalf("idempotency calls=%d first=%+v second=%+v", calls, first, second)
	}
}

type productBundleRunner struct{}

func (productBundleRunner) ReadFile(string) ([]byte, error)      { return nil, os.ErrNotExist }
func (productBundleRunner) Stat(string) (os.FileInfo, error)     { return nil, os.ErrNotExist }
func (productBundleRunner) LookPath(file string) (string, error) { return file, nil }
func (productBundleRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "-S B4_PPE_PRE"):
		return "-A B4_PPE_PRE -m set --match-set secret_clients src -p tcp -m comment --comment b4:ppe:v1:tcp -j PPE", nil
	case strings.Contains(joined, "-S PREROUTING"):
		return "-A PREROUTING -m comment --comment b4:ppe:v1:jump:pre -j B4_PPE_PRE", nil
	case strings.Contains(joined, "-S B4_PPE_FWD"), strings.Contains(joined, "-S FORWARD"):
		return "", nil
	default:
		return "", errors.New("unexpected command")
	}
}

func TestCollectActualOwnedRulesIsRedacted(t *testing.T) {
	service := &ProductService{runner: productBundleRunner{}}
	desired := DesiredState{ManagedSourceSet: "secret_clients", Families: []FamilyPlan{{Family: "ipv4", Binary: "iptables", Enabled: true, WaitSupported: true}}}
	rules, failures := service.collectActualOwnedRules(context.Background(), desired)
	if len(failures) != 0 || len(rules) != 1 || len(rules[0].Rules) != 2 {
		t.Fatalf("rules=%+v failures=%v", rules, failures)
	}
	for _, rule := range rules[0].Rules {
		if strings.Contains(rule, "secret_clients") {
			t.Fatalf("unredacted managed source set: %q", rule)
		}
	}
}

func TestApplyConfigRejectsSkipTables(t *testing.T) {
	cfg := config.NewConfig()
	cfg.System.Tables.SkipSetup = true
	service := NewProductService(func() *config.Config { return &cfg }, nil, DefaultManagedSourceSet)
	if _, err := service.ApplyConfig(context.Background(), &cfg); err == nil || !strings.Contains(err.Error(), "skip_setup") {
		t.Fatalf("skip-tables PPE apply accepted: %v", err)
	}
}
