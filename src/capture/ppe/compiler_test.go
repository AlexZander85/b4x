package ppe

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func compilerConfig() *config.Config {
	cfg := config.DefaultConfig
	cfg.System.Classifier = config.DefaultClassifierConfig
	cfg.System.Classifier.Runtime = config.DefaultClassifierRuntimeConfig
	cfg.System.Classifier.Runtime.Capture.OffloadPolicy = config.OffloadPolicyExclude
	cfg.System.Classifier.Runtime.Capture.PPE.SourceScope = config.PPESourceManagedDevices
	cfg.Sets = []*config.SetConfig{
		{Name: "web", Enabled: true, TCP: config.TCPConfig{DPortFilter: "80,443,8443"}, UDP: config.UDPConfig{DPortFilter: "443"}},
		{Name: "disabled", Enabled: false, TCP: config.TCPConfig{DPortFilter: "2053"}, UDP: config.UDPConfig{DPortFilter: "2053"}},
	}
	return &cfg
}

func supportedCapabilities() CapabilityReport {
	family4 := FamilyCapability{Family: "ipv4", Binary: "iptables", State: CapabilitySupported, TargetRegistered: true, ConnskipUsable: true, MangleAvailable: true, Prerouting: true, Forward: true}
	family6 := FamilyCapability{Family: "ipv6", Binary: "ip6tables", State: CapabilitySupported, TargetRegistered: true, ConnskipUsable: true, MangleAvailable: true, Prerouting: true, Forward: true}
	return CapabilityReport{State: CapabilitySupported, Supported: true, IPv4: family4, IPv6: family6}
}

func TestCompileDeterministicGoldenRestore(t *testing.T) {
	input := CompileInput{Config: compilerConfig(), Capabilities: supportedCapabilities(), ManagedSourceSet: "b4_managed"}
	first, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Generation != second.Generation || !reflect.DeepEqual(first, second) {
		t.Fatal("compiler is not deterministic")
	}
	if !reflect.DeepEqual(first.EffectiveTCPPorts, []uint16{80, 443, 8443}) || !reflect.DeepEqual(first.EffectiveUDPPorts, []uint16{443}) {
		t.Fatalf("unexpected intersection tcp=%v udp=%v", first.EffectiveTCPPorts, first.EffectiveUDPPorts)
	}
	golden, err := os.ReadFile("testdata/ipv4.restore")
	if err != nil {
		t.Fatal(err)
	}
	if first.Families[0].RestoreScript != string(golden) {
		t.Fatalf("restore mismatch\n--- got ---\n%s\n--- want ---\n%s", first.Families[0].RestoreScript, golden)
	}
	if strings.Count(first.Families[0].RestoreScript, CommentJumpPre) != 1 || strings.Count(first.Families[0].RestoreScript, CommentJumpFwd) != 1 {
		t.Fatal("compiler emitted duplicate owned jumps")
	}
	if strings.Contains(first.Families[0].RestoreScript, "CONNMARK") || strings.Contains(first.Families[0].RestoreScript, "--set-mark") {
		t.Fatal("PPE compiler must not persist packet marks")
	}
}

func TestCompileIPv6AutoAndOn(t *testing.T) {
	cfg := compilerConfig()
	caps := supportedCapabilities()
	caps.IPv6 = FamilyCapability{Family: "ipv6", State: CapabilityUnsupported}
	state, err := Compile(CompileInput{Config: cfg, Capabilities: caps, ManagedSourceSet: "b4_managed"})
	if err != nil || state.Families[1].Enabled {
		t.Fatalf("auto IPv6 should skip unsupported family: state=%+v err=%v", state.Families[1], err)
	}
	cfg.System.Classifier.Runtime.Capture.PPE.IPv6 = config.PPEFamilyOn
	_, err = Compile(CompileInput{Config: cfg, Capabilities: caps, ManagedSourceSet: "b4_managed"})
	if !errors.Is(err, ErrFamilyRequiredUnsupported) {
		t.Fatalf("required IPv6 did not fail: %v", err)
	}
}

func TestCompileManagedScopeRequiredBeforePayload(t *testing.T) {
	_, err := Compile(CompileInput{Config: compilerConfig(), Capabilities: supportedCapabilities()})
	if err == nil || !strings.Contains(err.Error(), "source ipset") {
		t.Fatalf("missing managed source scope accepted: %v", err)
	}
}

func TestCompileIPv6ManagedScopeDisabledInAuto(t *testing.T) {
	cfg := compilerConfig() // SourceScope = PPESourceManagedDevices
	state, err := Compile(CompileInput{Config: cfg, Capabilities: supportedCapabilities(), ManagedSourceSet: "b4_managed"})
	if err != nil {
		t.Fatal(err)
	}
	if state.Families[0].Family != "ipv4" || !state.Families[0].Enabled {
		t.Fatalf("IPv4 must stay enabled: %+v", state.Families[0])
	}
	if state.Families[1].Family != "ipv6" || state.Families[1].Enabled {
		t.Fatalf("IPv6 must be disabled under IPv4-only managed scope: %+v", state.Families[1])
	}
	if !strings.Contains(state.Families[1].Reason, "IPv4-only") {
		t.Fatalf("unexpected reason: %q", state.Families[1].Reason)
	}
	cfg.System.Classifier.Runtime.Capture.PPE.IPv6 = config.PPEFamilyOn
	if _, err := Compile(CompileInput{Config: cfg, Capabilities: supportedCapabilities(), ManagedSourceSet: "b4_managed"}); err == nil {
		t.Fatal("required IPv6 with IPv4-only managed scope must fail")
	}
}

func TestExpandPortExpression(t *testing.T) {
	ports, err := expandPortExpression("80,443,1000-1002")
	if err != nil || len(ports) != 5 {
		t.Fatalf("ports=%v err=%v", ports, err)
	}
	if _, err := expandPortExpression("200-100"); err == nil {
		t.Fatal("descending range accepted")
	}
}
