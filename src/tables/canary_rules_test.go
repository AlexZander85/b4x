package tables

import (
	"testing"

	"github.com/daniellavrushin/b4/capture"
)

func TestCanarySteeringSpecValidation(t *testing.T) {
	spec := CanarySteeringSpec{
		ClientGroup: "ip:192.0.2.10", Protocol: "tcp", Percent: 10,
		FlowMark: uint(capture.CanarySelectedMarkBit), DirectMark: uint(capture.CanaryDirectMarkBit),
		InjectedMark: uint(capture.ProcessedMarkBit | capture.CanaryInjectedMarkBit),
		QueueStart:   100, QueueThreads: 1,
	}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	spec.ClientGroup = "mac:aa:bb:cc:dd:ee:ff"
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	spec.ClientGroup = "all"
	if err := spec.Validate(); err == nil {
		t.Fatal("global canary scope accepted")
	}
	spec.ClientGroup = "device-name"
	if err := spec.Validate(); err == nil {
		t.Fatal("invalid client group accepted")
	}
}

func TestCanarySelectorsPersistSelectedAndDirectDecisions(t *testing.T) {
	spec := CanarySteeringSpec{Protocol: "tcp", Percent: 10, FlowMark: uint(capture.CanarySelectedMarkBit), DirectMark: uint(capture.CanaryDirectMarkBit)}
	selected := canaryIPTSelector("iptables", false, canaryScope{all: true}, spec, "0x0/0x7000000", true)
	direct := canaryIPTSelector("iptables", false, canaryScope{all: true}, spec, "0x0/0x7000000", false)
	if containsToken(direct, "--probability") {
		t.Fatal("direct decision must not be randomized")
	}
	if !containsToken(selected, "--probability") || !containsToken(selected, "--set-xmark") || !containsToken(direct, "--set-xmark") {
		t.Fatalf("selected=%v direct=%v", selected, direct)
	}
}

func containsToken(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
