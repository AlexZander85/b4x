package config

import (
	"errors"
	"reflect"
	"testing"
)

func TestPPEConfigDefaultsAndNormalizesPorts(t *testing.T) {
	cfg := DefaultConfig
	cfg.System.Classifier = DefaultClassifierConfig
	cfg.System.Classifier.Runtime = DefaultClassifierRuntimeConfig
	cfg.System.Classifier.Runtime.Capture.PPE.TCPPorts = []uint16{443, 80, 443, 0}
	cfg.System.Classifier.Runtime.Capture.PPE.UDPPorts = []uint16{443, 443}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ppe := cfg.System.Classifier.Runtime.Capture.PPE
	if !reflect.DeepEqual(ppe.TCPPorts, []uint16{80, 443}) || !reflect.DeepEqual(ppe.UDPPorts, []uint16{443}) {
		t.Fatalf("ports not normalized: tcp=%v udp=%v", ppe.TCPPorts, ppe.UDPPorts)
	}
}

func TestPPEConfigRejectsUnsafeModes(t *testing.T) {
	cfg := DefaultConfig
	cfg.System.Classifier = DefaultClassifierConfig
	cfg.System.Classifier.Runtime = DefaultClassifierRuntimeConfig
	cfg.System.Classifier.Runtime.Capture.OffloadPolicy = "magic"
	cfg.System.Classifier.Runtime.Capture.PPE.ConnskipPackets = 1
	err := cfg.Validate()
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if len(validation.Fields) < 2 {
		t.Fatalf("expected multiple PPE validation fields: %+v", validation.Fields)
	}
}
