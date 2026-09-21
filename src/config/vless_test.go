package config

import "testing"

func TestValidateVLESSFields(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Vless.Enabled = false
	cfg.System.Vless.Nodes = []string{
		"vless://11111111-1111-1111-1111-111111111111@h.example.org:443?type=tcp&security=tls&sni=www.microsoft.com#x",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("baseline vless config rejected: %v", err)
	}

	// mixed with the default helper (xray) must fail early.
	cfg.System.Vless.Mixed = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("mixed with helper=xray must fail validation")
	}
	cfg.System.Vless.Helper = VLESSHelperSingbox
	if err := cfg.Validate(); err != nil {
		t.Fatalf("mixed with sing-box should pass: %v", err)
	}

	// client enum.
	cfg.System.Vless.Client = "bogus"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid client must fail validation")
	}
	cfg.System.Vless.Client = VLESSClientAuto

	// pin_node must be host:port.
	cfg.System.Vless.PinNode = "not-a-hostport"
	if err := cfg.Validate(); err == nil {
		t.Fatal("bad pin_node must fail validation")
	}
	cfg.System.Vless.PinNode = "203.0.113.9:443"

	// bad node syntax.
	cfg.System.Vless.Nodes = []string{"vless://u@host"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("bad node must fail validation")
	}
}
