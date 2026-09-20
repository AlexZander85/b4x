package opera

import "testing"

// TestResolveMasqueradePoolDefault locks the field default of 2026-09-20: an
// unset sni_mode resolves to POOL with the built-in neutral pool (the real
// *.sec-tunnel.com name is SNI-filtered in RU). Explicit node/none keep their
// meaning, and a custom pool wins over the built-in one.
func TestResolveMasqueradePoolDefault(t *testing.T) {
	m := ResolveMasquerade("", "", nil, nil, nil, false)
	if m.SNIMode != SNIModePool {
		t.Fatalf("unset sni mode = %q, want %q", m.SNIMode, SNIModePool)
	}
	if len(m.SNIPool) == 0 {
		t.Fatal("pool default must carry a built-in SNIPool")
	}
	if got := m.EffectiveAPISNI("api2.sec-tunnel.com"); got == "" || got == "api2.sec-tunnel.com" {
		t.Fatalf("default API SNI = %q, want a neutral pool name", got)
	}

	m = ResolveMasquerade("browser", "node", nil, nil, nil, false)
	if m.SNIMode != SNIModeNode {
		t.Fatalf("explicit node = %q, want node", m.SNIMode)
	}
	if got := m.EffectiveAPISNI("api2.sec-tunnel.com"); got != "api2.sec-tunnel.com" {
		t.Fatalf("node API SNI = %q, want the real host", got)
	}

	m = ResolveMasquerade("browser", "none", nil, nil, nil, false)
	if m.SNIMode != SNIModeNone {
		t.Fatalf("explicit none = %q, want none", m.SNIMode)
	}

	m = ResolveMasquerade("browser", "pool", []string{"cover.example"}, nil, nil, false)
	if len(m.SNIPool) != 1 || m.SNIPool[0] != "cover.example" {
		t.Fatalf("custom pool = %v, want [cover.example]", m.SNIPool)
	}
}
