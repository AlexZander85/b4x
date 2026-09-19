package config

import "testing"

// b4x-w4c: system.warp.socks5 shape validation.
func TestValidateSocks5Addr(t *testing.T) {
	valid := []string{
		"",
		"host:1080",
		"1.2.3.4:1080",
		"socks5://host:1080",
		"socks5://u:p@host:1080",
		"socks5h://u:p@1.2.3.4:1080",
	}
	for _, s := range valid {
		if err := validateSocks5Addr(s); err != nil {
			t.Errorf("valid %q rejected: %v", s, err)
		}
	}
	invalid := []string{
		"host",
		"http://host:1080",
		"socks5://",
		"socks5://:1080",
		"host:notaport",
		"host:99999",
	}
	for _, s := range invalid {
		if err := validateSocks5Addr(s); err == nil {
			t.Errorf("invalid %q accepted", s)
		}
	}
}

func TestWarpConfigSocks5Effective(t *testing.T) {
	var w WarpConfig
	if w.EffectiveSocks5() != "" {
		t.Fatal("zero value must be empty")
	}
	w.Socks5 = "  socks5://u:p@h:1080  "
	if got := w.EffectiveSocks5(); got != "socks5://u:p@h:1080" {
		t.Fatalf("EffectiveSocks5 = %q", got)
	}
}
