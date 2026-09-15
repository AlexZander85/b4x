package dnspath

import "testing"

func TestDefaultAdaptivePolicyMatchesAddendum(t *testing.T) {
	p := DefaultAdaptivePolicy()
	if !p.Enabled {
		t.Fatal("adaptive policy must be operational once DNS mode is explicitly switched to adaptive")
	}
	if !p.AllowNativeClassic || !p.AllowNativeEncrypted || !p.AllowManagedDNSCrypt {
		t.Fatalf("default provider families do not match addendum: %+v", p)
	}
	if p.AllowAnonymizedDNSCrypt || p.AllowODoH || p.AllowPQDNSCrypt {
		t.Fatalf("optional expensive/privacy families must remain default-off: %+v", p)
	}
	if !p.RequireNoLogClaim || !p.RequireNoFilterClaim {
		t.Fatalf("default privacy provenance gates must remain enabled: %+v", p)
	}
	if p.Preference != PreferenceBalanced {
		t.Fatalf("preference=%q want balanced", p.Preference)
	}
}
