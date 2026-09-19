package warpservice

import (
	"context"
	"net/netip"
	"testing"
)

type fakeCoverRunner struct{ calls [][]string }

func (f *fakeCoverRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return "", nil
}

func (f *fakeCoverRunner) has(want ...string) bool {
	for _, c := range f.calls {
		if len(c) != len(want) {
			continue
		}
		match := true
		for i := range c {
			if c[i] != want[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// b4x-h6o: the field cover applier must create both family sets and add every
// prefix (all-or-nothing), and release by flushing both sets.

func TestIPSETCoverApplier_Activate(t *testing.T) {
	fr := &fakeCoverRunner{}
	a := &ipsetCoverApplier{run: fr}
	v4 := []netip.Prefix{netip.MustParsePrefix("162.159.192.0/24")}
	v6 := []netip.Prefix{netip.MustParsePrefix("2606:4700::/32")}
	if err := a.Activate("b4_cf_fakequic_v4", "b4_cf_fakequic_v6", v4, v6); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	for _, want := range [][]string{
		{"ipset", "create", "b4_cf_fakequic_v4", "hash:net", "family", "inet", "-exist"},
		{"ipset", "create", "b4_cf_fakequic_v6", "hash:net", "family", "inet6", "-exist"},
		{"ipset", "add", "b4_cf_fakequic_v4", "162.159.192.0/24", "-exist"},
		{"ipset", "add", "b4_cf_fakequic_v6", "2606:4700::/32", "-exist"},
	} {
		if !fr.has(want...) {
			t.Errorf("missing call %v; got %v", want, fr.calls)
		}
	}
}

func TestIPSETCoverApplier_Deactivate(t *testing.T) {
	fr := &fakeCoverRunner{}
	a := &ipsetCoverApplier{run: fr}
	if err := a.Deactivate("b4_cf_fakequic_v4", "b4_cf_fakequic_v6"); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if !fr.has("ipset", "flush", "b4_cf_fakequic_v4") {
		t.Errorf("missing v4 flush: %v", fr.calls)
	}
	if !fr.has("ipset", "flush", "b4_cf_fakequic_v6") {
		t.Errorf("missing v6 flush: %v", fr.calls)
	}
}

func TestNewFakeQUICCover_Valid(t *testing.T) {
	c, err := newFakeQUICCover()
	if err != nil {
		t.Fatalf("newFakeQUICCover: %v", err)
	}
	if c == nil {
		t.Fatal("nil cover")
	}
}
