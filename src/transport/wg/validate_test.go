package transportwg

import "testing"

func TestParseRange(t *testing.T) {
	cases := []struct {
		in   string
		lo   uint32
		hi   uint32
		want string // canonical re-render; "" means expect error
	}{
		{"5", 5, 5, "5"},
		{"123456-123500", 123456, 123500, "123456-123500"},
		{"0-0", 0, 0, "0"}, // upstream canonical: lo==hi renders single value
		{"7-3", 0, 0, ""},
		{"a-b", 0, 0, ""},
		{"1-2-3", 0, 0, ""},
	}
	for _, tc := range cases {
		r, err := ParseRange(tc.in)
		if tc.want == "" {
			if err == nil {
				t.Fatalf("ParseRange(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", tc.in, err)
		}
		if r.Lo != tc.lo || r.Hi != tc.hi {
			t.Fatalf("ParseRange(%q) = %v, want lo=%d hi=%d", tc.in, r, tc.lo, tc.hi)
		}
		if got := r.String(); got != tc.want {
			t.Fatalf("render %q -> %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestProfileValidateVanillaOK(t *testing.T) {
	var p Profile
	if err := p.Validate(); err != nil {
		t.Fatalf("vanilla zero profile must validate: %v", err)
	}
	if !p.VanillaSafe() {
		t.Fatalf("vanilla profile must be VanillaSafe")
	}
}

func TestProfileValidateJunkRules(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Profile)
		wantErr bool
	}{
		{"valid junk triple", func(p *Profile) { p.JunkCount, p.JunkMin, p.JunkMax = 4, 40, 70 }, false},
		{"jc over max", func(p *Profile) { p.JunkCount = 129 }, true},
		{"jc at max", func(p *Profile) { p.JunkCount, p.JunkMin, p.JunkMax = 128, 23, 911 }, false},
		{"jc without sizes", func(p *Profile) { p.JunkCount = 4 }, true},
		{"sizes without jc", func(p *Profile) { p.JunkMin, p.JunkMax = 40, 70 }, true},
		{"jmin>jmax (upstream underflow trap)", func(p *Profile) { p.JunkCount, p.JunkMin, p.JunkMax = 4, 911, 40 }, true},
		{"jmax over 1280", func(p *Profile) { p.JunkCount, p.JunkMin, p.JunkMax = 4, 1000, 1281 }, true},
		{"jmin zero", func(p *Profile) { p.JunkCount, p.JunkMin, p.JunkMax = 4, 0, 70 }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p Profile
			tc.mutate(&p)
			err := p.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestProfileValidateHeaderOverlap(t *testing.T) {
	ok := func() *Range { r := Range{Lo: 10, Hi: 20}; return &r }()
	tests := []struct {
		name    string
		mutate  func(*Profile)
		wantErr bool
	}{
		{"disjoint ranges ok", func(p *Profile) {
			p.HeaderInit, p.HeaderResponse = &Range{1, 5}, &Range{6, 9}
		}, false},
		{"overlap rejected (upstream uapi.go:828-838)", func(p *Profile) {
			p.HeaderInit, p.HeaderResponse = &Range{1, 5}, &Range{5, 9}
		}, true},
		{"three-way overlap rejected", func(p *Profile) {
			p.HeaderInit, p.HeaderCookie, p.HeaderTransport = &Range{1, 100}, &Range{50, 60}, &Range{200, 300}
		}, true},
		{"single value ranges disjoint ok", func(p *Profile) {
			p.HeaderInit, p.HeaderResponse = &Range{1, 1}, &Range{2, 2}
		}, false},
		{"nil untouched", func(p *Profile) { p.HeaderInit = ok }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Profile{}
			tc.mutate(&p)
			err := p.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestProfileValidateHeaderProtectionKey(t *testing.T) {
	key := make([]byte, 32)
	mk := func(s1, s2, s3, s4 uint32) *Profile {
		return &Profile{PadInit: s1, PadResponse: s2, PadCookie: s3, PadTransport: s4, HeaderProtKey: key}
	}
	if err := mk(12, 12, 12, 12).Validate(); err != nil {
		t.Fatalf("S=12 boundary must pass: %v", err)
	}
	if err := mk(12, 12, 12, 11).Validate(); err == nil {
		t.Fatalf("s4<12 with HP key must fail")
	}
	short := make([]byte, 31)
	if err := (&Profile{PadInit: 12, PadResponse: 12, PadCookie: 12, PadTransport: 12, HeaderProtKey: short}).Validate(); err == nil {
		t.Fatalf("short HP key must fail")
	}
}

func TestProfileValidateChains(t *testing.T) {
	p := &Profile{InitPacket: [5]string{"<b 0xdead>", "", "<r 4>"}}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid chains: %v", err)
	}
	bad := &Profile{InitPacket: [5]string{"<b 0xdead><c>"}}
	if err := bad.Validate(); err == nil {
		t.Fatalf("invalid i2 chain must fail")
	}
	// Store-only keys are validated too even though never rendered.
	sb := &Profile{HiddenJunk: [3]string{"<t>:junk"}}
	if err := sb.Validate(); err == nil {
		t.Fatalf("store-only j1 must be validated as well")
	}
}

func TestProfileVanillaSafeClassification(t *testing.T) {
	junkOnly := &Profile{JunkCount: 4, JunkMin: 40, JunkMax: 70, InitPacket: [5]string{"<b 0xce00>"}}
	if !junkOnly.VanillaSafe() {
		t.Fatalf("junk-family profile must be vanilla-safe (research finding 3)")
	}
	sMod := &Profile{PadInit: 15}
	if sMod.VanillaSafe() {
		t.Fatalf("S modification must not be vanilla-safe")
	}
	hMod := &Profile{HeaderInit: &Range{1, 5}}
	if hMod.VanillaSafe() {
		t.Fatalf("H modification must not be vanilla-safe")
	}
}
