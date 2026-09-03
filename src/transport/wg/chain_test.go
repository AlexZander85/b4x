package transportwg

import (
	"reflect"
	"strings"
	"testing"
)

// Table tests for the hard chain grammar. Upstream has NO unit tests for
// obf*.go (research §1); these are the mandatory regression the design adds.
func TestParseChainValid(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want []ChainElem
	}{
		{"bytes only", "<b 0xdeadbeef>", []ChainElem{{Kind: ElemBytes, Bytes: []byte{0xde, 0xad, 0xbe, 0xef}}}},
		{"bytes no prefix", "<b abcd>", []ChainElem{{Kind: ElemBytes, Bytes: []byte{0xab, 0xcd}}}},
		{"timestamp", "<t>", []ChainElem{{Kind: ElemTimestamp}}},
		{"data copy", "<d>", []ChainElem{{Kind: ElemData}}},
		{"data string", "<ds>", []ChainElem{{Kind: ElemDataStr}}},
		{"rand", "<r 10>", []ChainElem{{Kind: ElemRand, Count: 10}}},
		{"rand chars", "<rc 7>", []ChainElem{{Kind: ElemRandChar, Count: 7}}},
		{"rand digits", "<rd 0>", []ChainElem{{Kind: ElemRandDigit, Count: 0}}},
		{"size marker", "<dz 2>", []ChainElem{{Kind: ElemDataSize, Count: 2}}},
		{
			"adjacent tags (upstream form)",
			"<b 0xf6ab3267fa><b 0xf6ab><t><r 10>",
			[]ChainElem{
				{Kind: ElemBytes, Bytes: []byte{0xf6, 0xab, 0x32, 0x67, 0xfa}},
				{Kind: ElemBytes, Bytes: []byte{0xf6, 0xab}},
				{Kind: ElemTimestamp},
				{Kind: ElemRand, Count: 10},
			},
		},
		{
			"space separated tags",
			"<b 0xce00> <t> <r 10>",
			[]ChainElem{
				{Kind: ElemBytes, Bytes: []byte{0xce, 0x00}},
				{Kind: ElemTimestamp},
				{Kind: ElemRand, Count: 10},
			},
		},
		{"newline separators", "<t>\n<r 3>", []ChainElem{{Kind: ElemTimestamp}, {Kind: ElemRand, Count: 3}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseChain(tc.spec)
			if err != nil {
				t.Fatalf("ParseChain(%q): %v", tc.spec, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
			if err := ValidateChainSpec(tc.spec); err != nil {
				t.Fatalf("ValidateChainSpec: %v", err)
			}
		})
	}
}

func TestParseChainInvalid(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		wantSub string
	}{
		{"empty", "", "empty"},
		{"no tags", "hello world", "outside tags"},
		{"stray text between tags", "<t> oops <r 1>", "outside tags"},
		{"colon separator typo degrades silently upstream", "<t>:<r 1>", "outside tags"},
		{"unclosed tag", "<r 10", "unclosed"},
		{"empty tag", "<>", "empty tag"},
		{"unknown tag c (upstream skipped-test bug)", "<b 0xaa><c><r 1>", "unknown tag"},
		{"missing arg", "<r>", "requires an argument"},
		{"extra arg", "<t 5>", "takes no argument"},
		{"two args", "<r 1 2>", "more than one argument"},
		{"odd hex", "<b abc>", "odd amount"},
		{"bad hex", "<b zzzz>", "tag <b>"},
		{"negative count passes upstream, rejected here", "<r -1>", "out of"},
		{"huge count", "<rd 999999999999>", "bad count|out of"},
		{"too many elements", "<t><t><t><t><t><t><t><t><t><t><t><t><t><t><t><t><t>", "max 16"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseChain(tc.spec)
			if err == nil {
				t.Fatalf("ParseChain(%q): expected error", tc.spec)
			}
			if !strings.Contains(err.Error(), "transportwg") {
				t.Fatalf("error %v lacks package prefix", err)
			}
		})
	}
}

// RenderChain must produce canonical adjacent-tag output that re-parses to
// the same elements (storage round-trip determinism).
func TestRenderChainRoundTrip(t *testing.T) {
	specs := []string{
		"<b 0xdeadbeef><t><r 10>",
		"<rc 4><dz 2><ds>",
		"<b 0xce00000044d0>",
	}
	for _, spec := range specs {
		elems, err := ParseChain(spec)
		if err != nil {
			t.Fatalf("ParseChain(%q): %v", spec, err)
		}
		rendered := RenderChain(elems)
		again, err := ParseChain(rendered)
		if err != nil {
			t.Fatalf("re-parse %q: %v", rendered, err)
		}
		if !reflect.DeepEqual(elems, again) {
			t.Fatalf("round trip mismatch: %+v vs %+v", elems, again)
		}
	}
}

func TestRenderChainCanonicalForms(t *testing.T) {
	if got := RenderChain(nil); got != "" {
		t.Fatalf("nil render: %q", got)
	}
	got := RenderChain([]ChainElem{
		{Kind: ElemBytes, Bytes: []byte{0x00, 0xff}},
		{Kind: ElemDataSize, Count: 4},
		{Kind: ElemTimestamp},
	})
	if want := "<b 0x00ff><dz 4><t>"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
