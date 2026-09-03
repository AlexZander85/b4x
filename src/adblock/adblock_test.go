// BLK-1 verification: list parsing, matcher semantics, fail-open discipline.
package adblock

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMatcherTrailingLabelSemantics(t *testing.T) {
	m := newMatcher("test")
	for _, d := range []string{"doubleclick.net", "Sub.Example.COM.", "ads.google.com"} {
		m.add(d)
	}
	cases := map[string]bool{
		"doubleclick.net":          true,
		"ads.doubleclick.net":      true,
		"deep.sub.example.com":     true,
		"sub.example.com":          true,
		"notdoubleclick.net":       false, // suffix must be label-aligned
		"evilfake-doubleclick.net": false,
		"example.com":              false,
		"google.com":               false,
		"com":                      false,
	}
	for host, want := range cases {
		if got := m.match(host); got != want {
			t.Errorf("match(%q)=%v want %v", host, got, want)
		}
	}
}

func TestParseListFileFormats(t *testing.T) {
	p := writeFile(t, ""+
		"# comment\n"+
		"! another comment\n"+
		"\n"+
		"example.com\n"+
		"0.0.0.0 tracker.example.net\n"+
		"::1 ipv6.example.net\n"+
		"@@whitelist-style-line\n")
	m, n, err := parseListFile(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("entries=%d want 3", n)
	}
	for _, d := range []string{"example.com", "tracker.example.net", "ipv6.example.net"} {
		if !m.match(d) {
			t.Errorf("missing %q", d)
		}
	}
}

func TestReloadFailOpenOnMissingLists(t *testing.T) {
	cfg := config.AdBlockConfig{Enabled: true, Lists: []config.AdBlockList{{Source: filepath.Join(t.TempDir(), "absent.txt"), Enabled: true}}}
	Reload(cfg)
	s := GetStats()
	if s.Enabled {
		t.Fatal("layer must stay disabled when no list loads (fail-open)")
	}
	if s.ListInvalid == 0 {
		t.Fatal("expected list_invalid counter")
	}
	if _, listName := Decide("doubleclick.net"); listName != "" || DecisionBlock == DecisionPass {
		t.Fatalf("disabled layer must pass everything: %v %q", DecisionPass, listName)
	}
}

func TestReloadAllowlistWins(t *testing.T) {
	blockP := writeFile(t, "example.com\ntracker.io\n")
	allowP := writeFile(t, "ok.example.com\n")
	Reload(config.AdBlockConfig{
		Enabled:   true,
		Lists:     []config.AdBlockList{{Source: blockP, Enabled: true}},
		Allowlist: []string{allowP},
	})
	if d, _ := Decide("example.com"); d != DecisionBlock {
		t.Fatal("listed domain must block")
	}
	if d, name := Decide("ok.example.com"); d != DecisionPass || name != "allow" {
		t.Fatalf("allowlisted subdomain must pass via allow list, got %v/%q", d, name)
	}
	if d, _ := Decide("other.org"); d != DecisionPass {
		t.Fatal("unlisted domain must pass")
	}
}

func TestReloadDisabledIgnoresLists(t *testing.T) {
	blockP := writeFile(t, "example.com\n")
	Reload(config.AdBlockConfig{Enabled: false, Lists: []config.AdBlockList{{Source: blockP, Enabled: true}}})
	if GetStats().Enabled {
		t.Fatal("disabled config must not activate layer")
	}
	if d, _ := Decide("example.com"); d != DecisionPass {
		t.Fatal("disabled layer must pass")
	}
}

func TestNormalizeListLineABP(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"||ads.example.com^", "ads.example.com", true},
		{"||cdn.tracker.io^$important", "cdn.tracker.io", true},
		{".suffix-only.org^", "suffix-only.org", true},
		{"||wild*.cards.com^", "", false},
		{"||path.rule.com/path^", "", false},
		{"/^139\\.45\\.197\\.2(4[0-9]|5[0-4]):/", "", false},
		{"@@||allow-me.com^", "", false},
		{"||plain.org", "plain.org", true},
		{".doublepimp.com^", "doublepimp.com", true},
	}
	for _, tc := range cases {
		got, ok := normalizeListLine(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("normalize(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDefaultSubscriptionsPresent(t *testing.T) {
	if len(DefaultSubscriptions) < 2 {
		t.Fatalf("default subscriptions missing: %v", DefaultSubscriptions)
	}
	for _, u := range DefaultSubscriptions {
		if !isURL(u) {
			t.Fatalf("default subscription %q is not a URL", u)
		}
	}
}

func TestMaxEntriesCap(t *testing.T) {
	p := writeFile(t, "a.com\nb.com\nc.com\n")
	m, n, err := parseListFile(p, 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("capped entries=%d want 2", n)
	}
	if !m.match("a.com") || !m.match("b.com") {
		t.Fatal("first entries must survive the cap")
	}
	if m.match("c.com") {
		t.Fatal("entry beyond cap must not load")
	}
}
