package proton

import (
	"strings"
	"testing"
)

// TestDefaultSNIPool: the embedded white.sni parses into a non-empty pool,
// comments/blanks skipped, no Proton domains, all names admission-valid.
func TestDefaultSNIPool(t *testing.T) {
	pool := DefaultSNIPool()
	if len(pool) < 50 {
		t.Fatalf("SNI pool too small: %d", len(pool))
	}
	seen := map[string]bool{}
	for _, name := range pool {
		if !ValidSNIName(name) {
			t.Fatalf("pool name %q fails admission", name)
		}
		if seen[name] {
			t.Fatalf("pool name %q duplicated", name)
		}
		seen[name] = true
	}
}

func TestValidSNIName(t *testing.T) {
	good := []string{"www.gosuslugi.ru", "go.sber.ru", "m.tutu.ru", "deep.sub.example.org"}
	for _, n := range good {
		if !ValidSNIName(n) {
			t.Fatalf("%q must be valid", n)
		}
	}
	bad := []string{
		"", "no-dots", "vpn-api.proton.me", "mirror.protonpro.xyz",
		"protonmail.ch", "bad name.ru", "-lead.ru", "trail-.ru",
		strings.Repeat("a", 64) + ".ru",
	}
	for _, n := range bad {
		if ValidSNIName(n) {
			t.Fatalf("%q must be invalid", n)
		}
	}
}

// TestIssueProfilesGolden: fixed rand + fixed pool -> deterministic
// profiles; proton-quic carries an I1 built from the drawn SNI; the size is
// the full 1250 bytes.
func TestIssueProfilesGolden(t *testing.T) {
	cands := []Candidate{
		{Node: Node{Name: "NL-FREE#1", Country: "NL", EntryIP: "1.2.3.4", PeerPubKey: "pk1"}, Port: 443},
		{Node: Node{Name: "US-FREE#2", Country: "US", EntryIP: "5.6.7.8", PeerPubKey: "pk2"}, Port: 88},
	}
	ladder := []string{"proton-quic", "proton-vanilla", "proton-sip", "proton-crlf"}
	pool := []string{"www.gosuslugi.ru", "go.sber.ru", "m.tutu.ru"}

	profs := IssueProfiles(cands, ladder, pool, newXorshift(42), nil)
	if len(profs) != 2 {
		t.Fatalf("profiles = %d", len(profs))
	}
	for i, p := range profs {
		if p.ProfileID != "proton-quic" {
			t.Fatalf("profile %d id = %s, want ladder head", i, p.ProfileID)
		}
		if p.Node.Name != cands[i].Node.Name || p.Port != cands[i].Port {
			t.Fatalf("profile %d mismatch: %+v", i, p)
		}
		if p.SNI == "" || !ValidSNIName(p.SNI) {
			t.Fatalf("profile %d SNI invalid: %q", i, p.SNI)
		}
		if n := QuicInitialSize(p.I1); n != QuicPadTo {
			t.Fatalf("profile %d I1 size = %d, want %d", i, n, QuicPadTo)
		}
		if !strings.Contains(p.I1, "<b 0x") {
			t.Fatalf("profile %d I1 grammar: %s...", i, p.I1[:20])
		}
	}
	// Different pool draws: consecutive candidates rotate names.
	if profs[0].SNI == profs[1].SNI {
		t.Fatal("SNI rotation collapsed to one name for consecutive candidates")
	}
	// Determinism.
	again := IssueProfiles(cands, ladder, pool, newXorshift(42), nil)
	for i := range again {
		if again[i].I1 != profs[i].I1 || again[i].SNI != profs[i].SNI {
			t.Fatalf("issuance not deterministic at %d", i)
		}
	}
}

// TestIssueProfilesLastGood: a last-good profile that is still a ladder
// member leads every candidate; a foreign one falls back to the head.
func TestIssueProfilesLastGood(t *testing.T) {
	cands := []Candidate{
		{Node: Node{Name: "NL-FREE#1", EntryIP: "1.2.3.4"}, Port: 443},
	}
	ladder := []string{"proton-quic", "proton-vanilla", "proton-sip", "proton-crlf"}
	pool := []string{"www.gosuslugi.ru"}

	p := IssueProfiles(cands, ladder, pool, newXorshift(7), &MemoryLastGood{ID: "proton-sip"})
	if p[0].ProfileID != "proton-sip" {
		t.Fatalf("last-good ignored: %s", p[0].ProfileID)
	}
	// Static families carry no runtime I1.
	if p[0].I1 != "" || p[0].SNI != "" {
		t.Fatalf("static family must not carry runtime I1: %q", p[0].I1)
	}

	p = IssueProfiles(cands, ladder, pool, newXorshift(7), &MemoryLastGood{ID: "quic-a"})
	if p[0].ProfileID != "proton-quic" {
		t.Fatalf("foreign last-good must fall back to the head: %s", p[0].ProfileID)
	}
}

// TestIssueProfilesEmptyPool: an empty pool yields empty I1/SNI on the
// runtime family — the explicit "no obfuscation" contract, not a stub.
func TestIssueProfilesEmptyPool(t *testing.T) {
	cands := []Candidate{{Node: Node{Name: "NL", EntryIP: "1.2.3.4"}, Port: 443}}
	p := IssueProfiles(cands, []string{"proton-quic"}, nil, newXorshift(3), nil)
	if p[0].SNI != "" || p[0].I1 != "" {
		t.Fatalf("empty pool must give empty I1/SNI: %+v", p[0])
	}
}
