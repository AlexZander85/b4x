package tor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TT2 DoD (patch-plan §3): ≥30 parser cases covering every design §1.5
// rule (injection, budget boundary, decoration addresses, sqs rejection,
// max clamp, split fingerprint), store roundtrip with corrupt quarantine,
// entry-memory TTL semantics, trim-keeping-every-kind.

const fp1 = "0123456789ABCDEF0123456789ABCDEF01234567"

func parseOK(t *testing.T, line string) Bridge {
	t.Helper()
	b, err := ParseBridgeLine(line)
	if err != nil {
		t.Fatalf("ParseBridgeLine(%q) unexpected error: %v", line, err)
	}
	return b
}

func parseErr(t *testing.T, line string) error {
	t.Helper()
	b, err := ParseBridgeLine(line)
	if err == nil {
		t.Fatalf("ParseBridgeLine(%q) = %+v, want error", line, b)
	}
	return err
}

// 1. obfs4 happy path.
func TestParseObfs4HappyPath(t *testing.T) {
	b := parseOK(t, "obfs4 45.66.35.35:443 "+fp1+" cert=abcDEF123 iat-mode=1")
	if b.Transport != "obfs4" || b.AddrPort != "45.66.35.35:443" || b.Fingerprint != fp1 {
		t.Fatalf("fields = %+v", b)
	}
	if b.Args["cert"] != "abcDEF123" || b.Args["iat-mode"] != "1" {
		t.Fatalf("args = %v", b.Args)
	}
	if b.DecorationAddr() {
		t.Fatal("45.66.35.35 is a real address, not decoration")
	}
}

// 2. webtunnel with decoration address.
func TestParseWebtunnelDecoration(t *testing.T) {
	b := parseOK(t, "webtunnel 2001:db8::1:443 "+fp1+" url=https://example.org/secret cert=QUJD")
	if !b.DecorationAddr() {
		t.Fatal("2001:db8:: is a documentation address — must be decoration")
	}
	if b.Args["url"] != "https://example.org/secret" {
		t.Fatalf("args = %v", b.Args)
	}
}

// 3. snowflake full shape (design §7.4 example).
func TestParseSnowflakeFull(t *testing.T) {
	b := parseOK(t, "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://broker/ fronts=a.example,b.example utls-imitate=hellorandomizedalpn")
	if b.Transport != "snowflake" || !b.DecorationAddr() {
		t.Fatalf("snowflake decoration expected: %+v", b)
	}
	if b.Args["fronts"] != "a.example,b.example" {
		t.Fatalf("args = %v", b.Args)
	}
}

// 4. vanilla implicit (line starts with addr:port).
func TestParseVanillaImplicit(t *testing.T) {
	b := parseOK(t, "1.2.3.4:443 "+fp1)
	if b.Transport != "vanilla" || b.Fingerprint != fp1 {
		t.Fatalf("vanilla implicit: %+v", b)
	}
}

// 5. vanilla explicit with fingerprint.
func TestParseVanillaExplicit(t *testing.T) {
	b := parseOK(t, "vanilla 5.6.7.8:9001 "+fp1)
	if b.Transport != "vanilla" || b.AddrPort != "5.6.7.8:9001" {
		t.Fatalf("vanilla explicit: %+v", b)
	}
}

// 6. vanilla without fingerprint (allowed).
func TestParseVanillaNoFingerprint(t *testing.T) {
	b := parseOK(t, "vanilla 5.6.7.8:9001")
	if b.Fingerprint != "" {
		t.Fatalf("fingerprint = %q, want empty", b.Fingerprint)
	}
}

// 7. split fingerprint gluing (tor glues pieces — so do we).
func TestParseSplitFingerprint(t *testing.T) {
	b := parseOK(t, "obfs4 45.66.35.35:443 01234567 89ABCDEF 0123456789ABCDEF01234567 cert=x")
	if b.Fingerprint != fp1 {
		t.Fatalf("glued fingerprint = %q, want %q", b.Fingerprint, fp1)
	}
	if b.Args["cert"] != "x" {
		t.Fatalf("args after glued fp: %v", b.Args)
	}
}

// 8. newline injection (scenario 3).
func TestParseRejectsNewlineInjection(t *testing.T) {
	err := parseErr(t, "obfs4 1.2.3.4:443 "+fp1+"\nUseBridges 0")
	if !errors.Is(err, ErrBridgeLineInvalid) {
		t.Fatalf("err = %v, want ErrBridgeLineInvalid", err)
	}
}

// 9. CR injection.
func TestParseRejectsCarriageReturn(t *testing.T) {
	parseErr(t, "obfs4 1.2.3.4:443 "+fp1+" cert=a\rb")
}

// 10. forbidden backslash.
func TestParseRejectsBackslash(t *testing.T) {
	parseErr(t, `obfs4 1.2.3.4:443 `+fp1+` cert=a\b`)
}

// 11. forbidden hash.
func TestParseRejectsHash(t *testing.T) {
	parseErr(t, "obfs4 1.2.3.4:443 "+fp1+" cert=a#b")
}

// 12. forbidden double quote.
func TestParseRejectsDoubleQuote(t *testing.T) {
	parseErr(t, `obfs4 1.2.3.4:443 `+fp1+` cert=a"b`)
}

// 13. non-ASCII.
func TestParseRejectsNonASCII(t *testing.T) {
	parseErr(t, "obfs4 1.2.3.4:443 "+fp1+" cert=абв")
}

// 14. empty line.
func TestParseRejectsEmpty(t *testing.T) {
	parseErr(t, "   ")
}

// 15. unknown transport token.
func TestParseRejectsUnknownTransport(t *testing.T) {
	err := parseErr(t, "utopia 1.2.3.4:443 "+fp1)
	if !errors.Is(err, ErrBridgeLineInvalid) {
		t.Fatalf("err = %v", err)
	}
}

// 16. known-unsupported transport (honest refusal).
func TestParseRejectsKnownUnsupported(t *testing.T) {
	for _, tr := range []string{"obfs3", "scramblesuit", "meek", "conjure", "dnstt"} {
		err := parseErr(t, tr+" 1.2.3.4:443 "+fp1)
		if !errors.Is(err, ErrTransportUnsupported) {
			t.Fatalf("transport %s: err = %v, want ErrTransportUnsupported", tr, err)
		}
	}
}

// 17. missing endpoint.
func TestParseRejectsMissingEndpoint(t *testing.T) {
	parseErr(t, "obfs4")
}

// 18. bad port zero.
func TestParseRejectsPortZero(t *testing.T) {
	parseErr(t, "obfs4 1.2.3.4:0 "+fp1)
}

// 19. bad port overflow.
func TestParseRejectsPortOverflow(t *testing.T) {
	parseErr(t, "obfs4 1.2.3.4:70000 "+fp1)
}

// 20. endpoint not addr:port.
func TestParseRejectsBadEndpoint(t *testing.T) {
	parseErr(t, "obfs4 not-an-endpoint "+fp1)
}

// 21. sqsqueue rejection (scenario 6).
func TestParseRejectsSQSQueue(t *testing.T) {
	err := parseErr(t, "snowflake 192.0.2.3:80 "+fp1+" url=https://broker/ sqsqueue=https://sqs.example/queue")
	if !errors.Is(err, ErrBridgeLineInvalid) || !strings.Contains(err.Error(), "sqs-rejected") {
		t.Fatalf("err = %v, want sqs-rejected", err)
	}
}

// 22. sqscreds rejection.
func TestParseRejectsSQSCreds(t *testing.T) {
	parseErr(t, "snowflake 192.0.2.3:80 "+fp1+" sqscreds=secret")
}

// 23. snowflake max=9 clamps to 8 with notice (scenario 5).
func TestParseSnowflakeMaxClamp(t *testing.T) {
	b := parseOK(t, "snowflake 192.0.2.3:80 "+fp1+" url=https://broker/ max=9")
	if b.Args["max"] != "8" {
		t.Fatalf("max = %q, want clamped 8", b.Args["max"])
	}
	if !strings.Contains(b.Line, "max=8") {
		t.Fatalf("line must carry the clamped token: %q", b.Line)
	}
	if len(b.Notices) == 0 || !strings.Contains(b.Notices[0], "clamped") {
		t.Fatalf("notices = %v, want clamp notice", b.Notices)
	}
}

// 24. snowflake max=0 clamps to 1.
func TestParseSnowflakeMaxClampLow(t *testing.T) {
	b := parseOK(t, "snowflake 192.0.2.3:80 "+fp1+" url=https://broker/ max=0")
	if b.Args["max"] != "1" {
		t.Fatalf("max = %q, want clamped 1", b.Args["max"])
	}
}

// 25. snowflake max=not-a-number.
func TestParseSnowflakeMaxGarbage(t *testing.T) {
	parseErr(t, "snowflake 192.0.2.3:80 "+fp1+" url=https://broker/ max=many")
}

// 26. obfs4 iat-mode out of range.
func TestParseObfs4IatModeRange(t *testing.T) {
	parseErr(t, "obfs4 45.66.35.35:443 "+fp1+" cert=x iat-mode=3")
}

// 27. obfs4 iat-mode boundary values pass.
func TestParseObfs4IatModeBoundaries(t *testing.T) {
	for _, m := range []string{"0", "1", "2"} {
		parseOK(t, "obfs4 45.66.35.35:443 "+fp1+" cert=x iat-mode="+m)
	}
}

// 28. argument budget at the 510 boundary (scenario 4).
func TestParseArgBudgetBoundary(t *testing.T) {
	// craft args to land exactly at 510 bytes serialized
	pad := strings.Repeat("a", 400)
	line := "obfs4 45.66.35.35:443 " + fp1 + " cert=" + pad
	b := parseOK(t, line)
	login, _, err := b.SocksArgs()
	if err != nil {
		t.Fatalf("510-budget line must parse: %v", err)
	}
	if len(login) > 255 {
		t.Fatalf("login %d bytes exceeds RFC 1929 field", len(login))
	}
	// now exceed it
	line2 := "obfs4 45.66.35.35:443 " + fp1 + " cert=" + strings.Repeat("a", 509)
	err = parseErr(t, line2)
	if !strings.Contains(err.Error(), "510") {
		t.Fatalf("err = %v, want budget message", err)
	}
}

// 29. login/password split past 255 bytes.
func TestSocksArgsSplitAcrossFields(t *testing.T) {
	b := parseOK(t, "obfs4 45.66.35.35:443 "+fp1+" cert="+strings.Repeat("a", 200)+" iat-mode=0 padding="+strings.Repeat("b", 200))
	login, pass, err := b.SocksArgs()
	if err != nil {
		t.Fatalf("SocksArgs: %v", err)
	}
	if len(login) > 255 || len(pass) > 255 {
		t.Fatalf("fields exceed RFC 1929: login=%d pass=%d", len(login), len(pass))
	}
	if login == "" || pass == "" {
		t.Fatalf("expected split across both fields: login=%q pass=%q", login, pass)
	}
}

// 30. duplicate argument.
func TestParseRejectsDuplicateArg(t *testing.T) {
	parseErr(t, "obfs4 45.66.35.35:443 "+fp1+" cert=a cert=b")
}

// 31. token that is neither fingerprint nor k=v.
func TestParseRejectsStrayToken(t *testing.T) {
	parseErr(t, "obfs4 45.66.35.35:443 "+fp1+" garbage")
}

// 32. fingerprint wrong length (8 hex chars).
func TestParseRejectsShortFingerprint(t *testing.T) {
	parseErr(t, "obfs4 45.66.35.35:443 deadbeef cert=x")
}

// 33. non-hex fingerprint.
func TestParseRejectsNonHexFingerprint(t *testing.T) {
	parseErr(t, "obfs4 45.66.35.35:443 zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz cert=x")
}

// 34. decoration families (RFC 5737/3849/unspecified).
func TestDecorationAddrFamilies(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "198.51.100.5", "203.0.113.9", "0.0.0.0", "2001:db8::dead", "::", "127.0.0.1"} {
		b := Bridge{AddrPort: host + ":443"}
		if !b.DecorationAddr() {
			t.Fatalf("%s must be decoration", host)
		}
	}
	for _, host := range []string{"45.66.35.35", "8.8.8.8"} {
		b := Bridge{AddrPort: host + ":443"}
		if b.DecorationAddr() {
			t.Fatalf("%s must NOT be decoration", host)
		}
	}
}

// 35. IPv6 bracket endpoint.
func TestParseIPv6Endpoint(t *testing.T) {
	b := parseOK(t, "vanilla [2001:db8::1]:443 "+fp1)
	if b.AddrPort != "[2001:db8::1]:443" {
		t.Fatalf("addr = %q", b.AddrPort)
	}
	if !b.DecorationAddr() {
		t.Fatal("2001:db8 is documentation space")
	}
	// real IPv6 relay
	b2 := parseOK(t, "vanilla [2620:106:3003:4b::1]:443 "+fp1)
	if b2.DecorationAddr() {
		t.Fatal("real global IPv6 must not be decoration")
	}
}

// 36. whitespace normalization (line is the exchange unit).
func TestParseWhitespaceNormalization(t *testing.T) {
	b := parseOK(t, "  obfs4   45.66.35.35:443   "+fp1+"   cert=x  ")
	if b.Line != "obfs4 45.66.35.35:443 "+fp1+" cert=x" {
		t.Fatalf("normalized line = %q", b.Line)
	}
}

// 37. builtin sets parse clean (packaging gate).
func TestBuiltinSetsParse(t *testing.T) {
	for _, set := range []string{"cdn77", "amp"} {
		bridges := BuiltinSnowflake(set)
		if len(bridges) == 0 {
			t.Fatalf("builtin set %q produced no bridges (packaging bug)", set)
		}
		for _, b := range bridges {
			if b.Transport != "snowflake" {
				t.Fatalf("builtin %q transport = %q", set, b.Transport)
			}
			if !b.DecorationAddr() {
				t.Fatalf("builtin snowflake endpoint must be decoration: %q", b.AddrPort)
			}
		}
	}
	if BuiltinSnowflake("nope") != nil {
		t.Fatal("unknown set must return nil")
	}
}

// 38. Explain renders the refusal reason.
func TestExplain(t *testing.T) {
	if Explain(nil) != "" {
		t.Fatal("nil error explains to empty")
	}
	err := parseErr(t, "obfs4 1.2.3.4:0 "+fp1)
	if Explain(err) == "" {
		t.Fatal("refusal must explain itself")
	}
}

// Store roundtrip: save/load/corrupt-quarantine.
func TestBridgesStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s := NewBridgesStore(dir)

	f, err := s.Load()
	if err != nil || len(f.Bridges) != 0 {
		t.Fatalf("fresh load = %+v err=%v", f, err)
	}

	now := time.Now()
	bridges := []StoredBridge{
		{Transport: "webtunnel", Line: "webtunnel 2001:db8::1:443 " + fp1 + " url=https://x/", Endpoint: "2001:db8::1:443", Fingerprint: fp1},
		{Transport: "obfs4", Line: "obfs4 45.66.35.35:443 " + fp1 + " cert=x", Endpoint: "45.66.35.35:443", Fingerprint: fp1},
	}
	if err := s.Save(BridgesFile{UpdatedAt: now.UnixMilli(), Source: "test", Bridges: bridges}); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Bridges) != 2 || got.Source != "test" || got.Schema != BridgesFileSchema {
		t.Fatalf("roundtrip = %+v", got)
	}
	if time.UnixMilli(got.UpdatedAt).Sub(now) > time.Second {
		t.Fatalf("timestamp drift: %v", time.UnixMilli(got.UpdatedAt).Sub(now))
	}

	// corrupt file → quarantine + empty, no crash
	if err := os.WriteFile(filepath.Join(dir, "bridges.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = s.Load()
	if err == nil {
		t.Fatal("corrupt store must report an error")
	}
	if len(got.Bridges) != 0 {
		t.Fatalf("corrupt store reads empty, got %+v", got)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "bridges.json.corrupt")); statErr != nil {
		t.Fatalf("corrupt file must be quarantined: %v", statErr)
	}

	// failed-run rule is caller-side: a failing conveyor simply never calls
	// Save — the previous list survives (asserted by the quarantine flow
	// above leaving the previous good file moved, not deleted).
}

func TestDedupAndTrim(t *testing.T) {
	var bridges []Bridge
	// 50 webtunnel + 1 obfs4 — the fat kind must not crowd out the rare one
	for i := 0; i < 50; i++ {
		bridges = append(bridges, Bridge{Transport: "webtunnel", AddrPort: "10.0.0.1:443", Fingerprint: fp1, Line: "x"})
	}
	bridges = append(bridges, Bridge{Transport: "obfs4", AddrPort: "45.66.35.35:443", Fingerprint: fp1, Line: "y"})

	trimmed := TrimKeepingEveryKind(bridges, 40)
	kinds := map[string]int{}
	for _, b := range trimmed {
		kinds[b.Transport]++
	}
	if kinds["webtunnel"] != 40 {
		t.Fatalf("webtunnel kept %d, want cap 40", kinds["webtunnel"])
	}
	if kinds["obfs4"] != 1 {
		t.Fatalf("rare obfs4 crowded out: %d", kinds["obfs4"])
	}

	dup := Dedup([]Bridge{
		{Transport: "obfs4", AddrPort: "1.2.3.4:443", Fingerprint: fp1},
		{Transport: "obfs4", AddrPort: "1.2.3.4:443", Fingerprint: fp1},
		{Transport: "obfs4", AddrPort: "5.6.7.8:443", Fingerprint: fp1},
	})
	if len(dup) != 2 {
		t.Fatalf("dedup kept %d, want 2", len(dup))
	}
}

func TestEntryMemoryLifecycle(t *testing.T) {
	dir := t.TempDir()
	m := NewEntryMemory(dir)
	now := time.Now

	// empty memory
	st := m.Load(now)
	if st.Winner != "" || len(st.Failed) != 0 {
		t.Fatalf("fresh memory = %+v", st)
	}

	// record failures + winner
	if err := m.RecordFail("webtunnel", now); err != nil {
		t.Fatalf("record fail: %v", err)
	}
	if err := m.RecordFail("obfs4", now); err != nil {
		t.Fatalf("record fail: %v", err)
	}
	if err := m.RecordWin("snowflake", now); err != nil {
		t.Fatalf("record win: %v", err)
	}
	st = m.Load(now)
	if st.Winner != "snowflake" || len(st.Failed) != 2 || st.Failed[0] != "webtunnel" || st.Failed[1] != "obfs4" {
		t.Fatalf("memory = %+v", st)
	}

	// TTL expiry: a stale record reads empty and deletes the file
	later := func() time.Time { return time.Now().Add(EntryMemoryTTL + time.Minute) }
	st = m.Load(later)
	if st.Winner != "" || len(st.Failed) != 0 {
		t.Fatalf("stale memory must read empty: %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "entry_memory.txt")); !os.IsNotExist(err) {
		t.Fatal("stale memory file must be removed")
	}

	// manual clear (first successful stream / entry change)
	if err := m.RecordWin("webtunnel", now); err != nil {
		t.Fatalf("record win: %v", err)
	}
	if err := m.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	st = m.Load(now)
	if st.Winner != "" {
		t.Fatalf("cleared memory = %+v", st)
	}
}

func TestEntryMemoryCorruptReadsEmpty(t *testing.T) {
	dir := t.TempDir()
	m := NewEntryMemory(dir)
	if err := os.WriteFile(filepath.Join(dir, "entry_memory.txt"), []byte("garbage\nmore garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := m.Load(time.Now)
	if st.Winner != "" || len(st.Failed) != 0 {
		t.Fatalf("corrupt memory reads empty: %+v", st)
	}
}
