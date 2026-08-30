package transportwarp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestH3FrameRoundTrip(t *testing.T) {
	var buf []byte
	buf = appendH3Frame(buf, h3FrameHeaders, []byte("section"))
	buf = appendH3Frame(buf, h3FrameData, bytes.Repeat([]byte{0xAB}, 300))
	buf = appendH3Frame(buf, h3FrameSettings, nil)

	fr := newH3Framer(bytes.NewReader(buf))
	want := []struct {
		typ uint64
		pl  []byte
	}{{h3FrameHeaders, []byte("section")}, {h3FrameData, bytes.Repeat([]byte{0xAB}, 300)}, {h3FrameSettings, nil}}
	for i, w := range want {
		typ, payload, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if typ != w.typ || !bytes.Equal(payload, w.pl) {
			t.Errorf("frame %d: got type %#x len %d, want %#x len %d", i, typ, len(payload), w.typ, len(w.pl))
		}
	}
	if _, _, err := fr.ReadFrame(); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("EOF expected at end, got %v", err)
	}
}

func TestH3UnknownFrameSkipBudget(t *testing.T) {
	mkUnknown := func(id uint64) []byte { return appendH3Frame(nil, id, []byte("grease")) }
	var buf []byte
	for i := uint64(0x21); i < 0x21+8; i++ {
		buf = append(buf, mkUnknown(i)...)
	}
	buf = appendH3Frame(buf, h3FrameHeaders, []byte("real"))

	fr := newH3Framer(bytes.NewReader(buf))
	typ, payload, err := fr.ReadKnownFrame(map[uint64]bool{h3FrameHeaders: true})
	if err != nil || typ != h3FrameHeaders || string(payload) != "real" {
		t.Fatalf("8 unknowns + headers: typ=%#x payload=%q err=%v", typ, payload, err)
	}

	// Nine consecutive unknowns must trip the budget (design §2).
	buf2 := []byte{}
	for i := uint64(0x21); i < 0x21+9; i++ {
		buf2 = append(buf2, mkUnknown(i)...)
	}
	fr2 := newH3Framer(bytes.NewReader(buf2))
	if _, _, err := fr2.ReadKnownFrame(map[uint64]bool{h3FrameHeaders: true}); !errors.Is(err, errH3TooManyUnknown) {
		t.Fatalf("want errH3TooManyUnknown, got %v", err)
	}
}

func TestH3OversizedFrameRejected(t *testing.T) {
	huge := AppendVarint(AppendVarint(nil, h3FrameData), uint64(h3MaxFramePayload)+1)
	fr := newH3Framer(bytes.NewReader(huge))
	if _, _, err := fr.ReadFrame(); !errors.Is(err, errH3FrameTooLarge) {
		t.Fatalf("want errH3FrameTooLarge, got %v", err)
	}
}

func TestH3ControlPreambleAndSettings(t *testing.T) {
	pre := WriteControlPreamble()
	if pre[0] != 0x00 { // stream type control
		t.Fatalf("control preamble stream type = %#x", pre[0])
	}
	fr := newH3Framer(bytes.NewReader(pre[1:]))
	typ, payload, err := fr.ReadFrame()
	if err != nil || typ != h3FrameSettings {
		t.Fatalf("settings frame parse: typ=%#x err=%v", typ, err)
	}
	got, err := ParseSettings(payload)
	if err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	// SETTINGS_H3_DATAGRAM_00 legacy draft: the official client still sends
	// it (usque masque.go:190-200) — our client must too (design §1).
	if got[0x276] != 1 {
		t.Fatalf("settings = %v, want 0x276 -> 1", got)
	}
	if _, dynamic := got[0x01]; len(got) != 1 || dynamic {
		t.Fatalf("unexpected extra settings advertised: %v (QPACK capacity must stay 0)", got)
	}

	payload = appendQUICVarintTest(0x276, 1) // legacy draft setting seen on the wire (usque)
	payload = append(payload, appendQUICVarintTest(0x01, 6)...)
	parsed, err := ParseSettings(payload)
	if err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	if parsed[0x276] != 1 || parsed[1] != 6 {
		t.Fatalf("settings = %v", parsed)
	}
	if _, err := ParseSettings([]byte{0x40}); err == nil {
		t.Fatal("truncated settings accepted")
	}
}

func TestH3DatagramWrapUnwrap(t *testing.T) {
	pkt := []byte{0x45, 0x00, 0x00, 0x14}
	wrapped := WrapH3Datagram(4, 0, pkt) // bi stream 4 -> quarter 1
	qsid, ctx, out, err := UnwrapH3Datagram(wrapped)
	if err != nil || qsid != 1 || ctx != 0 || !bytes.Equal(out, pkt) {
		t.Fatalf("small qsid: qsid=%d ctx=%d pkt=%v err=%v", qsid, ctx, out, err)
	}

	wrapped = WrapH3Datagram(4_000_000*4, 0, pkt) // multi-byte varint quarter id
	qsid, _, _, err = UnwrapH3Datagram(wrapped)
	if err != nil || qsid != 4_000_000 {
		t.Fatalf("big qsid: %d %v", qsid, err)
	}
}

func TestH3DatagramMalformed(t *testing.T) {
	cases := [][]byte{
		{},                   // empty
		{0x01},               // qsid only, no context
		AppendVarint(nil, 1), // qsid+... truncated context handled below
	}
	cases[2] = AppendVarint(cases[2], 0) // qsid + ctx but zero-length payload
	for i, c := range cases {
		if _, _, _, err := UnwrapH3Datagram(c); err == nil {
			t.Errorf("case %d (% x): expected error", i, c)
		}
	}
}

// ---- authority formatter (design §2 unit requirement) ----

func TestAuthorityForEndpoint(t *testing.T) {
	if got := AuthorityForEndpoint("162.159.198.2", 443); got != "162.159.198.2:443" {
		t.Errorf("v4 authority = %q", got)
	}
	if got := AuthorityForEndpoint("2606:4700:103::2", 500); got != "[2606:4700:103::2]:500" {
		t.Errorf("v6 authority = %q (brackets required by RFC 3986)", got)
	}
}

func appendQUICVarintTest(id, v uint64) []byte {
	return AppendVarint(AppendVarint(nil, id), v)
}

// ---- UDP dial policy ----

// Zero-value policy stays usable for tests and unconstrained environments.
func TestListenUDPZeroPolicyWorks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := DialPolicy{} // unconstrained
	a, err := p.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer a.Close()
	b, err := p.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer b.Close()

	bAddr := b.LocalAddr().(*net.UDPAddr)
	if _, err := a.WriteToUDP([]byte("ping"), bAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := b.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("exchange failed: n=%d err=%v", n, err)
	}
}

// RequireMark without a mark value fails closed BEFORE any traffic can leave
// through an unmarked socket (addendum §18 contract, TCP-branch parity). The
// exact error text differs per platform; both are structural failures.
func TestListenUDPRequireMarkFailClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := DialPolicy{RequireMark: true}
	_, err := p.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err == nil {
		t.Fatal("RequireMark without FwMark must fail closed")
	}
	if !strings.Contains(err.Error(), "SO_MARK") && !strings.Contains(err.Error(), "unsupported") &&
		!strings.Contains(err.Error(), "requires") {
		t.Fatalf("unexpected error class: %v", err)
	}
}

// Constrained mark policy: success iff the platform grants SO_MARK to this
// process (probed directly); otherwise the listen must fail closed — never a
// silent unmarked socket.
func TestListenUDPConstrainedMark(t *testing.T) {
	canMark := probeCanSetMark(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := DialPolicy{FwMark: 0x5D}
	conn, err := p.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if canMark {
		if err != nil {
			t.Fatalf("mark-capable platform rejected constrained socket: %v", err)
		}
		conn.Close()
	} else if err == nil {
		conn.Close()
		t.Fatal("SO_MARK unavailable yet constrained socket was created (silent fallback!)")
	}
}

// Constrained device-bind policy is Linux-only; elsewhere it must fail closed.
func TestListenUDPBindDeviceCrossPlatform(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := DialPolicy{BindDevice: "lo"}
	conn, err := p.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err == nil {
		conn.Close()
		if !isLinuxTest() {
			t.Fatal("bind-device constraint applied on non-Linux build")
		}
		return
	}
	if isLinuxTest() {
		// lo exists in the container; failure means SO_BINDTODEVICE was not
		// applied structurally (e.g. missing CAP_NET_RAW) — acceptable only
		// when it reports as such.
		if !strings.Contains(err.Error(), "bind device") && !strings.Contains(err.Error(), "operation not permitted") {
			t.Fatalf("linux bind-device failure has unexpected class: %v", err)
		}
	}
}

func isLinuxTest() bool { return testPlatform == "linux" }

var testPlatform = runtime.GOOS

// probeCanSetMark checks SO_MARK capability on a scratch datagram socket.
func probeCanSetMark(t *testing.T) bool {
	t.Helper()
	fd, err := socketProbeFD()
	if err != nil {
		return false
	}
	defer closeProbeFD(fd)
	return setMarkProbe(fd) == nil
}
