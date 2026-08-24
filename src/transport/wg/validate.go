// Pre-IpcSet validator for AWG parameters. The embedded daemon validates
// almost nothing at IpcSet time: jc/jmin/jmax are stored raw (uapi.go:355-380),
// junk packet generation underflows when jmax<jmin (noise-protocol.go), and
// negative chain lengths pass Atoi. The only structural checks the daemon
// performs are H-interval overlap and HP-key=>S>=12 (uapi.go:824-859) — we
// re-check those here anyway so a bad config never reaches a live device.
//
// Storage-vs-render rule (zapret-gui lesson, research §2): J1-J3/Itime are
// kept in Profile but NEVER rendered into IpcSet — external awg tools drop
// the WHOLE config on unknown keys ("Line unrecognized"), so the whitelist in
// confbridge.go is load-bearing.
package transportwg

import (
	"fmt"
	"strings"
)

// Validator bounds (design §3; wireproxy-awg ASecConfigType reference).
const (
	MaxJunkCount   = 128  // jc upper bound
	MaxJunkSize    = 1280 // jmax upper bound
	minPadForHPKey = 12   // HeaderCipherNonceSize (noise-types.go:23)
	maxHeaderType  = 0xFFFFFFFF
)

// Range is an inclusive [Lo,Hi] interval rendered as "lo" or "lo-hi"
// (upstream UintRange string form, noise-types.go:106-131).
type Range struct {
	Lo, Hi uint32
}

// ParseRange parses "lo" or "lo-hi"; hi >= lo enforced.
func ParseRange(s string) (Range, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return Range{}, fmt.Errorf("transportwg: wrong range format %q", s)
	}
	var r Range
	lo, err := parseUint32(parts[0])
	if err != nil {
		return Range{}, fmt.Errorf("transportwg: range lo %q: %w", parts[0], err)
	}
	r.Lo = lo
	r.Hi = lo
	if len(parts) == 2 {
		hi, err := parseUint32(parts[1])
		if err != nil {
			return Range{}, fmt.Errorf("transportwg: range hi %q: %w", parts[1], err)
		}
		r.Hi = hi
	}
	if r.Hi < r.Lo {
		return Range{}, fmt.Errorf("transportwg: range %q inverted", s)
	}
	return r, nil
}

// String renders canonical "lo" / "lo-hi".
func (r Range) String() string {
	if r.Lo == r.Hi {
		return fmt.Sprintf("%d", r.Lo)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// overlaps reports whether two inclusive intervals intersect.
func (r Range) overlaps(o Range) bool { return r.Lo <= o.Hi && o.Lo <= r.Hi }

// Profile carries every AWG obfuscation parameter of one device config.
// Zero value = vanilla wireguard-compatible profile (all features off).
type Profile struct {
	JunkCount        uint32 // jc: 0 = off, else 1..128
	JunkMin          uint32 // jmin
	JunkMax          uint32 // jmax <= 1280
	PadInit          uint32 // s1
	PadResponse      uint32 // s2
	PadCookie        uint32 // s3
	PadTransport     uint32 // s4
	HeaderInit       *Range // h1..h4: nil = not set
	HeaderResponse   *Range
	HeaderCookie     *Range
	HeaderTransport  *Range
	InitPacket       [5]string // i1..i5 chain specs (validated)
	HiddenJunk       [3]string // j1..j3 — STORE-ONLY, never rendered to IPC
	JunkIntervalSec  uint32    // itime — STORE-ONLY, never rendered to IPC
	HeaderProtKey    []byte    // header_protection_key: empty or exactly 32 bytes
	ContentPadding   *Range    // content_padding_addition
	RandomTrailers   bool      // v3: symmetric both ends (rendered true/false)
	DisableCookies   bool
	RekeyAfterTime   *Range // seconds ranges (v3 timing knobs)
	RekeyTimeout     *Range
	RejectAfterTime  *Range
	KeepaliveTimeout *Range
	MaxHandshakeAtt  *Range
}

// Validate enforces every structural rule BEFORE any device sees the config.
func (p *Profile) Validate() error {
	// Junk triple.
	if p.JunkCount > MaxJunkCount {
		return fmt.Errorf("transportwg: jc=%d exceeds max %d", p.JunkCount, MaxJunkCount)
	}
	hasSizes := p.JunkMin > 0 || p.JunkMax > 0
	if p.JunkCount > 0 && !hasSizes {
		return fmt.Errorf("transportwg: jc=%d requires jmin and jmax", p.JunkCount)
	}
	if hasSizes {
		if p.JunkCount == 0 {
			return fmt.Errorf("transportwg: jmin/jmax set but jc=0 (meaningless junk sizing)")
		}
		if p.JunkMin == 0 {
			return fmt.Errorf("transportwg: jmin must be >= 1")
		}
		if p.JunkMin > p.JunkMax {
			return fmt.Errorf("transportwg: jmin(%d) > jmax(%d)", p.JunkMin, p.JunkMax)
		}
		if p.JunkMax > MaxJunkSize {
			return fmt.Errorf("transportwg: jmax(%d) exceeds max %d", p.JunkMax, MaxJunkSize)
		}
	}

	// Header intervals: pairwise non-overlap among set values.
	hdrs := []struct {
		name string
		r    *Range
	}{
		{"h1", p.HeaderInit}, {"h2", p.HeaderResponse},
		{"h3", p.HeaderCookie}, {"h4", p.HeaderTransport},
	}
	for _, h := range hdrs {
		if h.r == nil {
			continue
		}
		if h.r.Lo > maxHeaderType {
			return fmt.Errorf("transportwg: %s out of uint32", h.name)
		}
	}
	for i := 0; i < len(hdrs); i++ {
		for j := i + 1; j < len(hdrs); j++ {
			a, b := hdrs[i], hdrs[j]
			if a.r != nil && b.r != nil && a.r.overlaps(*b.r) {
				return fmt.Errorf("transportwg: %s %s overlaps %s %s", a.name, a.r, b.name, b.r)
			}
		}
	}

	// Chains: I1-I5 rendered + J1-J3 stored-only all get hard validation.
	for i, spec := range p.InitPacket {
		if spec == "" {
			continue
		}
		if err := ValidateChainSpec(spec); err != nil {
			return fmt.Errorf("transportwg: i%d: %w", i+1, err)
		}
	}
	for i, spec := range p.HiddenJunk {
		if spec == "" {
			continue
		}
		if err := ValidateChainSpec(spec); err != nil {
			return fmt.Errorf("transportwg: j%d (store-only): %w", i+1, err)
		}
	}

	// HP-key requires S1-S4 >= 12 (upstream uapi.go:852-859).
	if len(p.HeaderProtKey) > 0 {
		if len(p.HeaderProtKey) != 32 {
			return fmt.Errorf("transportwg: header_protection_key must be 32 bytes, got %d", len(p.HeaderProtKey))
		}
		pads := []struct {
			name string
			v    uint32
		}{
			{"s1", p.PadInit}, {"s2", p.PadResponse},
			{"s3", p.PadCookie}, {"s4", p.PadTransport},
		}
		for _, pd := range pads {
			if pd.v < minPadForHPKey {
				return fmt.Errorf("transportwg: %s=%d < %d required by header_protection_key", pd.name, pd.v, minPadForHPKey)
			}
		}
	}

	// Misc ranges.
	ranges := []struct {
		name string
		r    *Range
	}{
		{"content_padding_addition", p.ContentPadding},
		{"rekey_after_time", p.RekeyAfterTime}, {"rekey_timeout", p.RekeyTimeout},
		{"reject_after_time", p.RejectAfterTime}, {"keepalive_timeout", p.KeepaliveTimeout},
		{"max_handshake_attempts", p.MaxHandshakeAtt},
	}
	for _, rr := range ranges {
		if rr.r == nil {
			continue
		}
		if rr.r.Lo > rr.r.Hi {
			return fmt.Errorf("transportwg: %s range inverted", rr.name)
		}
	}
	return nil
}

// VanillaSafe reports whether the profile modifies ONLY client-side-only
// parameters (junk count/size, I-chains). Against a vanilla peer (e.g. the
// Cloudflare edge) S/H modifications break the handshake on the peer side
// (research §7 finding 3), so seek-ladder profiles that may target vanilla
// edges must pass this check.
func (p *Profile) VanillaSafe() bool {
	return p.PadInit == 0 && p.PadResponse == 0 && p.PadCookie == 0 && p.PadTransport == 0 &&
		p.HeaderInit == nil && p.HeaderResponse == nil && p.HeaderCookie == nil && p.HeaderTransport == nil &&
		len(p.HeaderProtKey) == 0 && !p.RandomTrailers
}

// parseUint32 is strconv.ParseUint with a wrapped error type.
func parseUint32(s string) (uint32, error) {
	var v uint64
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &v)
	if err != nil || v > 0xFFFFFFFF {
		return 0, fmt.Errorf("not a uint32")
	}
	return uint32(v), nil
}
