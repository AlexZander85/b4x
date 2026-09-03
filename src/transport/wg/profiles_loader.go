// PATCH-05 (WG MAJOR 5), Variant B: external field-profile library loader.
//
// The seed catalog (profiles.go) deliberately ships conservative TEMPLATES,
// not byte-exact vendor blobs — the measured Nova/Aether QUIC Initials
// (44d0-marker, >= 1200 B RFC 9000 §14 Initials) belong to a FIELD library,
// not to a source tree. This loader brings such libraries in without code
// changes:
//
//	LoadProfileLibrary(dir) reads *.json files (sorted by name); each file
//	holds ONE entry or an ARRAY of entries in the catalog wire schema;
//	every entry is validated through ProfileTemplate.Build (Profile.Validate
//	+ cf-warp vanilla-safety) and the chain-DSL hard validator; quic-*
//	family entries must carry the 44d0 marker and a fixed Initial of
//	>= 1200 bytes (field-grade invariant, plan PATCH-05).
//
// Duplicate IDs are rejected — including collisions with the SEED catalog —
// so a library can never silently shadow a seed profile.
//
// CatalogVersion bumps to 2 with this schema. HONEST POSTURE (plan Variant
// B note): the seed fallback ladder remains template-grade; the
// "junk-first ladder is field-ready" claim holds ONLY when a validated
// field library is loaded and wired by the engine.
package transportwg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// quicFieldMarker is the first two bytes of a measured QUIC Initial blob
// (review plan PATCH-05: "маркер 44d0 в ожидаемой позиции").
const quicFieldMarker = "44d0"

// minQuicInitialBytes is the RFC 9000 §14 floor for a datagram carrying a
// QUIC Initial — the field blob must fill at least this much.
const minQuicInitialBytes = 1200

// profileFileEntry is the JSON wire schema of one catalog entry.
type profileFileEntry struct {
	ID      string   `json:"id"`
	Target  string   `json:"target"`
	Ports   []uint16 `json:"ports,omitempty"`
	Comment string   `json:"comment,omitempty"`

	JunkCount uint32 `json:"jc,omitempty"`
	JunkMin   uint32 `json:"jmin,omitempty"`
	JunkMax   uint32 `json:"jmax,omitempty"`

	// EngineGeneration: minimum demon generation for this profile
	// (PATCH-17). A library entry demanding a newer demon than the running
	// one is skipped by the ladder, not discarded.
	EngineGeneration int `json:"engine_generation,omitempty"`

	// Chain DSL slots (i1..i5 packets, j1..j3 hidden junk — the j-slots are
	// STORE-ONLY upstream, never rendered to IPC; same red line as seeds).
	I1 string `json:"i1,omitempty"`
	I2 string `json:"i2,omitempty"`
	I3 string `json:"i3,omitempty"`
	I4 string `json:"i4,omitempty"`
	I5 string `json:"i5,omitempty"`
	J1 string `json:"j1,omitempty"`
	J2 string `json:"j2,omitempty"`
	J3 string `json:"j3,omitempty"`

	JunkIntervalSec uint32 `json:"itime,omitempty"` // STORE-ONLY (never rendered)

	PadInit         uint32     `json:"s1,omitempty"`
	PadResponse     uint32     `json:"s2,omitempty"`
	PadCookie       uint32     `json:"s3,omitempty"`
	PadTransport    uint32     `json:"s4,omitempty"`
	HeaderInit      *[2]uint32 `json:"h1,omitempty"`
	HeaderResponse  *[2]uint32 `json:"h2,omitempty"`
	HeaderCookie    *[2]uint32 `json:"h3,omitempty"`
	HeaderTransport *[2]uint32 `json:"h4,omitempty"`
}

// LoadProfileLibrary loads and validates an external profile library from
// dir (all *.json files, sorted by filename for determinism). Returns the
// templates sorted by ID. Every entry passes Build() validation; quic-*
// family entries additionally pass the field-grade marker/length invariant.
func LoadProfileLibrary(dir string) ([]ProfileTemplate, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("transportwg: profile library glob %q: %w", dir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("transportwg: profile library %q contains no .json files", dir)
	}
	sort.Strings(files)

	var out []ProfileTemplate
	seen := map[string]bool{}
	for _, seed := range defaultCatalog() {
		seen[seed.ID] = true // seed IDs are reserved: no shadowing
	}

	for _, file := range files {
		blob, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("transportwg: profile library read %s: %w", file, err)
		}
		var raw []json.RawMessage
		if err := json.Unmarshal(blob, &raw); err != nil {
			// Single-object file: wrap it.
			var one profileFileEntry
			if err2 := json.Unmarshal(blob, &one); err2 != nil {
				return nil, fmt.Errorf("transportwg: profile library parse %s: %w", file, err)
			}
			raw = []json.RawMessage{blob}
		}
		for i, item := range raw {
			// Duplicate detection runs BEFORE per-entry validation so a
			// shadowing entry is reported as what it is, never as a
			// validation failure of its body.
			var probe profileFileEntry
			if err := json.Unmarshal(item, &probe); err != nil {
				return nil, fmt.Errorf("transportwg: profile library %s[%d]: decode: %w", filepath.Base(file), i, err)
			}
			if seen[probe.ID] {
				return nil, fmt.Errorf("transportwg: profile library %s[%d]: duplicate id %q (seeds are reserved)",
					filepath.Base(file), i, probe.ID)
			}
			t, err := decodeProfileEntry(item)
			if err != nil {
				return nil, fmt.Errorf("transportwg: profile library %s[%d]: %w", filepath.Base(file), i, err)
			}
			seen[t.ID] = true
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// decodeProfileEntry maps one wire entry onto a ProfileTemplate and runs
// every structural gate (Build + chain DSL + quic field invariant).
func decodeProfileEntry(item json.RawMessage) (ProfileTemplate, error) {
	var e profileFileEntry
	if err := json.Unmarshal(item, &e); err != nil {
		return ProfileTemplate{}, fmt.Errorf("decode: %w", err)
	}
	if strings.TrimSpace(e.ID) == "" {
		return ProfileTemplate{}, fmt.Errorf("id is required")
	}
	if e.ID != strings.TrimSpace(e.ID) || strings.ContainsAny(e.ID, " \t/") {
		return ProfileTemplate{}, fmt.Errorf("id %q must be a clean token", e.ID)
	}
	var target ProfileTarget
	switch ProfileTarget(e.Target) {
	case TargetCfWarp:
		target = TargetCfWarp
	case TargetAwgServer:
		target = TargetAwgServer
	default:
		return ProfileTemplate{}, fmt.Errorf("target %q must be %q or %q", e.Target, TargetCfWarp, TargetAwgServer)
	}

	p := Profile{
		JunkCount:       e.JunkCount,
		JunkMin:         e.JunkMin,
		JunkMax:         e.JunkMax,
		InitPacket:      [5]string{e.I1, e.I2, e.I3, e.I4, e.I5},
		HiddenJunk:      [3]string{e.J1, e.J2, e.J3},
		JunkIntervalSec: e.JunkIntervalSec,
		PadInit:         e.PadInit,
		PadResponse:     e.PadResponse,
		PadCookie:       e.PadCookie,
		PadTransport:    e.PadTransport,
	}
	if e.HeaderInit != nil {
		p.HeaderInit = rangeFromPair(e.HeaderInit)
	}
	if e.HeaderResponse != nil {
		p.HeaderResponse = rangeFromPair(e.HeaderResponse)
	}
	if e.HeaderCookie != nil {
		p.HeaderCookie = rangeFromPair(e.HeaderCookie)
	}
	if e.HeaderTransport != nil {
		p.HeaderTransport = rangeFromPair(e.HeaderTransport)
	}

	t := ProfileTemplate{
		ID:               e.ID,
		Target:           target,
		Ports:            e.Ports,
		Comment:          e.Comment,
		EngineGeneration: e.EngineGeneration,
		build:            func() Profile { return p },
	}
	if _, err := t.Build(); err != nil {
		return ProfileTemplate{}, err
	}
	// The chain-DSL hard validator runs over every non-empty slot (Build
	// covers InitPacket validation already; hidden j-slots are checked here
	// because they are store-only and skip the IPC render path).
	for i, spec := range p.HiddenJunk {
		if spec == "" {
			continue
		}
		if _, err := ParseChain(spec); err != nil {
			return ProfileTemplate{}, fmt.Errorf("j%d: %w", i+1, err)
		}
	}
	if strings.HasPrefix(e.ID, "quic-") {
		if err := validateQuicFieldProfile(p); err != nil {
			return ProfileTemplate{}, fmt.Errorf("quic field invariant: %w", err)
		}
	}
	return t, nil
}

func rangeFromPair(pair *[2]uint32) *Range {
	return &Range{Lo: pair[0], Hi: pair[1]}
}

// validateQuicFieldProfile enforces the field-grade invariant on quic-*
// profiles: the first packet chain must carry a FIXED blob that starts with
// the 44d0 marker and is at least minQuicInitialBytes long (RFC 9000 §14).
func validateQuicFieldProfile(p Profile) error {
	spec := strings.TrimSpace(p.InitPacket[0])
	if spec == "" {
		return fmt.Errorf("quic profile has no i1 chain")
	}
	elems, err := ParseChain(spec)
	if err != nil {
		return fmt.Errorf("i1: %w", err)
	}
	var blob []byte
	for _, el := range elems {
		if el.Kind == ElemBytes {
			blob = append(blob, el.Bytes...)
		}
		if len(blob) >= minQuicInitialBytes {
			break
		}
	}
	if len(blob) < minQuicInitialBytes {
		return fmt.Errorf("fixed Initial is %d bytes, want >= %d (RFC 9000 §14)", len(blob), minQuicInitialBytes)
	}
	if !strings.HasPrefix(strings.ToLower(spec), "<b 0x"+quicFieldMarker) &&
		!strings.HasPrefix(strings.ToLower(spec), "<b 0x"+strings.ToUpper(quicFieldMarker)) {
		return fmt.Errorf("fixed Initial must start with the %s marker", quicFieldMarker)
	}
	return nil
}
