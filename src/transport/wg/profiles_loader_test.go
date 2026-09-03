// PATCH-05 (WG MAJOR 5, Variant B): field-profile library loader tests.
// The seed catalog stays template-grade fallback; the loader validates
// field-grade libraries incl. the quic-* 44d0 / >=1200B invariant.
package transportwg

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// quicFieldJSON builds one quic-* library entry with a plausible QUIC
// v1-Initial fixed blob: the 44d0 marker, a version field, DCID, and
// deterministic pseudo-random payload padding the datagram past the
// RFC 9000 §14 floor (>= 1200 B).
func quicFieldJSON(t *testing.T, id string, blobBytes int) []byte {
	t.Helper()
	if blobBytes < 2 {
		blobBytes = minQuicInitialBytes
	}
	blob := make([]byte, blobBytes)
	blob[0], blob[1] = 0x44, 0xd0 // the field marker
	rng := rand.New(rand.NewSource(42))
	rng.Read(blob[2:])
	spec := "<b 0x" + hex.EncodeToString(blob) + "><t>"
	entry := map[string]any{
		"id":     id,
		"target": "cf-warp",
		"ports":  []uint16{2408, 4500},
		"comment": "measured Nova-lineage QUIC Initial (variant B fixture); " +
			"source=field-measurement; sha256=fixture",
		"jc":   4,
		"jmin": blobBytes,
		"jmax": blobBytes,
		"i1":   spec,
	}
	out, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func writeLib(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestLoadProfileLibraryQuicMarkers is the PATCH-05 acceptance test: a
// field library whose quic-* entries carry the 44d0 marker and a >= 1200 B
// fixed Initial loads and validates; short or marker-less blobs are
// rejected structurally.
func TestLoadProfileLibraryQuicMarkers(t *testing.T) {
	dir := writeLib(t, map[string][]byte{
		"quic-field-a.json": quicFieldJSON(t, "quic-field-a", 1252),
		"quic-field-b.json": quicFieldJSON(t, "quic-field-b", 1200),
	})
	lib, err := LoadProfileLibrary(dir)
	if err != nil {
		t.Fatalf("valid field library rejected: %v", err)
	}
	if len(lib) != 2 {
		t.Fatalf("library size = %d, want 2", len(lib))
	}
	for _, tpl := range lib {
		p, err := tpl.Build()
		if err != nil {
			t.Fatalf("%s: build: %v", tpl.ID, err)
		}
		if err := validateQuicFieldProfile(p); err != nil {
			t.Fatalf("%s: invariant: %v", tpl.ID, err)
		}
	}

	// Short Initial (RFC 9000 floor violated).
	dir = writeLib(t, map[string][]byte{
		"bad.json": quicFieldJSON(t, "quic-short", 900),
	})
	if _, err := LoadProfileLibrary(dir); err == nil || !strings.Contains(err.Error(), "quic field invariant") {
		t.Fatalf("short Initial accepted: %v", err)
	}

	// Missing marker: starts with garbage bytes.
	dir = writeLib(t, map[string][]byte{
		"bad.json": quicFieldJSON(t, "quic-nomarker", 1200),
	})
	// Patch the fixture: flip the first bytes by rewriting i1 via a fresh entry.
	blob := make([]byte, 1200)
	blob[0], blob[1] = 0x17, 0x70
	rng := rand.New(rand.NewSource(7))
	rng.Read(blob[2:])
	entry := map[string]any{
		"id": "quic-nomarker", "target": "cf-warp",
		"jc": 1, "jmin": 1200, "jmax": 1200,
		"i1": "<b 0x" + hex.EncodeToString(blob) + ">",
	}
	blobJSON, _ := json.Marshal(entry)
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), blobJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfileLibrary(dir); err == nil || !strings.Contains(err.Error(), "marker") {
		t.Fatalf("marker-less Initial accepted: %v", err)
	}
}

// TestLoadProfileLibraryStructuralRejections pins the loader gates:
// duplicate IDs (incl. seed shadowing), bad targets, bad chain DSL.
func TestLoadProfileLibraryStructuralRejections(t *testing.T) {
	good := quicFieldJSON(t, "quic-field-x", 1200)

	t.Run("duplicate-within-library", func(t *testing.T) {
		dir := writeLib(t, map[string][]byte{
			"a.json": good,
			"b.json": quicFieldJSON(t, "quic-field-x", 1200),
		})
		if _, err := LoadProfileLibrary(dir); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate id accepted: %v", err)
		}
	})

	t.Run("seed-shadowing", func(t *testing.T) {
		entry := map[string]any{"id": "quic-a", "target": "cf-warp"}
		blob, _ := json.Marshal(entry)
		dir := writeLib(t, map[string][]byte{"a.json": blob})
		if _, err := LoadProfileLibrary(dir); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("seed shadowing accepted: %v", err)
		}
	})

	t.Run("bad-target", func(t *testing.T) {
		entry := map[string]any{"id": "vanilla-field", "target": "vless"}
		blob, _ := json.Marshal(entry)
		dir := writeLib(t, map[string][]byte{"a.json": blob})
		if _, err := LoadProfileLibrary(dir); err == nil {
			t.Fatal("bad target accepted")
		}
	})

	t.Run("bad-chain-dsl", func(t *testing.T) {
		entry := map[string]any{
			"id": "crlf-field", "target": "cf-warp",
			"jc": 1, "jmin": 40, "jmax": 70,
			"i1": "<b 0x0d0a> typo outside tags",
		}
		blob, _ := json.Marshal(entry)
		dir := writeLib(t, map[string][]byte{"a.json": blob})
		if _, err := LoadProfileLibrary(dir); err == nil {
			t.Fatal("bad chain DSL accepted")
		}
	})

	t.Run("cf-warp-must-be-vanilla-safe", func(t *testing.T) {
		entry := map[string]any{
			"id": "cf-sh", "target": "cf-warp",
			"jc": 1, "jmin": 40, "jmax": 70,
			"s1": 15,
			"h1": [2]uint32{123456, 123500},
		}
		blob, _ := json.Marshal(entry)
		dir := writeLib(t, map[string][]byte{"a.json": blob})
		if _, err := LoadProfileLibrary(dir); err == nil || !strings.Contains(err.Error(), "vanilla-safe") {
			t.Fatalf("S/H profile accepted for cf-warp: %v", err)
		}
	})

	t.Run("empty-dir", func(t *testing.T) {
		if _, err := LoadProfileLibrary(t.TempDir()); err == nil {
			t.Fatal("empty library dir accepted")
		}
	})
}

// TestCatalogV2QuicMarkers documents the v2 posture: the SEED quic templates
// are intentionally NOT field-grade (template-grade fallback per plan
// Variant B), while the merged invariant (marker + length) holds for every
// quic-* entry a field LIBRARY contributes.
func TestCatalogV2QuicMarkers(t *testing.T) {
	for _, tpl := range defaultCatalog() {
		if !strings.HasPrefix(tpl.ID, "quic-") {
			continue
		}
		p, err := tpl.Build()
		if err != nil {
			t.Fatalf("seed %s: %v", tpl.ID, err)
		}
		if err := validateQuicFieldProfile(p); err == nil {
			t.Fatalf("seed %s unexpectedly passes the field invariant — if seeds became field-grade, update this posture", tpl.ID)
		}
	}
	// The merged posture: seeds + a loaded library coexist under one set of
	// invariants (duplicates impossible, quic field entries field-grade).
	dir := writeLib(t, map[string][]byte{
		"field.json": quicFieldJSON(t, "quic-field-nova", 1252),
	})
	lib, err := LoadProfileLibrary(dir)
	if err != nil {
		t.Fatal(err)
	}
	merged := append(defaultCatalog(), lib...)
	seen := map[string]bool{}
	for _, tpl := range merged {
		if seen[tpl.ID] {
			t.Fatalf("duplicate id in merged set: %s", tpl.ID)
		}
		seen[tpl.ID] = true
	}
	if CatalogVersion != 2 {
		t.Fatalf("CatalogVersion = %d, want 2", CatalogVersion)
	}
}
