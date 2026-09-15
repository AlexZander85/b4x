package managed

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrUnsignedCatalog is returned when a resolver catalog fails signature or
// provenance verification (zero-tolerance gate dns_unsigned_catalog_applied_total).
var ErrUnsignedCatalog = errors.New("resolver catalog signature verification failed")

// CatalogEntry is one validated resolver entry. Stamp is optional for legacy
// v1 catalogs, but production managed providers require it so generated
// dnscrypt-proxy instances are self-contained and cannot silently select a
// resolver from an external/default source list.
type CatalogEntry struct {
	Name        string `json:"name"`
	Family      string `json:"family"` // dnscrypt | pqdnscrypt | doh | odoh | relay
	NoLog       bool   `json:"nolog"`
	NoFilter    bool   `json:"nofilter"`
	DNSSEC      bool   `json:"dnssec"`
	Stamp       string `json:"stamp,omitempty"`
	Description string `json:"description,omitempty"`
}

// ProductionReady reports whether the signed entry carries the minimum
// material needed to instantiate one deterministic managed upstream.
func (e CatalogEntry) ProductionReady() bool {
	if strings.TrimSpace(e.Name) == "" || strings.TrimSpace(e.Stamp) == "" {
		return false
	}
	if !strings.HasPrefix(strings.TrimSpace(e.Stamp), "sdns://") {
		return false
	}
	switch e.Family {
	case "dnscrypt", "pqdnscrypt", "doh":
		return true
	default:
		return false
	}
}

// Catalog is a bounded, signed resolver list.
type Catalog struct {
	Version  string         `json:"version"`
	Entries  []CatalogEntry `json:"entries"`
	MaxSize  int            `json:"-"`
	LoadedAt time.Time      `json:"loaded_at"`
}

// ParseCatalog parses and bounds a catalog payload. Legacy v1 lines use
// "name|family|nolog|nofilter|dnssec". The self-contained form appends a
// sixth `stamp` field. Legacy entries remain parseable for rollback/history,
// but ProductionReady() is false until a signed stamp is present.
func ParseCatalog(payload []byte, maxEntries int) (*Catalog, error) {
	if maxEntries <= 0 {
		maxEntries = 512
	}
	lines := strings.Split(string(payload), "\n")
	c := &Catalog{MaxSize: maxEntries, LoadedAt: time.Now()}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if fields[0] == "version" && len(fields) == 2 {
			c.Version = strings.TrimSpace(fields[1])
			continue
		}
		if len(fields) != 5 && len(fields) != 6 {
			return nil, fmt.Errorf("malformed catalog line %q", line)
		}
		if len(c.Entries) >= maxEntries {
			return nil, fmt.Errorf("catalog exceeds bound %d", maxEntries)
		}
		entry := CatalogEntry{
			Name: strings.TrimSpace(fields[0]), Family: strings.TrimSpace(fields[1]),
			NoLog: strings.TrimSpace(fields[2]) == "true",
			NoFilter: strings.TrimSpace(fields[3]) == "true",
			DNSSEC: strings.TrimSpace(fields[4]) == "true",
		}
		if len(fields) == 6 {
			entry.Stamp = strings.TrimSpace(fields[5])
			if entry.Stamp != "" && !strings.HasPrefix(entry.Stamp, "sdns://") {
				return nil, fmt.Errorf("catalog entry %q has invalid resolver stamp", entry.Name)
			}
		}
		c.Entries = append(c.Entries, entry)
	}
	if c.Version == "" {
		return nil, fmt.Errorf("catalog version header missing")
	}
	return c, nil
}

// SignaturePayload is the detached signature envelope: base64 ed25519
// signature over the catalog payload, made by the pinned B4X catalog key.
type SignaturePayload struct {
	PublicKey string `json:"public_key"` // base64 ed25519 public key
	Signature string `json:"signature"`  // base64 signature over payload
}

// VerifyCatalogSignature verifies the detached ed25519 signature against a
// pinned trusted key. Arbitrary keys embedded in the download are not
// trusted: the caller supplies the pinned key.
func VerifyCatalogSignature(payload []byte, sig SignaturePayload, pinnedKeyB64 string) error {
	if sig.PublicKey != pinnedKeyB64 {
		return fmt.Errorf("%w: signer key is not the pinned catalog key", ErrUnsignedCatalog)
	}
	pub, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key", ErrUnsignedCatalog)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: bad signature encoding", ErrUnsignedCatalog)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sigBytes) {
		return fmt.Errorf("%w: signature mismatch", ErrUnsignedCatalog)
	}
	return nil
}

// AtomicUpdate implements the §48 update chain: verify → parse → write
// candidate → atomic replace → retain last-good → rollback on failure.
func AtomicUpdate(dir string, payload []byte, sig SignaturePayload, pinnedKeyB64 string, maxEntries int) (*Catalog, error) {
	if err := VerifyCatalogSignature(payload, sig, pinnedKeyB64); err != nil {
		return nil, err
	}
	cat, err := ParseCatalog(payload, maxEntries)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	final := filepath.Join(dir, "catalog.current")
	candidate := filepath.Join(dir, "catalog.candidate")
	lastGood := filepath.Join(dir, "catalog.lastgood")
	if err := os.WriteFile(candidate, payload, 0o600); err != nil {
		return nil, err
	}
	// retain last-good before replace
	if existing, err := os.ReadFile(final); err == nil {
		_ = os.WriteFile(lastGood, existing, 0o600)
	}
	if err := os.Rename(candidate, final); err != nil {
		os.Remove(candidate)
		return nil, err
	}
	return cat, nil
}

// Rollback restores the last-good catalog after a failed update.
func Rollback(dir string) error {
	final := filepath.Join(dir, "catalog.current")
	lastGood := filepath.Join(dir, "catalog.lastgood")
	if _, err := os.Stat(lastGood); err != nil {
		return fmt.Errorf("no last-good catalog to roll back to")
	}
	return os.Rename(lastGood, final)
}
