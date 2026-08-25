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

// CatalogEntry is one validated resolver entry.
type CatalogEntry struct {
	Name      string `json:"name"`
	Family    string `json:"family"` // dnscrypt | doh | odoh | relay
	NoLog     bool   `json:"nolog"`
	NoFilter  bool   `json:"nofilter"`
	DNSSEC    bool   `json:"dnssec"`
	Description string `json:"description,omitempty"`
}

// Catalog is a bounded, signed resolver list.
type Catalog struct {
	Version   string         `json:"version"`
	Entries   []CatalogEntry `json:"entries"`
	MaxSize   int            `json:"-"`
	LoadedAt  time.Time      `json:"loaded_at"`
}

// ParseCatalog parses and bounds a catalog payload. Payload format (v1):
// line-based "name|family|nolog|nofilter|dnssec" with a header line
// "version|<id>".
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
			c.Version = fields[1]
			continue
		}
		if len(fields) != 5 {
			return nil, fmt.Errorf("malformed catalog line %q", line)
		}
		if len(c.Entries) >= maxEntries {
			return nil, fmt.Errorf("catalog exceeds bound %d", maxEntries)
		}
		c.Entries = append(c.Entries, CatalogEntry{
			Name: fields[0], Family: fields[1],
			NoLog: fields[2] == "true", NoFilter: fields[3] == "true", DNSSEC: fields[4] == "true",
		})
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
