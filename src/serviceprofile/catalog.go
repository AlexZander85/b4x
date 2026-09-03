package serviceprofile

import (
	"crypto/ed25519"
	"errors"
	"github.com/daniellavrushin/b4/serviceprofile/schema"
)

type CatalogSource string

const (
	Bundled        CatalogSource = "bundled"
	OfficialSigned CatalogSource = "official-signed"
	Community      CatalogSource = "community"
	Local          CatalogSource = "local"
)

type CatalogEntry struct {
	Manifest  schema.Manifest
	Source    CatalogSource
	Signature []byte
	PublicKey ed25519.PublicKey
}

func (e CatalogEntry) Verify() error {
	if e.Source == Bundled {
		if err := schemaManifest(e.Manifest); err != nil {
			return err
		}
		return nil
	}
	if e.Source == Community || e.Source == Local {
		return nil
	}
	b, err := e.Manifest.CanonicalBytes()
	if err != nil || len(e.Signature) == 0 || len(e.PublicKey) == 0 || !ed25519.Verify(e.PublicKey, b, e.Signature) {
		return errors.New("invalid profile signature")
	}
	return nil
}
func schemaManifest(m schema.Manifest) error {
	if m.ID == "" || m.SchemaVersion == 0 {
		return errors.New("invalid bundled manifest")
	}
	return nil
}

type Catalog struct{ entries map[string]CatalogEntry }

func NewCatalog() *Catalog { return &Catalog{entries: map[string]CatalogEntry{}} }
func (c *Catalog) Add(e CatalogEntry) error {
	if err := e.Verify(); err != nil {
		return err
	}
	if c.entries == nil {
		c.entries = map[string]CatalogEntry{}
	}
	c.entries[e.Manifest.ID] = e
	return nil
}
func (c *Catalog) Get(id string) (CatalogEntry, bool) { e, ok := c.entries[id]; return e, ok }
