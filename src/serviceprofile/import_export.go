package serviceprofile

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/daniellavrushin/b4/serviceprofile/schema"
	"github.com/daniellavrushin/b4/serviceprofile/validate"
)

type ExportEnvelope struct {
	Manifest        schema.Manifest `json:"manifest"`
	Provenance      string          `json:"provenance"`
	SecretsRedacted bool            `json:"secrets_redacted"`
}

// Export serialises a profile pack without secrets (SP-12: "export profile
// without secrets"; SP 22: "profile pack/export не содержит пользовательских
// proxy secrets"). The manifest is validated first, so an invalid or
// secret-bearing manifest can never leave the device, and the envelope is
// explicitly marked secrets_redacted=true.
func Export(m schema.Manifest, provenance string) ([]byte, error) {
	if strings.TrimSpace(provenance) == "" {
		return nil, errors.New("export requires provenance")
	}
	if err := validate.Manifest(m); err != nil {
		return nil, err
	}
	return json.Marshal(ExportEnvelope{Manifest: m, Provenance: provenance, SecretsRedacted: true})
}

// Import restores a profile pack. Fail-closed by construction (SP-12):
//   - a pack that is not explicitly marked secrets_redacted is rejected, so an
//     envelope that (incorrectly) declares unredacted secrets cannot be used to
//     author a profile from secret-bearing material;
//   - the provenance must be non-empty (shared packs must stay traceable);
//   - the embedded manifest must pass full schema validation before it is
//     accepted as authorable content.
func Import(data []byte) (schema.Manifest, error) {
	var e ExportEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		return schema.Manifest{}, err
	}
	if !e.SecretsRedacted {
		return schema.Manifest{}, errors.New("import rejected: pack is not secrets-redacted")
	}
	if strings.TrimSpace(e.Provenance) == "" {
		return schema.Manifest{}, errors.New("import rejected: provenance missing")
	}
	if err := validate.Manifest(e.Manifest); err != nil {
		return schema.Manifest{}, err
	}
	return e.Manifest, nil
}

// ForkManagedProfile creates a locally authored copy of a managed profile
// (SP-12 "fork managed profile"). The fork must be a first-class manifest
// again: it gets a new id and its provenance records the fork origin, while
// the source profile stays untouched.
func ForkManagedProfile(source schema.Manifest, newID, forker string) (schema.Manifest, error) {
	if err := validate.Manifest(source); err != nil {
		return schema.Manifest{}, err
	}
	if strings.TrimSpace(newID) == "" || strings.TrimSpace(forker) == "" {
		return schema.Manifest{}, errors.New("fork requires new id and author")
	}
	f := source
	f.ID = newID
	f.Provenance = schema.Provenance{
		Source:   "forked",
		Signer:   forker,
		Version:  "1",
		Official: false,
	}
	return f, nil
}
