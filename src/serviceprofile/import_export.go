package serviceprofile

import (
	"encoding/json"
	"github.com/daniellavrushin/b4/serviceprofile/schema"
)

type ExportEnvelope struct {
	Manifest        schema.Manifest `json:"manifest"`
	Provenance      string          `json:"provenance"`
	SecretsRedacted bool            `json:"secrets_redacted"`
}

func Export(m schema.Manifest, provenance string) ([]byte, error) {
	return json.Marshal(ExportEnvelope{Manifest: m, Provenance: provenance, SecretsRedacted: true})
}
func Import(data []byte) (schema.Manifest, error) {
	var e ExportEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		return schema.Manifest{}, err
	}
	return e.Manifest, nil
}
