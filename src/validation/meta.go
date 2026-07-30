package validation

import "crypto/sha256"

type Artifact struct {
	Name, SHA256, Kind string
	Size               int64
	Redacted           bool
}

func ArtifactValid(a Artifact) bool {
	return a.Name != "" && len(a.SHA256) == 64 && a.Kind != "" && a.Size >= 0 && a.Redacted
}

type MetaResult struct {
	RegistryComplete, APIParity, VerdictMutationDetected, EvidenceIntegrity, Reproducible, InfrastructureSafe, FalseNegativeDetected bool
	Artifacts                                                                                                                        []Artifact
}

func (m MetaResult) Ready() bool {
	if !m.RegistryComplete || !m.APIParity || !m.VerdictMutationDetected || !m.EvidenceIntegrity || !m.Reproducible || !m.InfrastructureSafe || !m.FalseNegativeDetected {
		return false
	}
	for _, a := range m.Artifacts {
		if !ArtifactValid(a) {
			return false
		}
	}
	return len(m.Artifacts) > 0
}
func HashBytes(b []byte) string { h := sha256.Sum256(b); return fmtHex(h[:]) }
func fmtHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hex[x>>4]
		out[i*2+1] = hex[x&15]
	}
	return string(out)
}
