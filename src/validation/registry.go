package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

const RegistryVersion uint16 = 1

type Requirement struct {
	ID, Description, Source, Stage, Suite string
	Blocking                              bool
}
type Coverage struct {
	RequirementID, TestID, Artifact string
	Verdict                         string
}
type Registry struct {
	Version      uint16
	AddendumHash string
	Requirements []Requirement
	Coverage     []Coverage
}

func (r Registry) CanonicalBytes() []byte {
	c := r
	sort.Slice(c.Requirements, func(i, j int) bool { return c.Requirements[i].ID < c.Requirements[j].ID })
	sort.Slice(c.Coverage, func(i, j int) bool {
		if c.Coverage[i].RequirementID != c.Coverage[j].RequirementID {
			return c.Coverage[i].RequirementID < c.Coverage[j].RequirementID
		}
		return c.Coverage[i].TestID < c.Coverage[j].TestID
	})
	b, _ := json.Marshal(c)
	return b
}
func (r Registry) Hash() string {
	h := sha256.Sum256(r.CanonicalBytes())
	return hex.EncodeToString(h[:])
}
func (r Registry) Orphans(declaredStages map[string]bool) []string {
	covered := map[string]bool{}
	for _, c := range r.Coverage {
		covered[c.RequirementID] = true
	}
	var out []string
	for _, q := range r.Requirements {
		if declaredStages[q.Stage] && !covered[q.ID] {
			out = append(out, q.ID)
		}
	}
	sort.Strings(out)
	return out
}
func (r Registry) Valid() bool {
	return r.Version == RegistryVersion && r.AddendumHash != "" && len(r.Requirements) > 0 && len(r.Coverage) > 0 && len(r.Orphans(map[string]bool{})) == 0
}
