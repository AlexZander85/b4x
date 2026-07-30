package serviceprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/daniellavrushin/b4/serviceprofile/schema"
	"github.com/daniellavrushin/b4/serviceprofile/validate"
)

type OrdinarySet struct {
	ID, ComponentID, Domain string
	Ownership               Ownership
}
type StrategyBinding struct{ ID, ComponentID, Delivery string }
type Probe struct{ ID, ComponentID, Role string }
type CompiledComponentSafety struct {
	ComponentID                         string
	EffectivePolicy                     schema.ExecutionPolicy
	RequiresCleanPath, RequiresControls bool
	CapabilityRequirements              []string
}
type CompiledProfile struct {
	ProfileID, SafetyHash string
	Sets                  []OrdinarySet
	Strategies            []StrategyBinding
	Probes                []Probe
	Safety                []CompiledComponentSafety
}
type CompileOptions struct {
	Existing []OrdinarySet
	DryRun   bool
}

func Compile(m schema.Manifest, opts CompileOptions) (CompiledProfile, error) {
	if err := validate.Manifest(m); err != nil {
		return CompiledProfile{}, err
	}
	result := CompiledProfile{ProfileID: m.ID, SafetyHash: m.SafetyHash()}
	for _, c := range m.Components {
		if c.Delivery == "" {
			return CompiledProfile{}, fmt.Errorf("missing delivery for %s", c.ID)
		}
		s := CompiledComponentSafety{ComponentID: c.ID, EffectivePolicy: c.Execution, RequiresCleanPath: true, RequiresControls: true, CapabilityRequirements: []string{"scoped-authorization"}}
		result.Safety = append(result.Safety, s)
		for _, t := range c.Targets {
			for _, d := range t.Domains {
				id := stableID(m.ID, c.ID, d)
				result.Sets = append(result.Sets, OrdinarySet{ID: id, ComponentID: c.ID, Domain: d, Ownership: Managed})
				result.Probes = append(result.Probes, Probe{ID: id + "/" + t.Role, ComponentID: c.ID, Role: t.Role})
			}
		}
		result.Strategies = append(result.Strategies, StrategyBinding{ID: c.ID + "/delivery", ComponentID: c.ID, Delivery: string(c.Delivery)})
	}
	sort.Slice(result.Sets, func(i, j int) bool { return result.Sets[i].ID < result.Sets[j].ID })
	sort.Slice(result.Probes, func(i, j int) bool { return result.Probes[i].ID < result.Probes[j].ID })
	sort.Slice(result.Safety, func(i, j int) bool { return result.Safety[i].ComponentID < result.Safety[j].ComponentID })
	return result, nil
}
func stableID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
