package validate

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/daniellavrushin/b4/serviceprofile/schema"
)

var ErrInvalidManifest = errors.New("invalid service profile manifest")

func Manifest(m schema.Manifest) error {
	if m.SchemaVersion == 0 || m.SchemaVersion > schema.CurrentVersion || strings.TrimSpace(m.ID) == "" || strings.TrimSpace(m.Name) == "" {
		return ErrInvalidManifest
	}
	if len(m.Components) == 0 || len(m.Components) > 64 {
		return fmt.Errorf("%w: components", ErrInvalidManifest)
	}
	seen := map[string]bool{}
	for _, c := range m.Components {
		if c.ID == "" || seen[c.ID] {
			return fmt.Errorf("%w: duplicate component", ErrInvalidManifest)
		}
		seen[c.ID] = true
		if c.Delivery == "" {
			return fmt.Errorf("%w: delivery", ErrInvalidManifest)
		}
		if c.Execution != schema.ExecutionOff && c.Execution != schema.ExecutionObserve && c.Execution != schema.ExecutionRecommend && c.Execution != schema.ExecutionAutoCanary {
			return fmt.Errorf("%w: execution", ErrInvalidManifest)
		}
		if strings.EqualFold(c.PassiveRST, "aggressive") {
			return fmt.Errorf("%w: aggressive passive rst", ErrInvalidManifest)
		}
		for _, t := range c.Targets {
			if t.Name == "" || (t.Role != "primary" && t.Role != "same-service-control" && t.Role != "same-provider-control" && t.Role != "unrelated-control" && t.Role != "custom") {
				return fmt.Errorf("%w: target role", ErrInvalidManifest)
			}
			for _, d := range t.Domains {
				d = strings.TrimSpace(d)
				if d == "" || strings.ContainsAny(d, "/\\*$") {
					if _, _, e := net.ParseCIDR(d); e != nil {
						return fmt.Errorf("%w: domain", ErrInvalidManifest)
					}
				}
			}
		}
	}
	return nil
}
