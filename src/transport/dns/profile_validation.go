package dnspath

import "time"

// Validated is the production acceptance contract for a READY DNS profile.
// Valid() intentionally remains the structural/freshness compatibility check
// for older serialized profiles; production callers must additionally prove
// the canonical repeated evidence chain before the profile can influence
// discovery, canary or promotion.
func (p *DNSPathProfile) Validated(now time.Time) error {
	if err := p.Valid(now); err != nil {
		return err
	}
	return ValidatePromotionEvidence(p)
}
