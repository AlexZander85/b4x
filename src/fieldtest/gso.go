package fieldtest

import "errors"

type Representation string

const (
	GSOOff      Representation = "off"
	GSOObserve  Representation = "observe"
	GSOClassify Representation = "classify"
	MSSBaseline Representation = "mss"
)

type ParityResult struct {
	DecisionHash, SetHash, ActionPlanHash string
	Equal                                 bool
	Representation                        Representation
}
type PassToken struct {
	ID                    string
	CreatedGen, ExpiresAt int64
	Consumed              bool
}

func (t *PassToken) Consume() error {
	if t.ID == "" || t.Consumed {
		return errors.New("gso pass token already consumed")
	}
	t.Consumed = true
	return nil
}
func ValidateParity(results []ParityResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if !r.Equal || r.DecisionHash == "" || r.SetHash == "" || r.ActionPlanHash == "" {
			return false
		}
	}
	return true
}
