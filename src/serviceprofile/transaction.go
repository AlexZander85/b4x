package serviceprofile

import "errors"

type ChangeKind string

const (
	Create ChangeKind = "create"
	Update ChangeKind = "update"
	Remove ChangeKind = "remove"
)

type Change struct {
	Kind          ChangeKind
	Before, After *OrdinarySet
}
type Preview struct {
	BaseGeneration, CandidateGeneration uint64
	Changes                             []Change
}
type Transaction struct {
	Previous, Candidate CompiledProfile
	Preview             Preview
	Applied, RolledBack bool
}

func Diff(previous, candidate CompiledProfile, generation uint64) Preview {
	old := map[string]OrdinarySet{}
	for _, s := range previous.Sets {
		old[s.ID] = s
	}
	next := map[string]OrdinarySet{}
	for _, s := range candidate.Sets {
		next[s.ID] = s
	}
	var changes []Change
	for id, s := range next {
		if p, ok := old[id]; !ok {
			x := s
			changes = append(changes, Change{Kind: Create, After: &x})
		} else if p != s {
			x, y := p, s
			changes = append(changes, Change{Kind: Update, Before: &x, After: &y})
		}
	}
	for id, s := range old {
		if _, ok := next[id]; !ok && s.Ownership == Managed {
			x := s
			changes = append(changes, Change{Kind: Remove, Before: &x})
		}
	}
	return Preview{BaseGeneration: generation, CandidateGeneration: generation + 1, Changes: changes}
}
func Begin(previous, candidate CompiledProfile, generation uint64) Transaction {
	return Transaction{Previous: previous, Candidate: candidate, Preview: Diff(previous, candidate, generation)}
}
func (t *Transaction) Apply() error {
	if t == nil || t.Applied || t.RolledBack {
		return errors.New("invalid transaction state")
	}
	t.Applied = true
	return nil
}
func (t *Transaction) Rollback() error {
	if t == nil || !t.Applied || t.RolledBack {
		return errors.New("rollback unavailable")
	}
	t.RolledBack = true
	return nil
}
