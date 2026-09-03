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
	state               CompiledProfile
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

// Begin opens a profile transaction: previous is the active profile, candidate
// the compiled next profile. The transaction's live state starts at the
// previous profile and only moves to the candidate through a successful
// Apply; Rollback restores the previous profile.
func Begin(previous, candidate CompiledProfile, generation uint64) Transaction {
	return Transaction{Previous: previous, Candidate: candidate, Preview: Diff(previous, candidate, generation), state: previous}
}

// State returns the currently active profile of the transaction: the previous
// profile until Apply commits the candidate, the candidate afterwards, and
// the previous profile again after a successful rollback.
func (t *Transaction) State() CompiledProfile {
	if t == nil {
		return CompiledProfile{}
	}
	return t.state
}

// ApplyTransaction commits the candidate profile as the active state. Unlike
// a flag flip, Apply advances the transaction's live state: State() returns
// the candidate afterwards, and the transaction is permanently committed —
// a second Apply or a rollback on a rolled-back transaction is rejected.
func (t *Transaction) Apply() error {
	if t == nil || t.Applied || t.RolledBack {
		return errors.New("invalid transaction state")
	}
	t.state = t.Candidate
	t.Applied = true
	return nil
}

// Rollback restores the previous profile. It operates on the real state: a
// rolled-back transaction exposes the previous profile and refuses any
// further mutation (recovery promotion must not be possible from a
// rolled-back transaction).
func (t *Transaction) Rollback() error {
	if t == nil || !t.Applied || t.RolledBack {
		return errors.New("rollback unavailable")
	}
	t.state = t.Previous
	t.RolledBack = true
	return nil
}
