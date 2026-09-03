package validation

var CoreStages = []string{"stage-1", "stage-2", "stage-3", "stage-4", "stage-5", "stage-6", "stage-7", "stage-8", "stage-9", "stage-10", "stage-11", "stage-12", "stage-13", "stage-14", "stage-15", "stage-16", "stage-17", "stage-18", "stage-19", "stage-20", "stage-21", "stage-22", "stage-23", "stage-24", "stage-25", "stage-26", "stage-27", "stage-28", "stage-29", "stage-30", "stage-31", "stage-32", "stage-33", "stage-34", "stage-35", "stage-36"}

type SuiteLevel string

const (
	L0 SuiteLevel = "L0"
	L1 SuiteLevel = "L1"
	L2 SuiteLevel = "L2"
	L3 SuiteLevel = "L3"
	L4 SuiteLevel = "L4"
	L5 SuiteLevel = "L5"
	L6 SuiteLevel = "L6"
	L7 SuiteLevel = "L7"
	L8 SuiteLevel = "L8"
)

type SuiteSpec struct {
	ID, Stage         string
	Levels            []SuiteLevel
	RequiredArtifacts []string
	Deterministic     bool
	E2E               bool
}
type Matrix struct{ Suites []SuiteSpec }

func (m Matrix) HasStage(stage string) bool {
	for _, s := range m.Suites {
		if s.Stage == stage {
			return true
		}
	}
	return false
}
func (m Matrix) Valid() bool {
	for _, s := range m.Suites {
		if s.ID == "" || s.Stage == "" || len(s.Levels) == 0 || len(s.RequiredArtifacts) == 0 {
			return false
		}
	}
	return len(m.Suites) > 0
}
