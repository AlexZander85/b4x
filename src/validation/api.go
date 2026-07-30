package validation

import "errors"

type APIRequest struct {
	Method, Path, IdempotencyKey, Client, RequestID, Token string
	DryRun                                                 bool
}

func (r APIRequest) Valid() bool {
	return r.Method != "" && r.Path != "" && r.IdempotencyKey != "" && r.Client != "" && r.RequestID != ""
}

type ValidationPlan struct {
	RunID, Profile   string
	Stages           []string
	DryRun           bool
	PromotionAllowed bool
}
type ValidationEvent struct {
	RunID, Stage, Type string
	Sequence           uint64
	Verdict            Verdict
	AtUnixNS           int64
}
type APIResponse struct {
	Schema  uint16
	Status  string
	RunID   string
	Verdict Verdict
	Error   string
}

func ValidatePlan(p ValidationPlan) error {
	if p.RunID == "" || p.Profile == "" || len(p.Stages) == 0 {
		return errors.New("validation plan requires run and stages")
	}
	if p.Profile == "full-b4x" && !p.PromotionAllowed {
		return nil
	}
	return nil
}
