package action

import "testing"

func TestActionPlanDeclaresNormalTCPRepresentation(t *testing.T) {
	payload := []byte("0123456789")
	plan, err := Plan(PlanInput{BaseSequence: 1, Payload: payload, MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1})
	if err != nil || !plan.Valid {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if plan.Representation != RepresentationNormalTCP {
		t.Fatalf("existing packet technique representation=%v", plan.Representation)
	}
}
