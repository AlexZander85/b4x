package classifier

import "testing"

func TestResolveCandidateDisposition(t *testing.T) {
	candidate := CaptureCandidate{CandidateSetID: "youtube"}
	cases := []struct {
		name string
		ids  []string
		want CandidateDisposition
	}{
		{"same set", []string{"youtube"}, CandidateEligible},
		{"gmail contradiction", []string{"gmail"}, CandidateContradicted},
		{"no hostname set", nil, CandidateContradicted},
		{"overlap", []string{"youtube", "other"}, CandidateAmbiguous},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveCandidateDisposition(candidate, tc.ids); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
