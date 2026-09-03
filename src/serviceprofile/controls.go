package serviceprofile

var YouTubeControlScenarioIDs = []string{"gmail-inbox", "gmail-message-body", "gmail-inline-images", "gmail-attachment", "google-feed-load", "google-feed-refresh", "google-article-open", "google-feed-images", "concurrent-youtube-controls"}

type ControlScenario struct {
	ID, ExpectedOutcome string
	Target              bool
}

func ControlScenarios() []ControlScenario {
	out := make([]ControlScenario, len(YouTubeControlScenarioIDs))
	for i, id := range YouTubeControlScenarioIDs {
		out[i] = ControlScenario{ID: id, ExpectedOutcome: "healthy", Target: false}
	}
	return out
}
