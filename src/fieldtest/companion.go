package fieldtest

type CompanionEvent struct {
	Marker           Marker
	Authenticated    bool
	ContentCollected bool
}
type CompanionPolicy struct {
	Enabled        bool
	LocalOnly      bool
	AllowedMarkers []string
}

func (p CompanionPolicy) Valid() bool {
	return !p.Enabled || (p.LocalOnly && !contains(p.AllowedMarkers, "screen_content"))
}
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
