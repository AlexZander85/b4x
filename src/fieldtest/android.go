package fieldtest

import "errors"

type AndroidDriver interface {
	ForceStop(packageName string) error
	Launch(packageName, deepLink string) error
	Background() error
	Foreground() error
	Diagnostics() (map[string]string, error)
}
type AndroidAction struct {
	Package, DeepLink      string
	Background, Foreground bool
}
type AndroidRun struct {
	Serial, Package, Variant                  string
	Started, UIVisible, FirstFrame, Buffering bool
	Markers                                   []Marker
	Inferred                                  bool
}

func ValidateAndroidRun(r AndroidRun) error {
	if r.Serial == "" || r.Package == "" {
		return errors.New("android run requires serial and package")
	}
	if r.Inferred && r.FirstFrame {
		return errors.New("inferred first-frame cannot be authoritative")
	}
	return nil
}
func (r *AndroidRun) AddMarker(m Marker) {
	r.Markers = append(r.Markers, m)
	switch m.Marker {
	case "ui_visible":
		r.UIVisible = true
	case "first_frame":
		r.FirstFrame = true
	case "buffering_start":
		r.Buffering = true
	case "buffering_end":
		r.Buffering = false
	}
}
