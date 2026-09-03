// Logger bridge: amneziawg-go device.Logger has two Printf-style fields and
// nil means silent (upstream logger.go:14-20). The engine supplies a LogSink;
// nil sink keeps the device fully quiet (the warp package convention: errors
// are structural, logging is the caller's concern).
package transportwg

import "github.com/amnezia-vpn/amneziawg-go/v3/device"

// LogSink receives device diagnostics.
type LogSink interface {
	Verbosef(format string, args ...any)
	Errorf(format string, args ...any)
}

// DeviceLogger adapts sink to *device.Logger. A nil sink yields explicit
// DiscardLogf functions: upstream code paths call log.Verbosef without a nil
// check (uapi.go:313) despite the "nil = silent" doc comment, so a zero-value
// Logger would panic on the first verbose line.
func DeviceLogger(sink LogSink) *device.Logger {
	l := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	if sink != nil {
		l.Verbosef = sink.Verbosef
		l.Errorf = sink.Errorf
	}
	return l
}
