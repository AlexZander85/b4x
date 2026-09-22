package nfq

import (
	"net"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/action"
)

// SynthesisPlanCompiler compiles a concrete ActionPlan for a real packet from a
// synthesized AFS candidate. It is injected by the Discovery owner through
// ArmSynthesisOverride so this packet package never imports the synthesis
// engine (which already imports nfq), and so the candidate is compiled against
// the actual payload/sequence rather than a template.
type SynthesisPlanCompiler func(input action.PlanInput) (action.ActionPlan, error)

type synthesisOverride struct {
	compiler  SynthesisPlanCompiler
	expiresAt time.Time
}

var (
	synthesisOverrideMu sync.RWMutex
	synthesisOverrides  = map[string]synthesisOverride{}
)

// ArmSynthesisOverride binds a synthesized candidate's compiler to one probe
// destination for a bounded window. It returns a release func that removes the
// override; release is idempotent and safe to call from any goroutine.
//
// The override only affects flows whose destination IP matches dst. The packet
// path always falls back to the configured plan when the override is absent,
// expired, or fails to compile, so arming it can never break normal traffic.
func ArmSynthesisOverride(dst net.IP, compiler SynthesisPlanCompiler, ttl time.Duration) func() {
	if dst == nil || compiler == nil || ttl <= 0 {
		return func() {}
	}
	key := dst.String()
	synthesisOverrideMu.Lock()
	synthesisOverrides[key] = synthesisOverride{compiler: compiler, expiresAt: time.Now().Add(ttl)}
	synthesisOverrideMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			synthesisOverrideMu.Lock()
			delete(synthesisOverrides, key)
			synthesisOverrideMu.Unlock()
		})
	}
}

// activeSynthesisCompiler returns the armed compiler for dst, if any is live.
func activeSynthesisCompiler(dst net.IP, now time.Time) (SynthesisPlanCompiler, bool) {
	if dst == nil {
		return nil, false
	}
	key := dst.String()
	synthesisOverrideMu.RLock()
	override, ok := synthesisOverrides[key]
	synthesisOverrideMu.RUnlock()
	if !ok || now.After(override.expiresAt) {
		return nil, false
	}
	return override.compiler, true
}

// clearSynthesisOverrides drops every armed override. It exists for tests and
// for a hard reset after a synthesis run is cancelled.
func clearSynthesisOverrides() {
	synthesisOverrideMu.Lock()
	synthesisOverrides = map[string]synthesisOverride{}
	synthesisOverrideMu.Unlock()
}
