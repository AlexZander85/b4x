package config

import "reflect"

type classifierRuntimeValidation struct {
	c *Config
	r *ClassifierRuntimeConfig
	d ClassifierRuntimeConfig
	v *validator
}

func (c *Config) validateClassifierRuntimeConfig(v *validator) {
	r := &c.System.Classifier.Runtime
	d := DefaultClassifierRuntimeConfig
	if reflect.DeepEqual(*r, ClassifierRuntimeConfig{}) {
		*r = d
	}
	if r.ClientIdentity == (ClientIdentityRuntimeConfig{}) {
		r.ClientIdentity = d.ClientIdentity
	}
	if r.Confidence == (ConfidenceRuntimeConfig{}) {
		r.Confidence = d.Confidence
	}
	if r.Hints == (HintStoreRuntimeConfig{}) {
		r.Hints = d.Hints
	}
	if reflect.DeepEqual(r.Capture, CaptureRuntimeConfig{}) {
		r.Capture = d.Capture
	}
	if r.Reassembly == (ReassemblyRuntimeConfig{}) {
		r.Reassembly = d.Reassembly
	}
	if r.HoldReplay == (HoldReplayRuntimeConfig{}) {
		r.HoldReplay = d.HoldReplay
	}
	if r.PassiveRST == (PassiveRSTRuntimeConfig{}) {
		r.PassiveRST = d.PassiveRST
	}
	if r.Actions == (ActionBudgetRuntimeConfig{}) {
		r.Actions = d.Actions
	}
	if r.Discovery == (DiscoveryRuntimeConfig{}) {
		r.Discovery = d.Discovery
	}
	if r.FailureInbox == (FailureInboxRuntimeConfig{}) {
		r.FailureInbox = d.FailureInbox
	}
	if r.ClientHelloLab == (ClientHelloLabRuntimeConfig{}) {
		r.ClientHelloLab = d.ClientHelloLab
	}
	if r.Rollout == (RolloutRuntimeConfig{}) {
		r.Rollout = d.Rollout
	}
	if r.Fallback == (FallbackRuntimeConfig{}) {
		r.Fallback = d.Fallback
	}
	if r.Privacy == (PrivacyRuntimeConfig{}) {
		r.Privacy = d.Privacy
	}
	s := classifierRuntimeValidation{c: c, r: r, d: d, v: v}
	s.validateIdentityHintsCapture()
	s.validateFlowControls()
	s.validateDiscoveryLabRollout()
	s.validateFallbackPrivacyStrategies()
}

func (s classifierRuntimeValidation) defaultInt(value *int, fallback int) {
	if *value <= 0 {
		*value = fallback
	}
}
func (s classifierRuntimeValidation) defaultU32(value *uint32, fallback uint32) {
	if *value == 0 {
		*value = fallback
	}
}
func (s classifierRuntimeValidation) defaultU64(value *uint64, fallback uint64) {
	if *value == 0 {
		*value = fallback
	}
}
func (s classifierRuntimeValidation) defaultU8(value *uint8, fallback uint8) {
	if *value == 0 {
		*value = fallback
	}
}
func (s classifierRuntimeValidation) outOfRange(path string, value, min, max int) {
	if value < min || value > max {
		s.v.addf(path, "out_of_range", map[string]any{"min": min, "max": max}, "value %d must be in [%d,%d]", value, min, max)
	}
}
