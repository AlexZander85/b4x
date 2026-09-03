package ppe

import "time"

type CapabilityState string

const (
	CapabilityUnknown     CapabilityState = "unknown"
	CapabilityUnsupported CapabilityState = "unsupported"
	CapabilityPartial     CapabilityState = "partial"
	CapabilitySupported   CapabilityState = "supported"
	CapabilityBroken      CapabilityState = "broken"
)

type PlatformMetadata struct {
	Platform  string `json:"platform"`
	SocFamily string `json:"soc_family,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
	Arch      string `json:"arch,omitempty"`
	NDM       bool   `json:"ndm"`
}

type FamilyCapability struct {
	Family           string          `json:"family"`
	Binary           string          `json:"binary,omitempty"`
	TargetRegistered bool            `json:"target_registered"`
	ConnskipUsable   bool            `json:"connskip_usable"`
	MangleAvailable  bool            `json:"mangle_available"`
	Prerouting       bool            `json:"prerouting_available"`
	Forward          bool            `json:"forward_available"`
	WaitSupported    bool            `json:"wait_supported"`
	PermissionDenied bool            `json:"permission_denied"`
	State            CapabilityState `json:"state"`
	Reasons          []string        `json:"reasons,omitempty"`
}

type CapabilityReport struct {
	CheckedAt          time.Time         `json:"checked_at"`
	Platform           PlatformMetadata  `json:"platform"`
	IPv4               FamilyCapability  `json:"ipv4"`
	IPv6               FamilyCapability  `json:"ipv6"`
	State              CapabilityState   `json:"state"`
	Supported          bool              `json:"supported"`
	FunctionalProbeRun bool              `json:"functional_probe_run"`
	Evidence           map[string]string `json:"evidence,omitempty"`
	Warnings           []string          `json:"warnings,omitempty"`
}
