package ppe

import (
	"errors"
	"fmt"
	"strings"

	"github.com/daniellavrushin/b4/config"
)

const (
	ChainPre = "B4_PPE_PRE"
	ChainFwd = "B4_PPE_FWD"

	CommentJumpPre = "b4:ppe:v1:jump:pre"
	CommentJumpFwd = "b4:ppe:v1:jump:fwd"
	CommentTCP     = "b4:ppe:v1:tcp"
	CommentQUIC    = "b4:ppe:v1:quic"
)

var ErrFamilyRequiredUnsupported = errors.New("required PPE address family is unsupported")

type CompileInput struct {
	Config           *config.Config
	Capabilities     CapabilityReport
	ManagedSourceSet string
}

type DesiredState struct {
	Generation        string       `json:"generation"`
	Policy            string       `json:"policy"`
	SourceScope       string       `json:"source_scope"`
	ManagedSourceSet  string       `json:"managed_source_set,omitempty"`
	ConnskipPackets   int          `json:"connskip_packets"`
	EffectiveTCPPorts []uint16     `json:"effective_tcp_ports,omitempty"`
	EffectiveUDPPorts []uint16     `json:"effective_udp_ports,omitempty"`
	Families          []FamilyPlan `json:"families"`
	Warnings          []string     `json:"warnings,omitempty"`
}

type FamilyPlan struct {
	Family        string   `json:"family"`
	Binary        string   `json:"binary"`
	Enabled       bool     `json:"enabled"`
	Reason        string   `json:"reason,omitempty"`
	RestoreScript string   `json:"restore_script,omitempty"`
	Rules         []string `json:"rules,omitempty"`
}

func Compile(input CompileInput) (DesiredState, error) {
	if input.Config == nil {
		return DesiredState{}, errors.New("config is nil")
	}
	capture := input.Config.System.Classifier.Runtime.Capture
	ppeCfg := capture.PPE
	state := DesiredState{
		Policy:           capture.OffloadPolicy,
		SourceScope:      ppeCfg.SourceScope,
		ManagedSourceSet: strings.TrimSpace(input.ManagedSourceSet),
		ConnskipPackets:  ppeCfg.ConnskipPackets,
	}
	if capture.OffloadPolicy == config.OffloadPolicyDetect {
		state.Warnings = append(state.Warnings, "detect policy compiles no mutation rules")
	}
	if capture.OffloadPolicy == config.OffloadPolicyDisableGlobal {
		state.Warnings = append(state.Warnings, "disable-global is an advanced external operation; no automatic global-disable rule is compiled")
	}

	inspectionTCP, tcpAll, err := inspectionPorts(input.Config, true)
	if err != nil {
		return DesiredState{}, err
	}
	inspectionUDP, udpAll, err := inspectionPorts(input.Config, false)
	if err != nil {
		return DesiredState{}, err
	}
	state.EffectiveTCPPorts = intersectPorts(ppeCfg.TCPPorts, inspectionTCP, tcpAll)
	state.EffectiveUDPPorts = intersectPorts(ppeCfg.UDPPorts, inspectionUDP, udpAll)
	if ppeCfg.TCPEnabled && len(state.EffectiveTCPPorts) == 0 {
		state.Warnings = append(state.Warnings, "TCP PPE scope is empty after intersection with enabled inspection sets")
	}
	if ppeCfg.QUICEnabled && len(state.EffectiveUDPPorts) == 0 {
		state.Warnings = append(state.Warnings, "QUIC PPE scope is empty after intersection with enabled inspection sets")
	}

	scopeArgs := []string(nil)
	if ppeCfg.SourceScope == config.PPESourceManagedDevices {
		if state.ManagedSourceSet == "" {
			return DesiredState{}, errors.New("managed-devices PPE scope requires a pre-payload source ipset")
		}
		if !validIdentifier(state.ManagedSourceSet) {
			return DesiredState{}, fmt.Errorf("invalid managed source set %q", state.ManagedSourceSet)
		}
		scopeArgs = []string{"-m", "set", "--match-set", state.ManagedSourceSet, "src"}
	}

	families := []struct {
		name string
		mode string
		cap  FamilyCapability
	}{
		{name: "ipv4", mode: ppeCfg.IPv4, cap: input.Capabilities.IPv4},
		{name: "ipv6", mode: ppeCfg.IPv6, cap: input.Capabilities.IPv6},
	}
	for _, family := range families {
		plan, err := compileFamily(family.name, family.mode, family.cap, capture.OffloadPolicy, ppeCfg, state.EffectiveTCPPorts, state.EffectiveUDPPorts, scopeArgs)
		if err != nil {
			return DesiredState{}, err
		}
		state.Families = append(state.Families, plan)
	}

	generation, err := desiredHash(state)
	if err != nil {
		return DesiredState{}, err
	}
	state.Generation = generation
	return state, nil
}
