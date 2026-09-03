package tables

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
)

const (
	canaryChainIPT        = "B4_CANARY"
	canaryChainNFT        = "b4_canary"
	canaryNFTJumpMarker   = "b4-canary-jump"
	canaryNFTBypassMarker = "b4-canary-main-bypass"
)

type CanarySteeringSpec struct {
	ClientGroup  string
	Protocol     string
	Percent      uint8
	FlowMark     uint
	DirectMark   uint
	InjectedMark uint
	QueueStart   int
	QueueThreads int
}

type canaryScope struct {
	all bool
	ip  netip.Addr
	mac string
}

func (s CanarySteeringSpec) Validate() error {
	if s.Protocol != "tcp" && s.Protocol != "udp" {
		return fmt.Errorf("canary protocol must be tcp or udp")
	}
	if s.Percent == 0 || s.Percent > 100 {
		return fmt.Errorf("canary percentage must be 1..100")
	}
	if s.FlowMark == 0 || s.DirectMark == 0 || s.InjectedMark == 0 ||
		s.FlowMark == s.DirectMark || s.FlowMark == s.InjectedMark || s.DirectMark == s.InjectedMark {
		return fmt.Errorf("canary marks must be distinct and non-zero")
	}
	control := uint(capture.CanaryControlMarkMask)
	if s.FlowMark&control != s.FlowMark || s.DirectMark&control != s.DirectMark ||
		uint32(s.InjectedMark)&capture.ProcessedMarkMask == 0 {
		return fmt.Errorf("canary marks do not satisfy the reserved mark contract")
	}
	if s.QueueStart < 0 || s.QueueThreads < 1 || s.QueueStart+s.QueueThreads-1 > 65535 {
		return fmt.Errorf("canary queue range is invalid")
	}
	_, err := parseCanaryScope(s.ClientGroup)
	return err
}

func ApplyCanarySteeringRules(cfg *config.Config, spec CanarySteeringSpec) (err error) {
	if cfg == nil {
		return fmt.Errorf("canary config is nil")
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	scope, _ := parseCanaryScope(spec.ClientGroup)
	backend := detectFirewallBackend(cfg)
	defer func() {
		if err != nil {
			ClearCanarySteeringRules(cfg, spec)
		}
	}()
	if backend == backendNFTables && hasBinary("nft") {
		return applyCanaryNFT(scope, spec)
	}
	legacy := backend == backendIPTablesLegacy
	if hasBinary(canaryIPTBinary(false, legacy)) || hasBinary(canaryIPTBinary(true, legacy)) {
		return applyCanaryIPT(scope, spec, legacy)
	}
	if hasBinary("nft") {
		return applyCanaryNFT(scope, spec)
	}
	return fmt.Errorf("no canary firewall backend available")
}

func ClearCanarySteeringRules(cfg *config.Config, spec CanarySteeringSpec) {
	if cfg == nil {
		return
	}
	backend := detectFirewallBackend(cfg)
	if backend == backendNFTables && hasBinary("nft") {
		clearCanaryNFT(spec)
		return
	}
	legacy := backend == backendIPTablesLegacy
	if hasBinary(canaryIPTBinary(false, legacy)) || hasBinary(canaryIPTBinary(true, legacy)) {
		clearCanaryIPT(spec, legacy)
		return
	}
	if hasBinary("nft") {
		clearCanaryNFT(spec)
	}
}

func parseCanaryScope(value string) (canaryScope, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "ip:") {
		addr, err := netip.ParseAddr(strings.TrimSpace(strings.TrimPrefix(value, "ip:")))
		if err != nil || !addr.IsValid() || addr.IsUnspecified() {
			return canaryScope{}, fmt.Errorf("invalid canary client IP")
		}
		return canaryScope{ip: addr.Unmap()}, nil
	}
	if strings.HasPrefix(value, "mac:") {
		hw, err := net.ParseMAC(strings.TrimSpace(strings.TrimPrefix(value, "mac:")))
		if err != nil || len(hw) != 6 {
			return canaryScope{}, fmt.Errorf("invalid canary client MAC")
		}
		return canaryScope{mac: strings.ToLower(hw.String())}, nil
	}
	return canaryScope{}, fmt.Errorf("client_group must be ip:<address> or mac:<address>")
}
