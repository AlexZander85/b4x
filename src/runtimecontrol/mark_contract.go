package runtimecontrol

import (
	"fmt"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/packetmark"
)

func validateLiveMarkContract(cfg *config.Config) error {
	if cfg == nil {
		return ErrInvalidRuntime
	}
	if uint32(cfg.Queue.Mark)&packetmark.ProcessedMask != 0 {
		return fmt.Errorf("queue mark overlaps generated-packet provenance bit")
	}
	for name, mark := range map[string]uint{
		"queue mark":              cfg.Queue.Mark,
		"discovery flow mark":     cfg.System.Checker.DiscoveryFlowMark,
		"discovery injected mark": cfg.System.Checker.DiscoveryInjectedMark,
	} {
		if uint32(mark)&packetmark.CanaryControlMask != 0 {
			return fmt.Errorf("%s overlaps reserved transactional canary control bits", name)
		}
	}
	return nil
}
