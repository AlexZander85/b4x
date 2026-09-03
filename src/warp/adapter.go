package warp

import "errors"

type AdapterBudget struct {
	MaxPackets, MaxBytes int
	MaxDurationMS        int
}
type TransportCamouflageAdapter struct {
	Budget      AdapterBudget
	Authorized  bool
	Established bool
}

func (a TransportCamouflageAdapter) Valid() bool {
	return a.Authorized && !a.Established && a.Budget.MaxPackets > 0 && a.Budget.MaxBytes > 0 && a.Budget.MaxDurationMS > 0
}
func (a TransportCamouflageAdapter) Apply(packetCount, bytes int) error {
	if !a.Valid() {
		return errors.New("camouflage adapter unavailable")
	}
	if packetCount > a.Budget.MaxPackets || bytes > a.Budget.MaxBytes {
		return errors.New("camouflage budget exceeded")
	}
	return nil
}
func (a *TransportCamouflageAdapter) Cutoff() {
	if a != nil {
		a.Established = true
	}
}
