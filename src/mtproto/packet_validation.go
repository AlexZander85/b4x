package mtproto

type PacketPathValidation struct {
	IPv4, IPv6                         bool
	Mark                               uint32
	OriginalDestination                string
	Connections                        int
	MaxPending                         int
	ReloadSafe, ShutdownSafe, LeakFree bool
}

func (v PacketPathValidation) Valid() bool {
	return (v.IPv4 || v.IPv6) && v.Mark != 0 && v.OriginalDestination != "" && v.Connections <= 1000 && v.MaxPending > 0 && v.ReloadSafe && v.ShutdownSafe && v.LeakFree
}
