package fieldtest

type TelegramFixture string

const (
	ZeroBeforeSoft   TelegramFixture = "zero-before-soft"
	ZeroUntilHard    TelegramFixture = "zero-until-hard"
	DelayedPrefix    TelegramFixture = "delayed-prefix"
	ValidHeader64    TelegramFixture = "valid-header-64"
	ReservedPrefix   TelegramFixture = "reserved-prefix"
	PrimaryWSFailure TelegramFixture = "primary-ws-failure"
	Overflow         TelegramFixture = "pending-overflow"
	ShutdownPending  TelegramFixture = "shutdown-pending"
)

type TelegramBridgeResult struct {
	Fixture                                                                                                                                                          TelegramFixture
	SoftTimeoutHandled, HardTimeoutHandled, BytesForwardedExactlyOnce, LimitsEnforced, RecursionGuard, OriginalDestinationPreserved, CleanupClosed, AndroidValidated bool
	ReadBytes, ForwardedBytes                                                                                                                                        uint64
}

func (r TelegramBridgeResult) Valid() bool {
	return !r.SoftTimeoutHandled && r.BytesForwardedExactlyOnce && r.LimitsEnforced && r.RecursionGuard && r.OriginalDestinationPreserved && r.CleanupClosed && r.ForwardedBytes == r.ReadBytes
}

type TelegramRelease struct {
	Results                               []TelegramBridgeResult
	DirectProxySeparated, ProductionScope bool
}

func (r TelegramRelease) Ready() bool {
	if !r.DirectProxySeparated || !r.ProductionScope || len(r.Results) == 0 {
		return false
	}
	for _, x := range r.Results {
		if !x.Valid() {
			return false
		}
	}
	return true
}
