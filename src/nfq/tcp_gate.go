package nfq

import (
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
)

// shouldPassCleanSYN centralizes the invariant at the nfq/action boundary.
// Fake SNI or fragmentation alone cannot turn a plain SYN into a raw-send
// action; only an explicit SYN technique may opt into that path.
func shouldPassCleanSYN(flags byte, payloadLen int, set *config.SetConfig) bool {
	return classifier.IsCleanSYN(flags, payloadLen, needsTCPSynInjection(set))
}
