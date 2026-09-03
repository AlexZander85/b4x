package sock

import (
	"crypto/rand"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

func cloneBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func GetPayload(faking *config.FakingConfig) []byte {
	switch faking.SNIType {
	case config.FakePayloadRandom:
		p := make([]byte, 1200)
		if _, err := rand.Read(p); err != nil {
			log.Warnf("crypto/rand read failed: %v", err)
		}
		return p
	case config.FakePayloadZero:
		return make([]byte, 1200)
	}

	if len(faking.PayloadData) > 0 {
		out := cloneBytes(faking.PayloadData)
		log.Tracef("Using fake SNI payload of %d bytes", len(out))
		return out
	}

	switch faking.SNIType {
	case config.FakePayloadDefault2:
		return cloneBytes(config.FakeSNI2)
	case config.FakePayloadCustom:
		return []byte(faking.CustomPayload)
	}
	return cloneBytes(config.FakeSNI1)
}
