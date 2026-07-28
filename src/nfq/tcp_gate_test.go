package nfq

import (
	"testing"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
)

func TestCleanSYNGateIgnoresFutureTLSStrategies(t *testing.T) {
	set := &config.SetConfig{}
	set.Faking.SNI = true
	set.Fragmentation.Strategy = config.ConfigNone
	if !shouldPassCleanSYN(classifier.TCPFlagSYN, 0, set) {
		t.Fatal("fake-SNI set routed clean SYN to action path")
	}
}

func TestCleanSYNGateAllowsExplicitSYNTechniques(t *testing.T) {
	for name, set := range map[string]*config.SetConfig{
		"synfake": {TCP: config.TCPConfig{SynFake: true}},
		"tcpmd5":  {TCP: config.TCPConfig{}, Fragmentation: config.FragmentationConfig{Strategy: "tcp"}, Faking: config.FakingConfig{TCPMD5: true}},
	} {
		t.Run(name, func(t *testing.T) {
			if shouldPassCleanSYN(classifier.TCPFlagSYN, 0, set) {
				t.Fatal("explicit SYN technique was incorrectly passed as clean")
			}
		})
	}
}

func TestCleanSYNGateRejectsTFOAndHandshakeFlags(t *testing.T) {
	set := &config.SetConfig{}
	for name, tc := range map[string]struct {
		flags   byte
		payload int
	}{
		"tfo":     {flags: classifier.TCPFlagSYN, payload: 1},
		"syn-ack": {flags: classifier.TCPFlagSYN | classifier.TCPFlagACK},
		"syn-fin": {flags: classifier.TCPFlagSYN | classifier.TCPFlagFIN},
		"syn-rst": {flags: classifier.TCPFlagSYN | classifier.TCPFlagRST},
	} {
		t.Run(name, func(t *testing.T) {
			if shouldPassCleanSYN(tc.flags, tc.payload, set) {
				t.Fatalf("flags=%#x payload=%d was incorrectly passed", tc.flags, tc.payload)
			}
		})
	}
}
