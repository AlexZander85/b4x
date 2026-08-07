package tables

import (
	"fmt"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
)

// captureRuleParams is the backend-neutral description of the capture contour
// that both the iptables and the nftables engine must install.
//
// FB-11: when System.Classifier.Flags.CaptureEnvelopeEnabled is false these
// values reproduce the legacy cfg.Queue-derived contour exactly (first-N
// limits, unconditional SYN-ACK/FIN/RST and UDP/QUIC rules, hard-coded
// processed mark). When the flag is true the values come from the
// capture.CaptureEnvelope contract built on Classifier.Runtime.Capture, so
// operators can tune the contour without touching cfg.Queue.
type captureRuleParams struct {
	outgoingLimit uint32 // packets [0, outgoingLimit) for original-direction TCP
	incomingLimit uint32 // packets [0, incomingLimit) for reply-direction TCP
	udpLimit      uint32 // packets [0, udpLimit) for original-direction UDP

	alwaysSynAck bool
	alwaysFin    bool
	alwaysRst    bool
	alwaysQuic   bool

	processedMark uint32
	processedMask uint32
}

// captureRuleParamsFor derives the capture contour parameters from the active
// configuration. It never mutates the configuration.
//
// Legacy mode (flag disabled) mirrors the old hard-coded defaults:
//   - TCP first-N range equals cfg.Queue.TCPConnBytesLimit packets (envelope
//     semantics are one-based inclusive, kernel packets range is 0-based);
//   - all lifecycle rules (SYN-ACK, FIN, RST, QUIC/UDP) are unconditional;
//   - processed mark/mask are the hard-coded capture.ProcessedMarkBit/Mask.
func captureRuleParamsFor(cfg *config.Config) (captureRuleParams, error) {
	udpLimit, err := boundedPacketLimitValue(cfg.Queue.UDPConnBytesLimit)
	if err != nil {
		return captureRuleParams{}, fmt.Errorf("capture contour: udp first-n: %w", err)
	}

	if !cfg.System.Classifier.Flags.CaptureEnvelopeEnabled {
		tcpLimit, err := boundedPacketLimitValue(cfg.Queue.TCPConnBytesLimit)
		if err != nil {
			return captureRuleParams{}, fmt.Errorf("capture contour: tcp first-n: %w", err)
		}
		return captureRuleParams{
			outgoingLimit: tcpLimit,
			incomingLimit: tcpLimit,
			udpLimit:      udpLimit,
			alwaysSynAck:  true,
			alwaysFin:     true,
			alwaysRst:     true,
			alwaysQuic:    true,
			processedMark: capture.ProcessedMarkBit,
			processedMask: capture.ProcessedMarkMask,
		}, nil
	}

	env, err := capture.NewCaptureEnvelope(cfg, capture.QueueRoleProduction)
	if err != nil {
		return captureRuleParams{}, err
	}
	return captureRuleParams{
		outgoingLimit: env.OutgoingPacketLimit,
		incomingLimit: env.IncomingPacketLimit,
		udpLimit:      udpLimit, // envelope has no separate UDP bound; keep queue default
		alwaysSynAck:  env.AlwaysQueueSynAck,
		alwaysFin:     env.AlwaysQueueFin,
		alwaysRst:     env.AlwaysQueueRst,
		alwaysQuic:    env.AlwaysQueueQuicInit,
		processedMark: env.ProcessedMark,
		processedMask: env.ProcessedMarkMask,
	}, nil
}

// boundedPacketLimitValue mirrors capture.boundedPacketLimit: a conn-bytes
// value of N captures packets 0..N, i.e. N+1 packets.
func boundedPacketLimitValue(value int) (uint32, error) {
	if value < 0 || uint64(value)+1 > uint64(capture.MaxCapturePacketLimit) {
		return 0, fmt.Errorf("value %d must produce a packet limit in [1,%d]", value, capture.MaxCapturePacketLimit)
	}
	return uint32(value + 1), nil
}
