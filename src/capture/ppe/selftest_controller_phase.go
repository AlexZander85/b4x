package ppe

import (
	"context"
	"fmt"
)

func (c *SelfTestController) runPhase(ctx context.Context, request SelfTestRequest, phase SelfTestPhase) (PhaseEvidence, error) {
	collector := newEvidenceCollector(phase, request.Family, request.TCPFlowID, request.QUICFlowID, request.TCPSourcePort, request.QUICSourcePort)
	unsubscribe := c.bus.Subscribe(collector)
	defer unsubscribe()
	tcpOutcome, err := c.probe.Run(ctx, ProbeRequest{RunID: request.RunID, Phase: phase, Protocol: "tcp", Family: request.Family, FlowID: request.TCPFlowID, SourcePort: request.TCPSourcePort, ControlledEndpoint: request.ControlledEndpoint, Timeout: request.Timeout})
	if err != nil {
		return PhaseEvidence{}, fmt.Errorf("TCP probe: %w", err)
	}
	evidence := collector.Snapshot()
	evidence.TCPClientEmitted = tcpOutcome.ClientEmitted
	if request.RequireQUIC {
		quicOutcome, err := c.probe.Run(ctx, ProbeRequest{RunID: request.RunID, Phase: phase, Protocol: "quic", Family: request.Family, FlowID: request.QUICFlowID, SourcePort: request.QUICSourcePort, ControlledEndpoint: request.ControlledEndpoint, Timeout: request.Timeout})
		if err != nil {
			return PhaseEvidence{}, fmt.Errorf("QUIC probe: %w", err)
		}
		evidence = collector.Snapshot()
		evidence.TCPClientEmitted = tcpOutcome.ClientEmitted
		evidence.QUICClientEmitted = quicOutcome.ClientEmitted
	}
	return evidence, nil
}
