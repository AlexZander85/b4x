package ppe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type CommandProbeExecutor struct {
	Runner Runner
	Binary string
}

func (e CommandProbeExecutor) Run(ctx context.Context, request ProbeRequest) (ProbeOutcome, error) {
	runner := e.Runner
	if runner == nil {
		runner = OSRunner{}
	}
	binary := strings.TrimSpace(e.Binary)
	if binary == "" {
		binary = "b4-ppe-probe"
	}
	output, err := runner.Run(ctx, binary,
		"--protocol", request.Protocol,
		"--family", request.Family,
		"--source-port", fmt.Sprintf("%d", request.SourcePort),
		"--flow-id", request.FlowID,
		"--phase", string(request.Phase),
		"--endpoint", request.ControlledEndpoint,
		"--timeout-ms", fmt.Sprintf("%d", request.Timeout.Milliseconds()),
	)
	if err != nil {
		return ProbeOutcome{}, err
	}
	var envelope struct {
		Protocol      string `json:"protocol"`
		ClientEmitted bool   `json:"client_emitted"`
		Detail        string `json:"detail,omitempty"`
	}
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		return ProbeOutcome{}, fmt.Errorf("decode probe result: %w", err)
	}
	if envelope.Protocol != SelfTestProtocol {
		return ProbeOutcome{}, errors.New("probe did not return b4-ppe-self-test/v1 protocol")
	}
	return ProbeOutcome{Protocol: request.Protocol, ClientEmitted: envelope.ClientEmitted, Detail: envelope.Detail}, nil
}
