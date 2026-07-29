package ppe

import "errors"

func evaluateSelfTest(result CaptureVisibilityResult, requireQUIC bool) CaptureVisibilityResult {
	b := result.PhaseB
	result.OutgoingFirstPayloadSeen = b.TCPFirstPayloadSeen
	result.OutgoingSecondRangeSeen = b.TCPSecondRangeSeen
	result.OutgoingRetransSeen = b.TCPRetransmissionSeen
	result.IncomingProgressSeen = b.TCPIncomingProgressSeen
	result.TCPBidirectionalComplete = b.TCPComplete()
	result.QUICBidirectionalComplete = b.QUICComplete(requireQUIC)
	if !b.TCPClientEmitted || (requireQUIC && !b.QUICClientEmitted) {
		return failResult(result, "client_probe", VerdictINCONCLUSIVE, errors.New("probe did not confirm expected client emissions"))
	}
	bComplete := b.TCPComplete() && b.QUICComplete(requireQUIC)
	aLaterMissing := result.PhaseA.TCPFirstPayloadSeen && (!result.PhaseA.TCPSecondRangeSeen || !result.PhaseA.TCPRetransmissionSeen || !result.PhaseA.TCPIncomingProgressSeen)
	if requireQUIC {
		aLaterMissing = aLaterMissing || (result.PhaseA.QUICInitialSeen && !result.PhaseA.QUICIncomingResponseSeen)
	}
	result.OffloadSuspected = aLaterMissing && bComplete
	switch {
	case bComplete && result.OffloadSuspected:
		result.Verdict = VerdictPASS
		result.ProductionReady = true
		result.Evidence = append(result.Evidence, "controlled A/B restored complete bidirectional handshake visibility")
	case bComplete:
		result.Verdict = VerdictPASSWithLimitations
		result.Evidence = append(result.Evidence, "visibility complete but A/B did not demonstrate an offload-dependent contrast")
	case b.TCPFirstPayloadSeen:
		result.Verdict = VerdictFAIL
		result.FailureStage = "phase_b_visibility"
		result.Evidence = append(result.Evidence, "controlled endpoint was healthy and first payload was visible, but exclusion did not produce complete expected evidence")
	default:
		result.Verdict = VerdictINCONCLUSIVE
		result.FailureStage = "phase_b_capture"
		result.Evidence = append(result.Evidence, "no first payload evidence was captured for the controlled B phase")
	}
	return result
}

func failResult(result CaptureVisibilityResult, stage string, verdict SelfTestVerdict, err error) CaptureVisibilityResult {
	result.FailureStage = stage
	result.Verdict = verdict
	result.ProductionReady = false
	if err != nil {
		result.Evidence = append(result.Evidence, err.Error())
	}
	return result
}
