package providers

import (
	"fmt"
	"strings"

	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// completeProbeEvidence records a structurally valid DNS response without
// claiming PASS_CORRECT. Correctness is a differential detector decision:
// providers can prove transport/message validity, but cannot prove that an
// on-path NXDOMAIN or answer substitution is truthful by themselves.
func completeProbeEvidence(out *dnspath.DNSPathProbeOutcome, payload []byte, q dnspath.DNSProbeQuery, obs b4dns.DNSObservation, fp dnspath.ResponseFingerprint) {
	out.Stage = dnspath.StageAnswer
	out.RCode = obs.RCode
	out.Truncated = obs.Truncated
	out.AnswerFingerprint = fp.AnswerDigest
	out.CNAMEFingerprint = fp.CNAMEDigest
	out.HTTPSFingerprint = fp.HTTPSDigest

	meta, err := b4dns.InspectResponseMetadata(payload)
	if err != nil {
		out.Class = dnspath.OutcomeMalformedDNS
		out.Stage = dnspath.StageDNSMessage
		out.FailureCode = "response_metadata_invalid"
		return
	}
	if meta.AuthenticatedData {
		out.DNSSECState = "ad"
	}
	if meta.HasNegativeProof() {
		out.EvidenceRefs = append(out.EvidenceRefs, "authority-soa")
	}
	if meta.Truncated {
		out.Class = dnspath.OutcomeTruncatedRequiresTCP
		return
	}

	caseID := strings.ToUpper(q.SuiteCase)
	switch caseID {
	case "A", "AAAA", "CONTROL_SAME", "CONTROL_UNRELATED":
		if meta.RCode != 0 {
			out.Class = dnspath.OutcomeRCodeMismatch
			out.FailureCode = "expected_positive_rcode"
			return
		}
		if fp.AnswerDigest == "" && fp.CNAMEDigest == "" {
			out.Class = dnspath.OutcomeAnswerConflict
			out.FailureCode = "expected_address_answer_missing"
			return
		}
	case "CNAME":
		if meta.RCode != 0 {
			out.Class = dnspath.OutcomeRCodeMismatch
			out.FailureCode = "expected_positive_rcode"
			return
		}
		if fp.CNAMEDigest == "" {
			out.Class = dnspath.OutcomeAnswerConflict
			out.FailureCode = "expected_cname_answer_missing"
			return
		}
	case "HTTPS":
		if meta.RCode != 0 {
			out.Class = dnspath.OutcomeRCodeMismatch
			out.FailureCode = "expected_positive_rcode"
			return
		}
		if fp.HTTPSDigest == "" {
			out.Class = dnspath.OutcomeAnswerConflict
			out.FailureCode = "expected_https_answer_missing"
			return
		}
	case "NXDOMAIN":
		if meta.RCode != 3 {
			out.Class = dnspath.OutcomeRCodeMismatch
			out.FailureCode = "expected_nxdomain"
			return
		}
		if !meta.HasNegativeProof() {
			out.Class = dnspath.OutcomeAnswerConflict
			out.FailureCode = "negative_without_authority_soa"
			return
		}
	}

	// This response is only a candidate correctness observation. The detector
	// must compare attempts, controls and independent paths before promoting it
	// to PASS_CORRECT/PASS_DIFFERENT_BUT_VALID.
	out.Class = dnspath.OutcomeInconclusive
}

// validateProductionResponse is the last provider-side guard before a DNS
// payload can reach the runtime manager/client. SERVFAIL/REFUSED are failures
// (so the manager can use a validated fallback); NXDOMAIN and NODATA require
// an authority SOA, preventing bare forged negative replies from becoming a
// normal production answer or cache entry.
func validateProductionResponse(payload []byte, obs b4dns.DNSObservation) error {
	meta, err := b4dns.InspectResponseMetadata(payload)
	if err != nil {
		return err
	}
	if meta.Truncated {
		return fmt.Errorf("truncated DNS response requires fallback")
	}
	switch meta.RCode {
	case 0:
		// A zero-answer NOERROR response is NODATA unless it carries CNAME or
		// HTTPS/SVCB answer evidence. RFC 2308 negative caching requires SOA.
		if meta.AnswerCount == 0 && len(obs.CNAMEs) == 0 && len(obs.HTTPSRecords) == 0 && !meta.HasNegativeProof() {
			return fmt.Errorf("NODATA response lacks authority SOA")
		}
	case 3:
		if !meta.HasNegativeProof() {
			return fmt.Errorf("NXDOMAIN response lacks authority SOA")
		}
	default:
		return fmt.Errorf("DNS rcode %d requires fallback", meta.RCode)
	}
	return nil
}
