package detector

import (
	"testing"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

func testOutcome(id dnspath.DNSPathID, caseID, answer string, class dnspath.OutcomeClass) dnspath.DNSPathProbeOutcome {
	return dnspath.DNSPathProbeOutcome{
		PathID: id, QuerySuiteID: caseID, Class: class,
		AnswerFingerprint: answer, ResponseCount: 1,
	}
}

func TestControlSameRequiresFullAnswerAgreement(t *testing.T) {
	a := dnspath.DNSPathID{Family: dnspath.DNSPathTCP, ResolverID: "r-a", EndpointID: "e-a", IPFamily: "ipv4"}
	b := dnspath.DNSPathID{Family: dnspath.DNSPathDoH, ResolverID: "r-b", EndpointID: "e-b", IPFamily: "ipv4"}
	outcomes := []dnspath.DNSPathProbeOutcome{
		testOutcome(a, "CONTROL_SAME", "answer-a", dnspath.OutcomeInconclusive),
		testOutcome(a, "CONTROL_SAME", "answer-a", dnspath.OutcomeInconclusive),
		testOutcome(b, "CONTROL_SAME", "answer-b", dnspath.OutcomeInconclusive),
		testOutcome(b, "CONTROL_SAME", "answer-b", dnspath.OutcomeInconclusive),
	}
	verified, _ := verifyADNSOutcomes(outcomes, []ADNSSuiteCase{{ID: "CONTROL_SAME"}}, 2)
	for _, out := range verified {
		if out.Class.Pass() {
			t.Fatalf("different same-service answers must not form quorum: %+v", out)
		}
	}
}

func TestControlUnrelatedMayUseCoarseLivenessAgreement(t *testing.T) {
	a := dnspath.DNSPathID{Family: dnspath.DNSPathTCP, ResolverID: "r-a", EndpointID: "e-a", IPFamily: "ipv4"}
	b := dnspath.DNSPathID{Family: dnspath.DNSPathDoH, ResolverID: "r-b", EndpointID: "e-b", IPFamily: "ipv4"}
	outcomes := []dnspath.DNSPathProbeOutcome{
		testOutcome(a, "CONTROL_UNRELATED", "cdn-a", dnspath.OutcomeInconclusive),
		testOutcome(a, "CONTROL_UNRELATED", "cdn-a", dnspath.OutcomeInconclusive),
		testOutcome(b, "CONTROL_UNRELATED", "cdn-b", dnspath.OutcomeInconclusive),
		testOutcome(b, "CONTROL_UNRELATED", "cdn-b", dnspath.OutcomeInconclusive),
	}
	verified, _ := verifyADNSOutcomes(outcomes, []ADNSSuiteCase{{ID: "CONTROL_UNRELATED"}}, 2)
	for _, out := range verified {
		if !out.Class.Pass() {
			t.Fatalf("unrelated liveness control may accept CDN diversity: %+v", out)
		}
	}
}

func TestInsufficientQuorumIsNotPort53Blocked(t *testing.T) {
	classic := dnspath.DNSPathID{Family: dnspath.DNSPathTCP, ResolverID: "r-classic", EndpointID: "e-c", IPFamily: "ipv4"}
	encrypted := dnspath.DNSPathID{Family: dnspath.DNSPathDoH, ResolverID: "r-encrypted", EndpointID: "e-e", IPFamily: "ipv4"}
	paths := map[string]dnspath.DNSPathID{classic.Hash(): classic, encrypted.Hash(): encrypted}
	stats := map[string]verifiedPathStats{
		classic.Hash(): {Fail: 14}, // structurally valid but no independent quorum
		encrypted.Hash(): {Pass: 14, CorrectnessPass: true, ControlsPass: true},
	}
	_, _, _, port53Blocked, _, _ := classifyDiagnosisFlags(nil, paths, stats, 2)
	if port53Blocked {
		t.Fatal("lack of independent corroboration must not be attributed as port-53 blocking")
	}
}

func TestRepeatedClassicTransportFailureCanProvePort53Blocked(t *testing.T) {
	classic := dnspath.DNSPathID{Family: dnspath.DNSPathTCP, ResolverID: "r-classic", EndpointID: "e-c", IPFamily: "ipv4"}
	encrypted := dnspath.DNSPathID{Family: dnspath.DNSPathDoH, ResolverID: "r-encrypted", EndpointID: "e-e", IPFamily: "ipv4"}
	paths := map[string]dnspath.DNSPathID{classic.Hash(): classic, encrypted.Hash(): encrypted}
	stats := map[string]verifiedPathStats{
		classic.Hash(): {Fail: 2, TransportFailures: 2, Timeouts: 2},
		encrypted.Hash(): {Pass: 14, CorrectnessPass: true, ControlsPass: true},
	}
	_, _, _, port53Blocked, _, _ := classifyDiagnosisFlags(nil, paths, stats, 2)
	if !port53Blocked {
		t.Fatal("repeated classic transport failures plus validated encrypted path should prove port-53 blocking")
	}
}
