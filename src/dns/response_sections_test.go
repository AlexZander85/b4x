package dns

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

func TestParseStructuredResponseExcludesAdditionalGlueFromAnswers(t *testing.T) {
	qname := encodeDNSName("service.example")
	body := append([]byte{}, qname...)
	body = append(body, 0x00, 0x01, 0x00, 0x01) // A/IN question
	body = appendStructuredRR(body, []byte{0xc0, 0x0c}, 1, 1, 60, []byte{1, 2, 3, 4})
	// Additional glue A record must be structurally accepted but must not
	// enter the answer/fingerprint view.
	body = appendStructuredRR(body, encodeDNSName("ns.example"), 1, 1, 60, []byte{9, 9, 9, 9})
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	binary.BigEndian.PutUint16(msg[10:12], 1)
	msg = append(msg, body...)

	obs, err := ParseStructuredResponse(msg, classifier.ClientKey{}, "resolver", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Answers) != 1 || obs.Answers[0].IP != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("answer section contaminated by additional glue: %+v", obs.Answers)
	}
	meta, err := InspectResponseMetadata(msg)
	if err != nil {
		t.Fatal(err)
	}
	if meta.AnswerCount != 1 || meta.AdditionalCount != 1 {
		t.Fatalf("section counts = %+v", meta)
	}
}
