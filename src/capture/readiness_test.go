package capture

import (
	"errors"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

type mapProcFS struct {
	data map[string][]byte
	err  error
}

func (m mapProcFS) ReadFile(path string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.data[path], nil
}

func TestParseNFNetlinkQueue(t *testing.T) {
	data := []byte("0 537 12 2 65531 3 4 0 0\n1 538 4 2 65531 0 1 0 0\n")
	got, err := ParseNFNetlinkQueue(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].QueueNumber != 0 || got[0].PortID != 537 || got[0].QueueDrops != 3 || got[0].UserDrops != 4 {
		t.Fatalf("unexpected states: %+v", got)
	}
}

func TestCheckQueueReadinessOwnerAndMissingQueue(t *testing.T) {
	clk := clock.NewFixed(time.Unix(123, 0))
	fs := mapProcFS{data: map[string][]byte{
		"mock": []byte("537 9001 2 2 65531 1 2\n538 9001 1 2 65531 0 0\n"),
	}}
	report := CheckQueueReadinessWithClock(fs, QueueReadinessSpec{
		ProcPath:            "mock",
		QueueNumbers:        []uint16{537, 538},
		ExpectedOwnerPortID: 9001,
		RequireOwner:        true,
	}, clk)
	if !report.Ready || !report.OwnerVerified || !report.QueueTableFound {
		t.Fatalf("expected ready report: %+v", report)
	}
	if !report.CheckedAt.Equal(time.Unix(123, 0)) || report.QueueDrops != 1 || report.UserDrops != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}

	report = CheckQueueReadiness(fs, QueueReadinessSpec{ProcPath: "mock", QueueNumbers: []uint16{537, 539}, ExpectedOwnerPortID: 9002})
	if report.Ready || len(report.MissingQueues) != 1 || len(report.OwnerMismatches) != 1 {
		t.Fatalf("expected missing queue and owner mismatch: %+v", report)
	}
}

func TestCheckQueueReadinessFailureIsFailOpenDiagnostic(t *testing.T) {
	report := CheckQueueReadiness(mapProcFS{err: errors.New("permission denied")}, QueueReadinessSpec{QueueNumbers: []uint16{537}})
	if report.Ready || len(report.Errors) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestCheckQueueReadinessIsIdempotent(t *testing.T) {
	fs := mapProcFS{data: map[string][]byte{"mock": []byte("537 9001 2 2 65531 1 2\n")}}
	spec := QueueReadinessSpec{ProcPath: "mock", QueueNumbers: []uint16{537}, ExpectedOwnerPortID: 9001}
	first := CheckQueueReadiness(fs, spec)
	second := CheckQueueReadiness(fs, spec)
	if first.Ready != second.Ready || first.QueueDrops != second.QueueDrops || first.UserDrops != second.UserDrops {
		t.Fatalf("repeated readiness probe changed state: first=%+v second=%+v", first, second)
	}
}

func TestParseNFNetlinkQueueRejectsMalformedData(t *testing.T) {
	if _, err := ParseNFNetlinkQueue([]byte("537 nope 1\n")); err == nil {
		t.Fatal("expected malformed portid to fail")
	}
}
