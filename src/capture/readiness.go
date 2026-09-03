package capture

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

const NFNetlinkQueueProcPath = "/proc/net/netfilter/nfnetlink_queue"

type ProcFS interface {
	ReadFile(path string) ([]byte, error)
}

type OSProcFS struct{}

func (OSProcFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

type QueueReadinessSpec struct {
	ProcPath            string
	QueueNumbers        []uint16
	ExpectedOwnerPortID uint32
	RequireOwner        bool
}

type QueueState struct {
	QueueNumber uint16 `json:"queue_number"`
	PortID      uint32 `json:"port_id"`
	QueueTotal  uint64 `json:"queue_total"`
	QueueDrops  uint64 `json:"queue_dropped"`
	UserDrops   uint64 `json:"user_dropped"`
}

type QueueOwnerMismatch struct {
	QueueNumber uint16 `json:"queue_number"`
	Expected    uint32 `json:"expected"`
	Actual      uint32 `json:"actual"`
}

type QueueReadinessReport struct {
	CheckedAt       time.Time            `json:"checked_at"`
	Ready           bool                 `json:"ready"`
	QueueTableFound bool                 `json:"queue_table_found"`
	OwnerVerified   bool                 `json:"owner_verified"`
	Queues          []QueueState         `json:"queues,omitempty"`
	MissingQueues   []uint16             `json:"missing_queues,omitempty"`
	OwnerMismatches []QueueOwnerMismatch `json:"owner_mismatches,omitempty"`
	QueueDrops      uint64               `json:"queue_drops"`
	UserDrops       uint64               `json:"user_drops"`
	Errors          []string             `json:"errors,omitempty"`
}

func (e CaptureEnvelope) ReadinessSpec() QueueReadinessSpec {
	queues := make([]uint16, 0, e.QueueThreads)
	for i := uint16(0); i < e.QueueThreads; i++ {
		queues = append(queues, e.QueueStart+i)
	}
	return QueueReadinessSpec{QueueNumbers: queues}
}

// ParseNFNetlinkQueue parses the stable numeric prefix of the kernel proc
// record: queue number, netlink portid, queue length, copy mode, copy range,
// queue drops and user drops. Extra columns are intentionally ignored because
// kernels have added fields over time.
func ParseNFNetlinkQueue(data []byte) ([]QueueState, error) {
	var states []QueueState
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 3 {
			if strings.Contains(strings.ToLower(strings.Join(fields, " ")), "queue") {
				continue
			}
			return nil, fmt.Errorf("nfnetlink_queue line %d: expected at least 3 columns", lineNo)
		}
		queue, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			// Some vendor kernels expose a header. Only skip a line that is
			// unambiguously a header; malformed numeric-looking data is fatal.
			if strings.Contains(strings.ToLower(strings.Join(fields, " ")), "queue") {
				continue
			}
			return nil, fmt.Errorf("nfnetlink_queue line %d queue number: %w", lineNo, err)
		}
		port, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("nfnetlink_queue line %d portid: %w", lineNo, err)
		}
		total, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("nfnetlink_queue line %d queue total: %w", lineNo, err)
		}
		state := QueueState{QueueNumber: uint16(queue), PortID: uint32(port), QueueTotal: total}
		if len(fields) > 5 {
			state.QueueDrops, err = strconv.ParseUint(fields[5], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("nfnetlink_queue line %d queue drops: %w", lineNo, err)
			}
		}
		if len(fields) > 6 {
			state.UserDrops, err = strconv.ParseUint(fields[6], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("nfnetlink_queue line %d user drops: %w", lineNo, err)
			}
		}
		states = append(states, state)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("nfnetlink_queue scan: %w", err)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].QueueNumber < states[j].QueueNumber })
	return states, nil
}

func CheckQueueReadiness(fs ProcFS, spec QueueReadinessSpec) QueueReadinessReport {
	return CheckQueueReadinessWithClock(fs, spec, clock.RealClock{})
}

func CheckQueueReadinessWithClock(fs ProcFS, spec QueueReadinessSpec, clk clock.Clock) QueueReadinessReport {
	report := QueueReadinessReport{CheckedAt: clk.Now(), OwnerVerified: spec.ExpectedOwnerPortID != 0}
	if spec.ProcPath == "" {
		spec.ProcPath = NFNetlinkQueueProcPath
	}
	if fs == nil {
		report.Errors = []string{"procfs reader is nil"}
		return report
	}
	if len(spec.QueueNumbers) == 0 {
		report.Errors = []string{"no queues configured"}
		return report
	}
	data, err := fs.ReadFile(spec.ProcPath)
	if err != nil {
		report.Errors = []string{fmt.Sprintf("read %s: %v", spec.ProcPath, err)}
		return report
	}
	report.QueueTableFound = true
	states, err := ParseNFNetlinkQueue(data)
	if err != nil {
		report.Errors = []string{err.Error()}
		return report
	}
	report.Queues = states
	byNumber := make(map[uint16]QueueState, len(states))
	for _, state := range states {
		byNumber[state.QueueNumber] = state
		report.QueueDrops += state.QueueDrops
		report.UserDrops += state.UserDrops
	}
	for _, queue := range spec.QueueNumbers {
		state, ok := byNumber[queue]
		if !ok {
			report.MissingQueues = append(report.MissingQueues, queue)
			continue
		}
		if spec.ExpectedOwnerPortID != 0 && state.PortID != spec.ExpectedOwnerPortID {
			report.OwnerMismatches = append(report.OwnerMismatches, QueueOwnerMismatch{
				QueueNumber: queue,
				Expected:    spec.ExpectedOwnerPortID,
				Actual:      state.PortID,
			})
		}
	}
	if spec.ExpectedOwnerPortID != 0 {
		report.OwnerVerified = len(report.OwnerMismatches) == 0 && len(report.MissingQueues) == 0
	}
	report.Ready = report.QueueTableFound && len(report.Errors) == 0 && len(report.MissingQueues) == 0 &&
		len(report.OwnerMismatches) == 0 && (!spec.RequireOwner || report.OwnerVerified)
	return report
}
