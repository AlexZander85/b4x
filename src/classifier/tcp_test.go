package classifier

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

func testFlowKey() FlowKey {
	return NewFlowKey(
		ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.10"), IfIndex: 2, VLAN: 10},
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.7"), 51000, 443, 6,
	)
}

func TestIsCleanSYNRequiresExplicitTechniqueForMutation(t *testing.T) {
	if !IsCleanSYN(TCPFlagSYN, 0, false) {
		t.Fatal("plain SYN was not clean")
	}
	for _, tc := range []struct {
		name     string
		flags    byte
		payload  int
		explicit bool
	}{
		{name: "fake technique", flags: TCPFlagSYN, explicit: true},
		{name: "TFO", flags: TCPFlagSYN, payload: 1},
		{name: "SYN ACK", flags: TCPFlagSYN | TCPFlagACK},
		{name: "SYN FIN", flags: TCPFlagSYN | TCPFlagFIN},
		{name: "SYN RST", flags: TCPFlagSYN | TCPFlagRST},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if IsCleanSYN(tc.flags, tc.payload, tc.explicit) {
				t.Fatalf("flags=%#x payload=%d explicit=%v was incorrectly clean", tc.flags, tc.payload, tc.explicit)
			}
		})
	}
}

func TestFlowKeyNormalizesReverseDirectionAndMappedIPv4(t *testing.T) {
	client := ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("::ffff:192.0.2.10"), IfIndex: 2, VLAN: 10}
	forward := NewFlowKey(client, netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.7"), 51000, 443, 6)
	reverse := NewFlowKey(client, netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("::ffff:192.0.2.10"), 443, 51000, 6)
	if forward != reverse {
		t.Fatalf("reverse flow keys differ: forward=%+v reverse=%+v", forward, reverse)
	}
	if forward.Client.SourceIP != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("client address was not canonicalized: %+v", forward.Client)
	}
}

func TestTCPFlowTransitionsAndRetransmission(t *testing.T) {
	phase, reason := Transition(TCPNew, TCPEventSYN)
	if phase != TCPSynSeen || reason != "client SYN seen" {
		t.Fatalf("SYN transition = %s/%q", phase, reason)
	}
	phase, reason = Transition(phase, TCPEventSYN)
	if phase != TCPSynSeen || reason != "SYN retransmission" {
		t.Fatalf("SYN retransmission = %s/%q", phase, reason)
	}
	phase, _ = Transition(phase, TCPEventSYNACK)
	if phase != TCPEstablished {
		t.Fatalf("SYN-ACK phase = %s", phase)
	}
	phase, _ = Transition(phase, TCPEventClientHelloPartial)
	phase, _ = Transition(phase, TCPEventClientHelloComplete)
	phase, _ = Transition(phase, TCPEventActionPlanned)
	phase, _ = Transition(phase, TCPEventActionApplied)
	if phase != TCPActionApplied {
		t.Fatalf("action phase = %s", phase)
	}
	phase, reason = Transition(phase, TCPEventRetransmission)
	if phase != TCPActionApplied || reason != "retransmission ignored" {
		t.Fatalf("post-action retransmission = %s/%q", phase, reason)
	}
}

func TestTCPFlowTFOAndServerProgressCloseMutation(t *testing.T) {
	state := NewTCPFlowState(testFlowKey(), 7, time.Unix(100, 0))
	result := state.Apply(TCPEventTFO, 7, time.Unix(101, 0))
	if !result.Accepted || state.Phase != TCPEstablished || !state.FastOpen {
		t.Fatalf("TFO state=%+v result=%+v", state, result)
	}
	result = state.Apply(TCPEventServerProgress, 7, time.Unix(102, 0))
	if !result.Accepted || state.Phase != TCPServerProgress || !state.MutationWindowClosed {
		t.Fatalf("server progress state=%+v result=%+v", state, result)
	}
	result = state.Apply(TCPEventActionPlanned, 7, time.Unix(103, 0))
	if result.Accepted || state.Phase != TCPServerProgress {
		t.Fatalf("action was allowed after server progress: state=%+v result=%+v", state, result)
	}
}

func TestTCPFlowFINRSTCleanupAndGenerationChange(t *testing.T) {
	clk := clock.NewFixed(time.Unix(200, 0))
	store := NewTCPFlowStore(2, clk)
	key := testFlowKey()
	state, result := store.Observe(key, TCPEventSYN, 7)
	if !result.Accepted || state.Phase != TCPSynSeen || store.Len() != 1 {
		t.Fatalf("SYN state=%+v result=%+v len=%d", state, result, store.Len())
	}
	state, result = store.Observe(key, TCPEventSYNACK, 8)
	if !result.ConfigChanged || state.ConfigGeneration != 8 || state.Phase != TCPEstablished {
		t.Fatalf("generation change state=%+v result=%+v", state, result)
	}
	state, result = store.Observe(key, TCPEventFIN, 8)
	if !result.Accepted || state.Phase != TCPClosed || store.Len() != 0 {
		t.Fatalf("FIN cleanup state=%+v result=%+v len=%d", state, result, store.Len())
	}
	state, result = store.Observe(key, TCPEventSYN, 8)
	if state.Phase != TCPSynSeen || result.From != TCPNew {
		t.Fatalf("new flow after FIN state=%+v result=%+v", state, result)
	}
	state, result = store.Observe(key, TCPEventRST, 8)
	if !result.Accepted || state.TerminalReason != "rst" || store.Len() != 0 {
		t.Fatalf("RST cleanup state=%+v result=%+v len=%d", state, result, store.Len())
	}
}

func TestTCPFlowStoreBoundedAndGC(t *testing.T) {
	clk := clock.NewFixed(time.Unix(300, 0))
	store := NewTCPFlowStore(2, clk)
	for i, ip := range []string{"192.0.2.20", "192.0.2.21", "192.0.2.22"} {
		key := NewFlowKey(ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr(ip)}, netip.MustParseAddr(ip), netip.MustParseAddr("203.0.113.7"), uint16(51000+i), 443, 6)
		store.Observe(key, TCPEventSYN, 1)
	}
	if store.Len() != 2 {
		t.Fatalf("flow store exceeded bound: %d", store.Len())
	}
	clk.Advance(time.Hour)
	if removed := store.GC(clk.Now(), time.Minute); removed != 2 || store.GC(clk.Now(), time.Minute) != 0 {
		t.Fatalf("GC not deterministic/idempotent: removed=%d len=%d", removed, store.Len())
	}
}
