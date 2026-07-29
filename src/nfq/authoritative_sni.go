package nfq

import (
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/sni"
)

// authoritativeTLSObservation normalizes packet-local and reassembled
// ClientHello metadata into one hostname decision input. A completed,
// conflict-free reassembly is authoritative for the exact flow.
type authoritativeTLSObservation struct {
	Host          string
	TLSVersion    uint16
	Source        classifier.EvidenceSource
	Complete      bool
	ECHPresent    bool
	Conflict      bool
	Reason        string
	ClientHelloID uint64
	ConfigGen     uint64
}

func resolveAuthoritativeTLSObservation(payload []byte, reassembly classifier.TCPReassemblyResult) authoritativeTLSObservation {
	return resolveAuthoritativeTLSObservationWithOffload(payload, reassembly, OffloadMetadata{})
}

func resolveAuthoritativeTLSObservationWithOffload(payload []byte, reassembly classifier.TCPReassemblyResult, offload OffloadMetadata) authoritativeTLSObservation {
	packet := sni.ParseTLSClientHelloMetadata(payload)
	observation := authoritativeTLSObservation{
		Host:       strings.ToLower(strings.TrimSpace(packet.SNI)),
		TLSVersion: packet.MaxVersion,
		Source:     classifier.EvidencePacketSNI,
		Complete:   packet.Complete,
		ECHPresent: packet.ECHPresent,
	}
	if offload.Truncated {
		// NFQA_CAP_LEN proves that userspace received only a prefix. Even when
		// that prefix happens to contain a syntactically complete ClientHello, it
		// is not authoritative for this skb. A separately completed bounded
		// reassembly result may still be used below.
		observation.Host = ""
		observation.Complete = false
		observation.Reason = "nfqueue payload truncated"
	}
	if reassembly.Status != classifier.ReassemblyComplete || !reassembly.Metadata.Complete {
		return observation
	}

	reassembledHost := strings.ToLower(strings.TrimSpace(reassembly.Metadata.SNI))
	if observation.Host != "" && reassembledHost != "" && !strings.EqualFold(observation.Host, reassembledHost) {
		return authoritativeTLSObservation{
			TLSVersion:    maxTLSVersion(observation.TLSVersion, reassembly.Metadata.MaxVersion),
			Source:        classifier.EvidenceReassembledSNI,
			Complete:      true,
			ECHPresent:    observation.ECHPresent || reassembly.Metadata.ECHPresent,
			Conflict:      true,
			Reason:        "packet-local and reassembled SNI conflict",
			ClientHelloID: reassembly.ClientHelloID,
			ConfigGen:     reassembly.ConfigGen,
		}
	}
	if reassembledHost != "" {
		observation.Host = reassembledHost
		observation.Source = classifier.EvidenceReassembledSNI
	}
	observation.TLSVersion = maxTLSVersion(observation.TLSVersion, reassembly.Metadata.MaxVersion)
	observation.Complete = true
	observation.ECHPresent = observation.ECHPresent || reassembly.Metadata.ECHPresent
	observation.ClientHelloID = reassembly.ClientHelloID
	observation.ConfigGen = reassembly.ConfigGen
	return observation
}

func maxTLSVersion(a, b uint16) uint16 {
	if b > a {
		return b
	}
	return a
}

type clientHelloDecisionKey struct {
	FlowKey       classifier.FlowKey
	ClientHelloID uint64
	ConfigGen     uint64
}

type clientHelloDecisionClaimStore struct {
	mu     sync.Mutex
	claims map[clientHelloDecisionKey]time.Time
	ttl    time.Duration
	max    int
}

func newClientHelloDecisionClaimStore() *clientHelloDecisionClaimStore {
	return &clientHelloDecisionClaimStore{
		claims: make(map[clientHelloDecisionKey]time.Time),
		ttl:    2 * time.Minute,
		max:    4096,
	}
}

// Claim returns true only for the first final decision for a logical
// ClientHello. Entries are exact-flow and config-generation scoped.
func (s *clientHelloDecisionClaimStore) Claim(key classifier.FlowKey, clientHelloID, configGen uint64, now time.Time) bool {
	if s == nil || clientHelloID == 0 {
		return true
	}
	claim := clientHelloDecisionKey{FlowKey: key.Normalize(), ClientHelloID: clientHelloID, ConfigGen: configGen}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	if _, exists := s.claims[claim]; exists {
		return false
	}
	if len(s.claims) >= s.max {
		var oldestKey clientHelloDecisionKey
		var oldest time.Time
		first := true
		for candidate, created := range s.claims {
			if first || created.Before(oldest) {
				oldestKey, oldest, first = candidate, created, false
			}
		}
		if !first {
			delete(s.claims, oldestKey)
		}
	}
	s.claims[claim] = now
	return true
}

func (s *clientHelloDecisionClaimStore) GC(now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
}

func (s *clientHelloDecisionClaimStore) gcLocked(now time.Time) {
	for key, created := range s.claims {
		if now.Sub(created) >= s.ttl {
			delete(s.claims, key)
		}
	}
}
