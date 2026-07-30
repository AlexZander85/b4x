package config

func (s classifierRuntimeValidation) validateIdentityHintsCapture() {
	s.defaultInt(&s.r.ClientIdentity.MaxEntries, s.d.ClientIdentity.MaxEntries)
	s.defaultInt(&s.r.ClientIdentity.TTLSeconds, s.d.ClientIdentity.TTLSeconds)
	s.outOfRange("system.classifier.runtime.client_identity.max_entries", s.r.ClientIdentity.MaxEntries, 64, 65536)
	s.outOfRange("system.classifier.runtime.client_identity.ttl_seconds", s.r.ClientIdentity.TTLSeconds, 5, 3600)

	s.defaultU8(&s.r.Confidence.Classify, s.d.Confidence.Classify)
	s.defaultU8(&s.r.Confidence.Mutate, s.d.Confidence.Mutate)
	s.defaultU8(&s.r.Confidence.Destructive, s.d.Confidence.Destructive)
	s.defaultU8(&s.r.Confidence.ProxyFallback, s.d.Confidence.ProxyFallback)
	if !(s.r.Confidence.ProxyFallback <= s.r.Confidence.Classify && s.r.Confidence.Classify <= s.r.Confidence.Mutate && s.r.Confidence.Mutate <= s.r.Confidence.Destructive && s.r.Confidence.Destructive <= 100) {
		s.v.add("system.classifier.runtime.confidence", "invalid_threshold_order", "thresholds must satisfy proxy_fallback <= classify <= mutate <= destructive <= 100", nil)
	}

	s.defaultInt(&s.r.Hints.MaxEntries, s.d.Hints.MaxEntries)
	s.defaultInt(&s.r.Hints.MaxEntriesPerClient, s.d.Hints.MaxEntriesPerClient)
	s.defaultInt(&s.r.Hints.MaxCandidatesPerKey, s.d.Hints.MaxCandidatesPerKey)
	s.defaultInt(&s.r.Hints.MaxBytesPerClient, s.d.Hints.MaxBytesPerClient)
	s.defaultInt(&s.r.Hints.DNSMaxTTLSeconds, s.d.Hints.DNSMaxTTLSeconds)
	s.defaultInt(&s.r.Hints.QUICTTLSeconds, s.d.Hints.QUICTTLSeconds)
	s.defaultInt(&s.r.Hints.LearnedTTLSeconds, s.d.Hints.LearnedTTLSeconds)
	s.outOfRange("system.classifier.runtime.hints.max_entries", s.r.Hints.MaxEntries, 64, 65536)
	s.outOfRange("system.classifier.runtime.hints.max_entries_per_client", s.r.Hints.MaxEntriesPerClient, 1, 1024)
	s.outOfRange("system.classifier.runtime.hints.max_candidates_per_key", s.r.Hints.MaxCandidatesPerKey, 1, 64)
	s.outOfRange("system.classifier.runtime.hints.max_bytes_per_client", s.r.Hints.MaxBytesPerClient, 4096, 4*1024*1024)
	s.outOfRange("system.classifier.runtime.hints.dns_max_ttl_seconds", s.r.Hints.DNSMaxTTLSeconds, 1, 3600)
	s.outOfRange("system.classifier.runtime.hints.quic_ttl_seconds", s.r.Hints.QUICTTLSeconds, 1, 600)
	s.outOfRange("system.classifier.runtime.hints.learned_ttl_seconds", s.r.Hints.LearnedTTLSeconds, 1, 600)
	if s.r.Hints.MaxEntriesPerClient > s.r.Hints.MaxEntries {
		s.v.add("system.classifier.runtime.hints.max_entries_per_client", "exceeds_global_limit", "per-client hint limit must not exceed global limit", nil)
	}

	if s.r.Capture.NFQueue == (NFQueueCaptureConfig{}) {
		s.r.Capture.NFQueue = s.d.Capture.NFQueue
	}
	if s.r.Capture.NFQueue.GSOMode == "" {
		s.r.Capture.NFQueue.GSOMode = s.d.Capture.NFQueue.GSOMode
	}
	if s.r.Capture.NFQueue.MaxGSOBytes <= 0 {
		s.r.Capture.NFQueue.MaxGSOBytes = s.d.Capture.NFQueue.MaxGSOBytes
	}
	if s.r.Capture.NFQueue.NormalizerMechanism == "" {
		s.r.Capture.NFQueue.NormalizerMechanism = s.d.Capture.NFQueue.NormalizerMechanism
	}
	s.defaultInt(&s.r.Capture.NFQueue.NormalizerQueueOffset, s.d.Capture.NFQueue.NormalizerQueueOffset)
	s.defaultInt(&s.r.Capture.NFQueue.NormalizerThreads, s.d.Capture.NFQueue.NormalizerThreads)
	s.defaultInt(&s.r.Capture.NFQueue.DiscoveryThreads, s.d.Capture.NFQueue.DiscoveryThreads)
	s.defaultInt(&s.r.Capture.NFQueue.MaxTopologyWorkers, s.d.Capture.NFQueue.MaxTopologyWorkers)
	s.defaultInt(&s.r.Capture.NFQueue.MaxTopologyMemoryBytes, s.d.Capture.NFQueue.MaxTopologyMemoryBytes)
	s.defaultInt(&s.r.Capture.CandidateQueueOffset, s.d.Capture.CandidateQueueOffset)
	switch s.r.Capture.NFQueue.GSOMode {
	case GSOModeOff, GSOModeObserve, GSOModeClassify, GSOModeFull:
	default:
		s.v.add("system.classifier.runtime.capture.nfqueue.gso_mode", "unsupported_mode", "gso_mode must be off, observe, classify, or full", nil)
	}
	s.outOfRange("system.classifier.runtime.capture.nfqueue.max_gso_bytes", s.r.Capture.NFQueue.MaxGSOBytes, 1500, 65535)
	switch s.r.Capture.NFQueue.NormalizerMechanism {
	case GSONormalizerDirectQueue, GSONormalizerNFRepeat:
	default:
		s.v.add("system.classifier.runtime.capture.nfqueue.normalizer_mechanism", "unsupported_mechanism", "normalizer_mechanism must be direct-queue or nf-repeat", nil)
	}
	s.outOfRange("system.classifier.runtime.capture.nfqueue.normalizer_queue_offset", s.r.Capture.NFQueue.NormalizerQueueOffset, 1, 1024)
	s.outOfRange("system.classifier.runtime.capture.nfqueue.normalizer_threads", s.r.Capture.NFQueue.NormalizerThreads, 1, 64)
	s.outOfRange("system.classifier.runtime.capture.nfqueue.discovery_queue_offset", s.r.Capture.NFQueue.DiscoveryQueueOffset, 0, 1024)
	s.outOfRange("system.classifier.runtime.capture.nfqueue.discovery_threads", s.r.Capture.NFQueue.DiscoveryThreads, 1, 64)
	s.outOfRange("system.classifier.runtime.capture.nfqueue.max_topology_workers", s.r.Capture.NFQueue.MaxTopologyWorkers, 4, 256)
	s.outOfRange("system.classifier.runtime.capture.nfqueue.max_topology_memory_bytes", s.r.Capture.NFQueue.MaxTopologyMemoryBytes, 8*1024*1024, 1024*1024*1024)
	if s.r.Capture.NFQueue.NormalizerMechanism == GSONormalizerNFRepeat && s.r.Capture.NFQueue.GSOMode != GSOModeOff {
		s.v.add("system.classifier.runtime.capture.nfqueue.normalizer_mechanism", "target_validation_required", "nf-repeat normalizer remains disabled until target mark/loop cleanup validation passes", nil)
	}
	if !s.r.Capture.NFQueue.TCPOnly {
		s.v.add("system.classifier.runtime.capture.nfqueue.tcp_only", "tcp_only_required", "GSO hardening currently supports TCP capture only", nil)
	}
	s.validateNFQueueTopologyEnvelope()

	s.defaultU32(&s.r.Capture.OutgoingPacketLimit, s.d.Capture.OutgoingPacketLimit)
	s.defaultU32(&s.r.Capture.IncomingPacketLimit, s.d.Capture.IncomingPacketLimit)
	s.defaultU32(&s.r.Capture.ProcessedMarkMask, s.d.Capture.ProcessedMarkMask)
	if s.r.Capture.ProcessedMark == 0 {
		s.r.Capture.ProcessedMark = uint32(s.c.Queue.Mark) | (1 << 27)
	}
	s.defaultInt(&s.r.Capture.ReadinessTimeoutMS, s.d.Capture.ReadinessTimeoutMS)
	s.c.validatePPEConfig(s.v)
	if s.r.Capture.OutgoingPacketLimit > 4096 || s.r.Capture.IncomingPacketLimit > 4096 {
		s.v.add("system.classifier.runtime.capture", "capture_limit", "capture packet limits must be 1..4096", nil)
	}
	if s.r.Capture.ProcessedMarkMask&(1<<27) == 0 || s.r.Capture.ProcessedMark&s.r.Capture.ProcessedMarkMask == 0 {
		s.v.add("system.classifier.runtime.capture.processed_mark", "invalid_provenance_mark", "processed mark and mask must reserve the generated-packet provenance bit", nil)
	}
	s.outOfRange("system.classifier.runtime.capture.candidate_queue_offset", s.r.Capture.CandidateQueueOffset, 1, 1024)
	s.outOfRange("system.classifier.runtime.capture.readiness_timeout_ms", s.r.Capture.ReadinessTimeoutMS, 100, 30000)
}

func (s classifierRuntimeValidation) validateNFQueueTopologyEnvelope() {
	base := s.c.Queue.StartNum
	productionThreads := s.c.Queue.Threads
	if base < 0 || base > 65535 || productionThreads < 1 {
		return
	}
	type queueRange struct {
		name    string
		start   int
		threads int
		enabled bool
	}
	nfq := s.r.Capture.NFQueue
	ranges := []queueRange{
		{name: "production", start: base, threads: productionThreads, enabled: true},
		{name: "discovery", start: base + productionThreads + nfq.DiscoveryQueueOffset, threads: nfq.DiscoveryThreads, enabled: true},
		{name: "candidate", start: base + productionThreads + s.r.Capture.CandidateQueueOffset, threads: 1, enabled: true},
		{name: "normalizer", start: base + productionThreads + nfq.NormalizerQueueOffset, threads: nfq.NormalizerThreads, enabled: nfq.NormalizeForMutation && (nfq.GSOMode == GSOModeClassify || nfq.GSOMode == GSOModeFull)},
	}
	for i, r := range ranges {
		if r.threads < 1 {
			continue
		}
		end := r.start + r.threads - 1
		if r.start < 0 || end > 65535 {
			s.v.addf("system.classifier.runtime.capture.nfqueue", "queue_range_overflow", map[string]any{"role": r.name, "start": r.start, "end": end}, "%s queue range %d-%d is outside [0,65535]", r.name, r.start, end)
		}
		for j := i + 1; j < len(ranges); j++ {
			o := ranges[j]
			if o.threads < 1 {
				continue
			}
			oEnd := o.start + o.threads - 1
			if r.start <= oEnd && o.start <= end {
				s.v.addf("system.classifier.runtime.capture.nfqueue", "queue_range_overlap", map[string]any{"first": r.name, "second": o.name}, "%s and %s NFQUEUE ranges overlap", r.name, o.name)
			}
		}
	}
	workers := productionThreads + nfq.DiscoveryThreads + 1
	if ranges[3].enabled {
		workers += nfq.NormalizerThreads
	}
	if workers > nfq.MaxTopologyWorkers {
		s.v.addf("system.classifier.runtime.capture.nfqueue.max_topology_workers", "worker_budget_exceeded", map[string]any{"workers": workers}, "topology requires %d workers but max_topology_workers is %d", workers, nfq.MaxTopologyWorkers)
	}
	perWorker := s.r.Reassembly.MaxBytesTotal + s.r.HoldReplay.MaxBytesTotal + nfq.MaxGSOBytes + 256*1024
	if perWorker < 256*1024 {
		perWorker = 256 * 1024
	}
	if workers > 0 && perWorker > 0 && workers > nfq.MaxTopologyMemoryBytes/perWorker {
		s.v.addf("system.classifier.runtime.capture.nfqueue.max_topology_memory_bytes", "memory_budget_exceeded", map[string]any{"workers": workers, "per_worker": perWorker}, "topology estimated memory exceeds max_topology_memory_bytes")
	}
}
