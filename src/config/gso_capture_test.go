package config

import "testing"

func TestNFQueueGSOConfigDefaultsOffAndTCPOnly(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Runtime.Capture.NFQueue = NFQueueCaptureConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate defaults: %v", err)
	}
	gso := cfg.System.Classifier.Runtime.Capture.NFQueue
	if gso.GSOMode != GSOModeOff || gso.MaxGSOBytes != 32*1024 || !gso.NormalizeForMutation || !gso.TCPOnly {
		t.Fatalf("unsafe GSO defaults: %+v", gso)
	}
}

func TestNFQueueGSOConfigValidatesModesAndBounds(t *testing.T) {
	for _, mode := range []string{GSOModeOff, GSOModeObserve, GSOModeClassify, GSOModeFull} {
		cfg := NewConfig()
		cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode = mode
		if err := cfg.Validate(); err != nil {
			t.Fatalf("mode %q rejected: %v", mode, err)
		}
	}
	cfg := NewConfig()
	cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode = "automatic"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsupported GSO mode accepted")
	}
	cfg = NewConfig()
	cfg.System.Classifier.Runtime.Capture.NFQueue.MaxGSOBytes = 1000
	if err := cfg.Validate(); err == nil {
		t.Fatal("undersized max_gso_bytes accepted")
	}
	cfg = NewConfig()
	cfg.System.Classifier.Runtime.Capture.NFQueue.TCPOnly = false
	cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode = GSOModeClassify
	if err := cfg.Validate(); err == nil {
		t.Fatal("non-TCP GSO mode accepted")
	}
}

func TestNFQueueGSOTopologyDefaultsAndOverlapValidation(t *testing.T) {
	cfg := NewConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	nfq := cfg.System.Classifier.Runtime.Capture.NFQueue
	if nfq.NormalizerMechanism != GSONormalizerDirectQueue || nfq.NormalizerQueueOffset != 2 || nfq.NormalizerThreads != 1 || nfq.DiscoveryThreads != 1 {
		t.Fatalf("topology defaults=%+v", nfq)
	}

	cfg = NewConfig()
	cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode = GSOModeClassify
	cfg.System.Classifier.Runtime.Capture.NFQueue.NormalizerQueueOffset = cfg.System.Classifier.Runtime.Capture.CandidateQueueOffset
	if err := cfg.Validate(); err == nil {
		t.Fatal("candidate/normalizer queue overlap accepted")
	}
}

func TestNFQueueGSOTopologyRejectsUncertifiedRepeatAndResourceOverflow(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode = GSOModeClassify
	cfg.System.Classifier.Runtime.Capture.NFQueue.NormalizerMechanism = GSONormalizerNFRepeat
	if err := cfg.Validate(); err == nil {
		t.Fatal("uncertified nf-repeat mode accepted")
	}

	cfg = NewConfig()
	cfg.Queue.StartNum = 65534
	cfg.Queue.Threads = 2
	if err := cfg.Validate(); err == nil {
		t.Fatal("topology queue overflow accepted")
	}
}
