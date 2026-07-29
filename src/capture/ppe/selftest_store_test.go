package ppe

import "testing"

func TestMemorySelfTestStoreIsBoundedAndClones(t *testing.T) {
	store := NewMemorySelfTestStore(2)
	store.Put(CaptureVisibilityResult{RunID: "one", Evidence: []string{"a"}})
	store.Put(CaptureVisibilityResult{RunID: "two"})
	store.Put(CaptureVisibilityResult{RunID: "three"})
	if _, ok := store.Get("one"); ok {
		t.Fatal("oldest result was not evicted")
	}
	result, ok := store.Get("three")
	if !ok {
		t.Fatal("missing result")
	}
	result.Evidence = append(result.Evidence, "mutated")
	again, _ := store.Get("three")
	if len(again.Evidence) != 0 {
		t.Fatal("store leaked mutable slice")
	}
}
