package nfq

import (
	"testing"
	"time"
)

func TestTCPInjectOnceClaimsFirstThenRejects(t *testing.T) {
	s := newTCPInjectOnceStore()
	now := time.Unix(1000, 0)
	if !s.Claim("a", now) {
		t.Fatal("first claim")
	}
	if s.Claim("a", now.Add(time.Second)) {
		t.Fatal("second claim must refuse")
	}
	if !s.Claim("b", now) {
		t.Fatal("other flow")
	}
}

func TestTCPInjectOnceExpires(t *testing.T) {
	s := newTCPInjectOnceStore()
	now := time.Unix(2000, 0)
	if !s.Claim("a", now) {
		t.Fatal("first")
	}
	if s.Claim("a", now.Add(time.Minute)) {
		t.Fatal("still live")
	}
	if !s.Claim("a", now.Add(3*time.Minute)) {
		t.Fatal("after ttl")
	}
}
