package ppe

import "testing"

func TestEqualRulesIgnoresArgumentOrder(t *testing.T) {
	desired := [][]string{{
		"-A", ChainPre, "-m", "set", "--match-set", "b4_managed_devices", "src",
		"-p", "tcp", "-m", "multiport", "--dports", "443",
		"-m", "connskip", "--connskip", "30",
		"-m", "comment", "--comment", "b4:ppe:v1:tcp", "-j", "PPE",
	}}
	// iptables 1.4.21 -S prints the protocol before the set match and quotes
	// comments; splitRuleLine strips quotes. Semantic equality must hold.
	listed := [][]string{{
		"-A", ChainPre, "-p", "tcp", "-m", "set", "--match-set", "b4_managed_devices", "src",
		"-m", "multiport", "--dports", "443",
		"-m", "connskip", "--connskip", "30",
		"-m", "comment", "--comment", "b4:ppe:v1:tcp", "-j", "PPE",
	}}
	if !equalRules(desired, listed) {
		t.Fatalf("equalRules: reordered argument lists must compare equal")
	}
}

func TestEqualRulesDetectsSemanticDifference(t *testing.T) {
	left := [][]string{{"-A", ChainPre, "-p", "tcp", "--dport", "443", "-j", "PPE"}}
	right := [][]string{{"-A", ChainPre, "-p", "tcp", "--dport", "8443", "-j", "PPE"}}
	if equalRules(left, right) {
		t.Fatalf("equalRules: different ports must not compare equal")
	}
	if equalRules(left, [][]string{{"-A", ChainPre, "-p", "tcp", "--dport", "443"}}) {
		t.Fatalf("equalRules: missing target must not compare equal")
	}
}