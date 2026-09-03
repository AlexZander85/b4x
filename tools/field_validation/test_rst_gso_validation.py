#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

import rst_gso_field_validation as rv


REQUIRED_NORMATIVE_TAGS = {
    "network_namespace", "veth", "real_gso_skb",
    "clienthello_1988", "clienthello_4096", "clienthello_16384", "clienthello_32768",
    "nfqa_cap_len", "nfqa_skb_csum_not_ready", "unchanged_nf_accept",
    "mutation_normalization", "direct_queue_or_nf_repeat", "hold_timeout", "shutdown_cleanup",
    "queue_listener_crash", "ipv4", "ipv6", "iptables", "nftables",
    "production_candidate_discovery_isolation", "ppe_visibility", "keenetic_resources",
    "chrome_cold_ab", "official_youtube", "revanced", "instagram_control",
    "facebook_control", "cloudflare_control", "discovery_reproducibility_ab",
    "legitimate_closed_port_rst", "legitimate_after_synack_rst",
    "legitimate_after_server_progress", "forged_pre_response_rst", "multi_rst_burst",
    "ttl_match", "ttl_mismatch", "stable_baseline", "route_change_baseline",
    "ecmp_anycast_variation", "impossible_seq_ack", "valid_seq_ack", "tcp_option_mismatch",
    "rst_without_ack", "ipv4_ttl", "ipv6_hop_limit", "incomplete_ppe_visibility",
    "unknown_flow", "budget_exhaustion", "config_generation_change",
    "rollback_reconnect_regression", "cloudflare_reconnect_control",
    "gso_classify_rst_observe", "gso_normalize_rst_held_first_flight",
    "gso_token_timeout_rst", "candidate_queue_rst_isolation", "ppe_deoffload_window_gso",
    "hot_topology_rollback_active_flows", "router_restart_stale_cleanup",
    "sustained_load_memory_pressure",
}


def make_args() -> argparse.Namespace:
    return argparse.Namespace(
        router_url="https://192.168.1.1:7000",
        architecture="arm64",
        target_client="mac:aa:bb:cc:dd:ee:ff",
        expected_generation="generation-42",
        branch="agent/classifier-v2.3-capture-envelope",
        commit="deadbeef",
        max_cpu_pct=75.0,
        max_memory_mib=96.0,
        max_queue_drops=1,
        min_throughput_bps=5_000_000,
        max_latency_regression_pct=15.0,
    )


def satisfying_metrics(definition: dict, budgets: dict) -> dict:
    metrics = {name: 0 for name in definition.get("required_metrics", [])}
    for assertion in definition.get("assertions", []):
        name = assertion["metric"]
        op = assertion["op"]
        if op == "true":
            metrics[name] = True
        elif op == "false":
            metrics[name] = False
        elif op == "eq":
            metrics[name] = assertion["value"]
        elif op == "neq":
            metrics[name] = assertion.get("value", 0) + 1
        elif op == "gte":
            metrics[name] = assertion["value"]
        elif op == "lte":
            metrics[name] = assertion["value"]
        elif op == "lte_budget":
            metrics[name] = budgets[assertion["budget"]]
        elif op == "gte_budget":
            metrics[name] = budgets[assertion["budget"]]
        else:
            raise AssertionError(op)
    return metrics


class RSTGSOValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = rv.load_manifest()
        self.run = rv.new_run(make_args(), self.manifest)

    def test_manifest_covers_normative_h10_matrix(self):
        tags = {tag for scenario in self.manifest["scenarios"] for tag in scenario["tags"]}
        self.assertTrue(REQUIRED_NORMATIVE_TAGS <= tags)
        suites = {}
        for scenario in self.manifest["scenarios"]:
            suites[scenario["suite"]] = suites.get(scenario["suite"], 0) + 1
        self.assertGreaterEqual(suites["gso"], 18)
        self.assertGreaterEqual(suites["passive_rst"], 18)
        self.assertEqual(8, suites["combined"])
        self.assertEqual("BLOCKED_TARGET_VALIDATION", self.manifest["blocked_verdict"])

    def test_new_run_is_blocked_and_identifiers_are_non_reversible(self):
        certification = rv.certify(self.run, self.manifest)
        self.assertEqual(rv.BLOCKED, certification["status"])
        target = self.run["target"]
        self.assertTrue(target["router_id"].startswith("sha256:"))
        self.assertTrue(target["target_client_id"].startswith("sha256:"))
        self.assertNotIn("192.168.1.1", json.dumps(self.run))
        self.assertNotIn("aa:bb:cc:dd:ee:ff", json.dumps(self.run))

    def test_pass_without_required_artifact_is_demoted_to_fail(self):
        definition = self.manifest["scenarios"][0]
        metrics = satisfying_metrics(definition, self.run["budgets"])
        record = rv.record_entry(self.run, self.manifest, "scenarios", definition["id"], "pass", "claimed pass", metrics, [], "")
        self.assertEqual("fail", record["status"])
        self.assertTrue(any("missing artifact kinds" in reason for reason in record["validation_reasons"]))

    def test_artifact_index_hashes_content_without_persisting_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "router raw commands.log"
            path.write_bytes(b"ip -details link show\n")
            artifact = rv.parse_artifact(f"command-log={path}", self.manifest)
            encoded = json.dumps(artifact)
            self.assertEqual("command-log", artifact["kind"])
            self.assertTrue(artifact["sha256"].startswith("sha256:"))
            self.assertNotIn(directory, encoded)
            self.assertNotIn("ip -details", encoded)

    def test_leak_metric_prevents_certification(self):
        definition = next(item for item in self.manifest["scenarios"] if item["id"] == "gso_netns_real_skb")
        metrics = satisfying_metrics(definition, self.run["budgets"])
        metrics["token_leaks"] = 1
        reasons = rv.evaluate_record(definition, {"metrics": metrics, "artifacts": []}, self.run["budgets"])
        self.assertIn("token_leaks=1 violates eq 0", reasons)

    def test_complete_evidence_can_certify_exact_target_run(self):
        with tempfile.TemporaryDirectory() as directory:
            files = {}
            for kind in self.manifest["allowed_artifact_kinds"]:
                path = Path(directory) / f"{kind}.txt"
                path.write_text(f"synthetic unit-test fixture for {kind}\n", encoding="utf-8")
                files[kind] = path

            for section in ("code_gates", "preflight", "scenarios"):
                definitions = rv.definitions_by_id(self.manifest, section)
                for entry_id, definition in definitions.items():
                    metrics = satisfying_metrics(definition, self.run["budgets"])
                    artifacts = [rv.parse_artifact(f"{kind}={files[kind]}", self.manifest) for kind in definition.get("required_artifacts", [])]
                    record = rv.record_entry(self.run, self.manifest, section, entry_id, "pass", "unit-test fixture", metrics, artifacts, "")
                    self.assertEqual("pass", record["status"], (section, entry_id, record["validation_reasons"]))

            result = rv.certify(self.run, self.manifest)
            self.assertEqual(rv.PASS, result["status"])
            self.assertEqual(set(self.manifest["required_coverage"]), set(result["coverage"]))
            self.assertGreater(result["artifact_count"], 0)

    def test_committed_status_must_not_claim_pass(self):
        status_path = Path(__file__).resolve().parents[2] / "docs" / "validation" / "rst-gso-h10-status.json"
        status = json.loads(status_path.read_text(encoding="utf-8"))
        self.assertEqual(rv.BLOCKED, status["status"])
        self.assertFalse(status["target_evidence_present"])
        self.assertFalse(status["production_ready_claimed"])


if __name__ == "__main__":
    unittest.main()
