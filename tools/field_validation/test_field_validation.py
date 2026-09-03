import argparse
import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("b4_field_validation.py")
SPEC = importlib.util.spec_from_file_location("b4_field_validation", MODULE_PATH)
assert SPEC and SPEC.loader
fv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fv)


def metric_value(name):
    if name in {"evidence_source"}:
        return "source-scoped-dns"
    if name in {"expected_set"}:
        return "youtube-video"
    if name in {"cross_client_leakage"}:
        return False
    if name.endswith("_pass") or name in {"reassembly_completed", "quic_initial_seen", "quic_tcp_handoff", "queue_chains_clean", "clienthello_segment_2_seen"}:
        return True
    if name in {
        "unclassified_first_flows", "queue_drops_delta", "collateral_failures",
        "clean_syn_raw_reinjects", "generated_packet_requeues",
        "retransmission_action_repeats", "post_server_progress_actions",
        "closed_flow_state_entries", "stale_runtime_entries",
        "held_packets_after_restart",
    }:
        return 0
    if name == "actions_per_logical_clienthello":
        return 1
    if name == "clients_observed":
        return 2
    if name == "body_bytes":
        return 2_000_000
    if name == "throughput_bps":
        return 8_000_000
    if name == "cpu_peak_pct":
        return 30
    if name == "memory_peak_bytes":
        return 32 * 1024 * 1024
    if name == "confidence":
        return 90
    if name in {"cdn_switches", "reassembly_bytes", "reassembly_segments", "syn_retries"}:
        return 1
    return 250


class FieldValidationTests(unittest.TestCase):
    def setUp(self):
        self.manifest = fv.load_manifest()
        args = argparse.Namespace(
            router_url="https://192.0.2.1:7000",
            architecture="arm64",
            target_client="mac:aa:bb:cc:dd:ee:ff",
            expected_generation="gen-1",
            branch="agent/classifier-v2.3-capture-envelope",
            commit="deadbeef",
            min_body_bytes=64 * 1024,
            min_throughput_bps=1_000_000,
            max_cpu_pct=75.0,
            max_memory_mib=96.0,
        )
        self.run = fv.new_run(args, self.manifest)

    def test_manifest_covers_stage_36_matrix(self):
        tags = {tag for scenario in self.manifest["scenarios"] for tag in scenario["tags"]}
        self.assertEqual(set(), set(self.manifest["required_coverage"]) - tags)
        self.assertEqual(14, len(self.manifest["scenarios"]))

    def test_preflight_passes_only_with_explicit_gates(self):
        config = {"runtime_generation": "gen-1", "config": {"runtime": {"confidence": {"classify": 50}}}}
        bundle = {"queue": {"ready": True, "owner_verified": True, "incoming_progress_visible": True, "processed_mark_verified": True, "offload_suspected": False, "status": "ready"}}
        result = fv.evaluate_preflight(
            self.run,
            config,
            bundle,
            {"enabled": False},
            None,
            {"target_identity_confirmed": True, "other_youtube_clients_idle": True, "clean_restart_confirmed": True},
            "aarch64",
            system_info={"service_manager": "entware", "os": "linux", "arch": "arm64"},
            version_info={"commit": "deadbeef"},
            runtime_control={
                "enabled": True,
                "active": {"id": "active-1", "config_hash": "cfg-1", "validation": {"valid": True}},
                "pending": None,
                "last_good": {"generation_hash": "active-1", "config_hash": "cfg-1"},
            },
        )
        self.assertEqual("pass", result["status"])
        self.assertTrue(all(item["status"] == "pass" for item in result["gates"].values()))

    def test_preflight_blocks_unknown_generation_and_budget(self):
        self.run["target"]["expected_generation"] = ""
        self.run["budgets"]["max_cpu_pct"] = None
        result = fv.evaluate_preflight(
            self.run,
            {"runtime_generation": "gen-2"},
            {"queue": {"ready": True, "owner_verified": True, "incoming_progress_visible": True, "processed_mark_verified": True, "offload_suspected": False}},
            {"enabled": False},
            None,
            {"target_identity_confirmed": True, "other_youtube_clients_idle": True, "clean_restart_confirmed": True},
            "arm64",
            system_info={"service_manager": "entware", "os": "linux", "arch": "arm64"},
            version_info={"commit": "deadbeef"},
            runtime_control={
                "enabled": True,
                "active": {"id": "active-1", "config_hash": "cfg-1", "validation": {"valid": True}},
                "pending": None,
                "last_good": {"generation_hash": "active-1", "config_hash": "cfg-1"},
            },
        )
        self.assertEqual("blocked", result["status"])

    def test_certification_passes_complete_bounded_run(self):
        self.run["preflight"] = {"status": "pass", "gates": {}, "snapshot": {"classify_threshold": 50}}
        for scenario in self.manifest["scenarios"]:
            self.run["scenarios"][scenario["id"]] = {
                "title": scenario["title"],
                "status": "pass",
                "metrics": {name: metric_value(name) for name in scenario["required_metrics"]},
                "evidence": [],
                "notes": "",
            }
        result = fv.certify(self.run, self.manifest)
        self.assertEqual("pass", result["status"], result["reasons"])
        self.assertTrue(set(self.manifest["required_coverage"]).issubset(set(result["coverage"])))

    def test_certification_rejects_repeated_action_and_cross_client_leak(self):
        self.run["preflight"] = {"status": "pass", "gates": {}, "snapshot": {"classify_threshold": 50}}
        for scenario in self.manifest["scenarios"]:
            metrics = {name: metric_value(name) for name in scenario["required_metrics"]}
            self.run["scenarios"][scenario["id"]].update(status="pass", metrics=metrics)
        self.run["scenarios"]["official_youtube_cold_start"]["metrics"]["actions_per_logical_clienthello"] = 2
        self.run["scenarios"]["second_client_simultaneous_lookup"]["metrics"]["cross_client_leakage"] = True
        result = fv.certify(self.run, self.manifest)
        self.assertEqual("fail", result["status"])
        self.assertTrue(any("actions_per_logical" in reason for reason in result["reasons"]))
        self.assertTrue(any("cross-client" in reason for reason in result["reasons"]))

    def test_preflight_blocks_missing_or_pending_runtime_control(self):
        base = dict(
            config={"runtime_generation": "gen-1"},
            bundle={"queue": {"ready": True, "owner_verified": True, "incoming_progress_visible": True, "processed_mark_verified": True, "offload_suspected": False}},
            watchdog={"enabled": False},
            discovery=None,
            confirmations={"target_identity_confirmed": True, "other_youtube_clients_idle": True, "clean_restart_confirmed": True},
            detected_architecture="arm64",
            system_info={"service_manager": "entware", "os": "linux", "arch": "arm64"},
            version_info={"commit": "deadbeef"},
        )
        missing = fv.evaluate_preflight(self.run, errors={"runtime_control": "HTTP 404"}, **base)
        self.assertEqual("blocked", missing["status"])
        pending = fv.evaluate_preflight(
            self.run,
            runtime_control={
                "enabled": True,
                "active": {"id": "active-1", "config_hash": "cfg-1", "validation": {"valid": True}},
                "pending": {"generation": {"id": "candidate-1"}},
                "last_good": {"generation_hash": "active-1", "config_hash": "cfg-1"},
            },
            **base,
        )
        self.assertEqual("fail", pending["status"])
        self.assertEqual("fail", pending["gates"]["runtime_no_pending"]["status"])

    def test_privacy_sanitizer_excludes_raw_and_hashes_identifiers(self):
        value = fv.sanitize({
            "client_id": "phone-one",
            "source_ip": "192.168.1.25",
            "raw_packet": "secret",
            "note": "peer 192.168.1.25 aa:bb:cc:dd:ee:ff",
        })
        self.assertTrue(value["client_id"].startswith("sha256:"))
        self.assertTrue(value["source_ip"].startswith("sha256:"))
        self.assertEqual("<excluded>", value["raw_packet"])
        self.assertNotIn("192.168.1.25", value["note"])
        self.assertNotIn("aa:bb:cc:dd:ee:ff", value["note"])


    def test_http_preflight_end_to_end(self):
        responses = {
            "/api/v2/classifier/config": {"runtime_generation": "gen-1", "api_version": "b4.classifier.v2.3", "schema_version": 52, "config": {"runtime": {"confidence": {"classify": 50}}}},
            "/api/diagnostics/issue-bundle": {"queue": {"ready": True, "processed_mark_verified": True, "offload_suspected": False, "status": "ready"}},
            "/api/watchdog/status": {"enabled": False, "domains": []},
            "/api/discovery/current": None,
            "/api/system/info": {"service_manager": "entware", "os": "linux", "arch": "arm64"},
            "/api/version": {"commit": "deadbeef", "version": "test"},
            "/api/system/diagnostics": {"data": {"system": {"kernel": "5.10-test"}, "firewall": {"capture_envelope": {"queue_ready": True, "owner_verified": True, "incoming_progress_visible": True, "processed_mark_verified": True, "flow_offload_bypass_suspected": False, "queue_drop": 0, "user_drop": 0, "status": "ready"}}}},
            "/api/v2/runtime-control/status": {"enabled": True, "active": {"id": "active-1", "config_hash": "cfg-1", "validation": {"valid": True}}, "pending": None, "last_good": {"generation_hash": "active-1", "config_hash": "cfg-1"}},
        }

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path not in responses:
                    self.send_response(404)
                    self.end_headers()
                    return
                body = json.dumps(responses[self.path]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                run_path = Path(directory) / "run.json"
                fv.save_run(run_path, self.run)
                args = argparse.Namespace(
                    run=str(run_path),
                    router_url=f"http://127.0.0.1:{server.server_port}",
                    token="",
                    timeout=2.0,
                    insecure=False,
                    detected_architecture=None,
                    target_identity_confirmed=True,
                    other_clients_idle=True,
                    clean_restart_confirmed=True,
                )
                self.assertEqual(0, fv.command_preflight(args))
                checked = fv.load_json(run_path)
                self.assertEqual("pass", checked["preflight"]["status"])
                self.assertEqual("5.10-test", checked["preflight"]["snapshot"]["kernel"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_atomic_run_roundtrip_and_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.json"
            fv.save_run(path, self.run)
            loaded = fv.load_json(path)
            report = fv.markdown_report(loaded, self.manifest)
            self.assertIn("Android scenarios", report)
            self.assertIn("official_youtube_cold_start", report)
            self.assertFalse(path.with_suffix(".json.tmp").exists())


if __name__ == "__main__":
    unittest.main()
