#!/usr/bin/env python3
"""Controlled Keenetic/Android field validation for B4 classifier v2.3.

The tool never mutates B4 configuration. It records bounded, privacy-safe
metadata and refuses certification while a mandatory gate is missing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1
STATUSES = {"pending", "pass", "fail", "blocked"}
PREFLIGHT_GATES = (
    "watchdog_disabled",
    "discovery_idle",
    "target_identity_confirmed",
    "other_youtube_clients_idle",
    "clean_restart_confirmed",
    "target_platform",
    "deployed_commit",
    "queue_ready",
    "queue_owner_verified",
    "incoming_progress_visible",
    "processed_mark_verified",
    "offload_clear",
    "known_generation",
    "architecture_known",
    "resource_budgets_defined",
    "runtime_control_available",
    "transactional_apply_enabled",
    "runtime_active_valid",
    "runtime_no_pending",
    "runtime_last_good_available",
)
SENSITIVE_KEY_PARTS = ("client", "flow_id", "source_ip", "source_mac", "destination_ip", "router_url")
FORBIDDEN_KEY_PARTS = ("raw_packet", "packet_bytes", "payload_bytes", "clienthello_bytes", "raw_capture")
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def identifier(value: Any) -> str:
    data = str(value).strip().encode("utf-8", "replace")
    return "sha256:" + hashlib.sha256(data).hexdigest()[:16]


def sanitize_text(value: str) -> str:
    value = MAC_RE.sub("<redacted-mac>", value)
    return IP_RE.sub("<redacted-ip>", value)


def safe_label(value: str) -> str:
    label = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip(".-")
    if not label or label in {".", ".."}:
        raise ValueError("snapshot label is empty or unsafe")
    return label[:96]


def normalize_architecture(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    if normalized in {"arm64", "aarch64"}:
        return "arm64"
    if normalized in {"armv7", "armv7l", "armhf"}:
        return "armv7"
    return normalized


def markdown_cell(value: Any) -> str:
    return sanitize_text(str(value)).replace("|", "\\|").replace("\n", "<br>")


def sanitize(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if any(part in lowered for part in FORBIDDEN_KEY_PARTS):
        return "<excluded>"
    if isinstance(value, dict):
        return {str(k): sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item, key) for item in value]
    if isinstance(value, str):
        if any(part in lowered for part in SENSITIVE_KEY_PARTS):
            return identifier(value)
        return sanitize_text(value)
    return value


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def manifest_path() -> Path:
    return Path(__file__).with_name("manifest.json")


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest = load_json(path or manifest_path())
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported field validation manifest schema")
    scenario_ids = [item.get("id") for item in manifest.get("scenarios", [])]
    if len(scenario_ids) != len(set(scenario_ids)) or not all(scenario_ids):
        raise ValueError("scenario IDs must be unique and non-empty")
    return manifest


def new_run(args: argparse.Namespace, manifest: dict[str, Any]) -> dict[str, Any]:
    budgets = {
        "min_body_bytes": args.min_body_bytes,
        "min_throughput_bps": args.min_throughput_bps,
        "max_cpu_pct": args.max_cpu_pct,
        "max_memory_bytes": args.max_memory_mib * 1024 * 1024 if args.max_memory_mib is not None else None,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": now_utc(),
        "updated_at": now_utc(),
        "target": {
            "router_id": identifier(args.router_url) if args.router_url else "",
            "architecture": args.architecture or "",
            "target_client_id": identifier(args.target_client) if args.target_client else "",
            "expected_generation": args.expected_generation or "",
            "b4_branch": args.branch,
            "b4_commit": args.commit,
        },
        "budgets": budgets,
        "preflight": {"status": "pending", "checked_at": None, "gates": {}},
        "scenarios": {
            item["id"]: {
                "title": item["title"],
                "status": "pending",
                "metrics": {},
                "evidence": [],
                "notes": "",
                "updated_at": None,
            }
            for item in manifest["scenarios"]
        },
        "certification": {"status": "pending", "reasons": [], "checked_at": None},
    }


class APIClient:
    def __init__(self, base_url: str, token: str = "", timeout: float = 8.0, insecure: bool = False) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("router URL must be an absolute http(s) URL")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.context = ssl._create_unverified_context() if insecure else ssl.create_default_context()

    def get(self, endpoint: str) -> Any:
        request = urllib.request.Request(self.base_url + endpoint, method="GET")
        request.add_header("Accept", "application/json")
        if self.token:
            request.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                body = response.read(2 * 1024 * 1024 + 1)
                if len(body) > 2 * 1024 * 1024:
                    raise ValueError(f"response too large for {endpoint}")
                return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", "replace")
            raise RuntimeError(f"GET {endpoint}: HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"GET {endpoint}: {exc}") from exc


def gate(status: str, reason: str, evidence: Any = None) -> dict[str, Any]:
    if status not in {"pass", "fail", "blocked"}:
        raise ValueError("invalid gate status")
    result: dict[str, Any] = {"status": status, "reason": sanitize_text(reason)}
    if evidence is not None:
        result["evidence"] = sanitize(evidence)
    return result


def budgets_defined(budgets: dict[str, Any]) -> bool:
    required = ("min_body_bytes", "min_throughput_bps", "max_cpu_pct", "max_memory_bytes")
    if not all(isinstance(budgets.get(name), (int, float)) and math.isfinite(float(budgets[name])) and budgets[name] > 0 for name in required):
        return False
    return float(budgets["max_cpu_pct"]) <= 100


def evaluate_preflight(
    run: dict[str, Any],
    config: dict[str, Any] | None,
    bundle: dict[str, Any] | None,
    watchdog: dict[str, Any] | None,
    discovery: Any,
    confirmations: dict[str, bool],
    detected_architecture: str,
    errors: dict[str, str] | None = None,
    system_info: dict[str, Any] | None = None,
    version_info: dict[str, Any] | None = None,
    runtime_control: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors = errors or {}
    gates: dict[str, Any] = {}

    if "watchdog" in errors:
        gates["watchdog_disabled"] = gate("blocked", errors["watchdog"])
    else:
        enabled = bool((watchdog or {}).get("enabled"))
        gates["watchdog_disabled"] = gate("fail" if enabled else "pass", "watchdog is active" if enabled else "watchdog disabled")

    if "discovery" in errors:
        gates["discovery_idle"] = gate("blocked", errors["discovery"])
    else:
        idle = discovery is None
        gates["discovery_idle"] = gate("pass" if idle else "fail", "Discovery idle" if idle else "Discovery suite is active")

    for name, label in (
        ("target_identity_confirmed", "target phone identity present"),
        ("other_youtube_clients_idle", "other YouTube clients idle"),
        ("clean_restart_confirmed", "clean B4 restart completed"),
    ):
        ok = bool(confirmations.get(name))
        gates[name] = gate("pass" if ok else "blocked", label if ok else f"operator confirmation required: {label}")

    if "system" in errors:
        gates["target_platform"] = gate("blocked", errors["system"])
    else:
        service = str((system_info or {}).get("service_manager") or "")
        target_os = str((system_info or {}).get("os") or "")
        platform_ok = service == "entware" and target_os == "linux"
        gates["target_platform"] = gate("pass" if platform_ok else "fail", "Keenetic/Entware Linux target confirmed" if platform_ok else "target is not reported as Entware on Linux", system_info or {})

    expected_commit = str(run.get("target", {}).get("b4_commit") or "")
    actual_commit = str((version_info or {}).get("commit") or "")
    if "version" in errors:
        gates["deployed_commit"] = gate("blocked", errors["version"])
    elif not expected_commit or not actual_commit:
        gates["deployed_commit"] = gate("blocked", "deployed commit identity is unavailable")
    else:
        commit_ok = expected_commit.startswith(actual_commit) or actual_commit.startswith(expected_commit)
        gates["deployed_commit"] = gate("pass" if commit_ok else "fail", "deployed commit matches validation run" if commit_ok else "deployed commit differs from validation run", {"expected": expected_commit, "actual": actual_commit})

    queue = (bundle or {}).get("queue") or {}
    if "bundle" in errors:
        for name in ("queue_ready", "queue_owner_verified", "incoming_progress_visible", "processed_mark_verified", "offload_clear"):
            gates[name] = gate("blocked", errors["bundle"])
    else:
        ready = bool(queue.get("ready"))
        owner_value = queue.get("owner_verified")
        incoming_value = queue.get("incoming_progress_visible")
        mark = bool(queue.get("processed_mark_verified"))
        offload_clear = not bool(queue.get("offload_suspected"))
        gates["queue_ready"] = gate("pass" if ready else "fail", queue.get("status") or ("queue ready" if ready else "queue not ready"), queue)
        gates["queue_owner_verified"] = gate("blocked" if owner_value is None else "pass" if bool(owner_value) else "fail", "NFQUEUE owner verified" if owner_value else "NFQUEUE owner not verified or unavailable")
        gates["incoming_progress_visible"] = gate("blocked" if incoming_value is None else "pass" if bool(incoming_value) else "fail", "incoming SYN-ACK/ServerHello progress visible" if incoming_value else "incoming progress visibility not verified or unavailable")
        gates["processed_mark_verified"] = gate("pass" if mark else "fail", "processed mark bypass verified" if mark else "processed mark bypass not verified")
        gates["offload_clear"] = gate("pass" if offload_clear else "fail", "offload visibility clear" if offload_clear else "flow offload bypass suspected")

    expected = str(run.get("target", {}).get("expected_generation") or "")
    actual = str((config or {}).get("runtime_generation") or "")
    if "config" in errors:
        gates["known_generation"] = gate("blocked", errors["config"])
    elif not expected:
        gates["known_generation"] = gate("blocked", "expected config generation is not set")
    elif actual != expected:
        gates["known_generation"] = gate("fail", "runtime generation differs from expected", {"expected": expected, "actual": actual})
    else:
        gates["known_generation"] = gate("pass", "runtime generation matches expected", {"generation": actual})

    configured_arch = normalize_architecture(str(run.get("target", {}).get("architecture") or ""))
    detected = normalize_architecture(detected_architecture)
    arch_ok = bool(configured_arch and detected and configured_arch == detected)
    gates["architecture_known"] = gate(
        "pass" if arch_ok else "blocked" if not configured_arch or not detected else "fail",
        "target architecture confirmed" if arch_ok else "target architecture missing or mismatched",
        {"configured": configured_arch, "detected": detected},
    )

    budget_ok = budgets_defined(run.get("budgets", {}))
    gates["resource_budgets_defined"] = gate("pass" if budget_ok else "blocked", "resource/body/throughput budgets defined" if budget_ok else "set positive CPU, memory, body and throughput budgets")

    if "runtime_control" in errors:
        for name in (
            "runtime_control_available",
            "transactional_apply_enabled",
            "runtime_active_valid",
            "runtime_no_pending",
            "runtime_last_good_available",
        ):
            gates[name] = gate("blocked", errors["runtime_control"])
    else:
        status = runtime_control if isinstance(runtime_control, dict) else {}
        available = bool(status)
        gates["runtime_control_available"] = gate(
            "pass" if available else "blocked",
            "transactional runtime-control endpoint available" if available else "runtime-control status is unavailable",
        )
        enabled = bool(status.get("enabled"))
        gates["transactional_apply_enabled"] = gate(
            "pass" if enabled else "fail" if available else "blocked",
            "transactional runtime apply enabled" if enabled else "transactional runtime apply is disabled",
        )
        active = status.get("active") if isinstance(status.get("active"), dict) else {}
        validation = active.get("validation") if isinstance(active.get("validation"), dict) else {}
        active_valid = bool(active.get("id") and active.get("config_hash") and validation.get("valid"))
        gates["runtime_active_valid"] = gate(
            "pass" if active_valid else "fail" if available else "blocked",
            "active transactional generation is validated" if active_valid else "active transactional generation metadata is missing or invalid",
            {"id": active.get("id"), "config_hash": active.get("config_hash"), "validation": validation},
        )
        pending = status.get("pending")
        gates["runtime_no_pending"] = gate(
            "pass" if pending is None and available else "fail" if available else "blocked",
            "no pending runtime candidate" if pending is None and available else "a runtime candidate is already pending",
            pending if pending is not None else None,
        )
        last_good = status.get("last_good") if isinstance(status.get("last_good"), dict) else {}
        last_good_ok = bool(last_good.get("generation_hash") and last_good.get("config_hash"))
        gates["runtime_last_good_available"] = gate(
            "pass" if last_good_ok else "fail" if available else "blocked",
            "last-good manifest available" if last_good_ok else "last-good manifest is unavailable",
            {"generation_hash": last_good.get("generation_hash"), "config_hash": last_good.get("config_hash")},
        )

    statuses = {entry["status"] for entry in gates.values()}
    status = "fail" if "fail" in statuses else "blocked" if "blocked" in statuses else "pass"
    return {"status": status, "checked_at": now_utc(), "gates": gates}


