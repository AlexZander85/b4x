from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

from field_common import (
    APIClient,
    SCHEMA_VERSION,
    STATUSES,
    evaluate_preflight,
    identifier,
    load_json,
    load_manifest,
    new_run,
    normalize_architecture,
    now_utc,
    safe_label,
    sanitize,
    sanitize_text,
    write_json,
)
from field_evaluation import (
    certify,
    counter_delta,
    evaluate_scenario,
    markdown_report,
)


def save_run(path: Path, run: dict[str, Any]) -> None:
    run["updated_at"] = now_utc()
    write_json(path, run)


def command_init(args: argparse.Namespace) -> int:
    path = Path(args.run)
    if path.exists() and not args.force:
        raise FileExistsError(f"run file already exists: {path}")
    manifest = load_manifest(Path(args.manifest) if args.manifest else None)
    run = new_run(args, manifest)
    save_run(path, run)
    print(path)
    return 0


def fetch_optional(client: APIClient, endpoint: str, name: str, values: dict[str, Any], errors: dict[str, str]) -> None:
    try:
        values[name] = client.get(endpoint)
    except RuntimeError as exc:
        values[name] = None
        errors[name] = str(exc)


def command_preflight(args: argparse.Namespace) -> int:
    path = Path(args.run)
    run = load_json(path)
    client = APIClient(args.router_url, args.token or os.getenv("B4_API_TOKEN", ""), args.timeout, args.insecure)
    values: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for endpoint, name in (
        ("/api/v2/classifier/config", "config"),
        ("/api/diagnostics/issue-bundle", "bundle"),
        ("/api/watchdog/status", "watchdog"),
        ("/api/discovery/current", "discovery"),
        ("/api/system/info", "system"),
        ("/api/version", "version"),
        ("/api/system/diagnostics", "diagnostics"),
    ):
        fetch_optional(client, endpoint, name, values, errors)

    diagnostics = values.get("diagnostics") or {}
    diagnostics_data = diagnostics.get("data") or {}
    capture = ((diagnostics_data.get("firewall") or {}).get("capture_envelope") or {})
    bundle = dict(values.get("bundle") or {})
    queue = dict(bundle.get("queue") or {})
    if capture:
        queue.update({
            "ready": capture.get("queue_ready", queue.get("ready")),
            "owner_verified": capture.get("owner_verified"),
            "incoming_progress_visible": capture.get("incoming_progress_visible"),
            "processed_mark_verified": capture.get("processed_mark_verified", queue.get("processed_mark_verified")),
            "offload_suspected": capture.get("flow_offload_bypass_suspected", queue.get("offload_suspected")),
            "queue_drops": capture.get("queue_drop", queue.get("queue_drops")),
            "user_drops": capture.get("user_drop", queue.get("user_drops")),
            "status": capture.get("status", queue.get("status")),
        })
    bundle["queue"] = queue
    detected_arch = args.detected_architecture or str((values.get("system") or {}).get("arch") or "")
    confirmations = {
        "target_identity_confirmed": args.target_identity_confirmed,
        "other_youtube_clients_idle": args.other_clients_idle,
        "clean_restart_confirmed": args.clean_restart_confirmed,
    }
    preflight = evaluate_preflight(run, values.get("config"), bundle, values.get("watchdog"), values.get("discovery"), confirmations, detected_arch, errors, values.get("system"), values.get("version"))
    config_runtime = ((values.get("config") or {}).get("config") or {}).get("runtime") or {}
    preflight["snapshot"] = {
        "api_version": (values.get("config") or {}).get("api_version"),
        "schema_version": (values.get("config") or {}).get("schema_version"),
        "runtime_generation": (values.get("config") or {}).get("runtime_generation"),
        "classify_threshold": ((config_runtime.get("confidence") or {}).get("classify")),
        "queue": sanitize(queue),
        "detected_architecture": normalize_architecture(detected_arch),
        "kernel": ((diagnostics_data.get("system") or {}).get("kernel")),
        "service_manager": ((values.get("system") or {}).get("service_manager")),
        "deployed_commit": ((values.get("version") or {}).get("commit")),
        "errors": sanitize(errors),
    }
    run["preflight"] = preflight
    save_run(path, run)
    print(preflight["status"])
    return 0 if preflight["status"] == "pass" else 2


def command_snapshot(args: argparse.Namespace) -> int:
    run_path = Path(args.run)
    run = load_json(run_path)
    client = APIClient(args.router_url, args.token or os.getenv("B4_API_TOKEN", ""), args.timeout, args.insecure)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "label": safe_label(args.label),
        "captured_at": now_utc(),
        "router_id": identifier(args.router_url),
        "issue_bundle": sanitize(client.get("/api/diagnostics/issue-bundle")),
        "metrics": sanitize(client.get("/api/observability/metrics")),
    }
    target = Path(args.output) if args.output else run_path.parent / "snapshots" / f"{args.label}.json"
    write_json(target, snapshot)
    run.setdefault("snapshots", []).append({"label": snapshot["label"], "path": str(target), "captured_at": snapshot["captured_at"], "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    save_run(run_path, run)
    print(target)
    return 0


def parse_metrics(args: argparse.Namespace) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    if args.metrics_json:
        loaded = load_json(Path(args.metrics_json))
        if not isinstance(loaded, dict):
            raise ValueError("metrics JSON must be an object")
        metrics.update(loaded)
    for item in args.metric or []:
        if "=" not in item:
            raise ValueError(f"invalid --metric {item!r}; expected name=value")
        name, raw = item.split("=", 1)
        name = name.strip()
        raw = raw.strip()
        if not name:
            raise ValueError("metric name is empty")
        try:
            value: Any = json.loads(raw)
        except json.JSONDecodeError:
            value = raw
        metrics[name] = value
    return sanitize(metrics)


def command_record(args: argparse.Namespace) -> int:
    path = Path(args.run)
    run = load_json(path)
    manifest = load_manifest(Path(args.manifest) if args.manifest else None)
    scenario_defs = {item["id"]: item for item in manifest["scenarios"]}
    if args.scenario not in scenario_defs:
        raise ValueError(f"unknown scenario: {args.scenario}")
    if args.status not in STATUSES - {"pending"}:
        raise ValueError("record status must be pass, fail or blocked")
    result = run["scenarios"][args.scenario]
    result.update({
        "status": args.status,
        "metrics": parse_metrics(args),
        "notes": sanitize_text(args.notes or ""),
        "evidence": [identifier(item) for item in (args.evidence or [])],
        "updated_at": now_utc(),
    })
    if args.before and args.after:
        before = load_json(Path(args.before)).get("metrics") or {}
        after = load_json(Path(args.after)).get("metrics") or {}
        result["counter_deltas"] = counter_delta(before, after)
    violations = evaluate_scenario(scenario_defs[args.scenario], result, run)
    result["validation_reasons"] = violations
    if args.status == "pass" and violations:
        result["status"] = "fail"
    run["certification"] = {"status": "pending", "reasons": [], "checked_at": None}
    save_run(path, run)
    print(result["status"])
    return 0 if result["status"] == "pass" else 2


def command_certify(args: argparse.Namespace) -> int:
    path = Path(args.run)
    run = load_json(path)
    manifest = load_manifest(Path(args.manifest) if args.manifest else None)
    run["certification"] = certify(run, manifest)
    save_run(path, run)
    if args.markdown:
        Path(args.markdown).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown).write_text(markdown_report(run, manifest), encoding="utf-8", newline="\n")
    print(run["certification"]["status"])
    return 0 if run["certification"]["status"] == "pass" else 2


def command_report(args: argparse.Namespace) -> int:
    run = load_json(Path(args.run))
    manifest = load_manifest(Path(args.manifest) if args.manifest else None)
    report = markdown_report(run, manifest)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(report, encoding="utf-8", newline="\n")
    else:
        print(report)
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--manifest", help="override scenario manifest")
    commands = root.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a controlled validation run")
    init.add_argument("--run", required=True)
    init.add_argument("--router-url", required=True)
    init.add_argument("--architecture", required=True, choices=("armv7", "arm64"))
    init.add_argument("--target-client", required=True)
    init.add_argument("--expected-generation", required=True)
    init.add_argument("--branch", default="agent/classifier-v2.3-capture-envelope")
    init.add_argument("--commit", required=True)
    init.add_argument("--min-body-bytes", type=int)
    init.add_argument("--min-throughput-bps", type=int)
    init.add_argument("--max-cpu-pct", type=float)
    init.add_argument("--max-memory-mib", type=float)
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=command_init)

    for name in ("preflight", "snapshot"):
        item = commands.add_parser(name)
        item.add_argument("--run", required=True)
        item.add_argument("--router-url", required=True)
        item.add_argument("--token", default="")
        item.add_argument("--timeout", type=float, default=8.0)
        item.add_argument("--insecure", action="store_true")
        if name == "preflight":
            item.add_argument("--detected-architecture")
            item.add_argument("--target-identity-confirmed", action="store_true")
            item.add_argument("--other-clients-idle", action="store_true")
            item.add_argument("--clean-restart-confirmed", action="store_true")
            item.set_defaults(func=command_preflight)
        else:
            item.add_argument("--label", required=True)
            item.add_argument("--output")
            item.set_defaults(func=command_snapshot)

    record = commands.add_parser("record", help="record one Android scenario")
    record.add_argument("--run", required=True)
    record.add_argument("--scenario", required=True)
    record.add_argument("--status", required=True, choices=("pass", "fail", "blocked"))
    record.add_argument("--metrics-json")
    record.add_argument("--metric", action="append")
    record.add_argument("--evidence", action="append")
    record.add_argument("--notes")
    record.add_argument("--before")
    record.add_argument("--after")
    record.set_defaults(func=command_record)

    certify_cmd = commands.add_parser("certify", help="fail closed unless every target gate passes")
    certify_cmd.add_argument("--run", required=True)
    certify_cmd.add_argument("--markdown")
    certify_cmd.set_defaults(func=command_certify)

    report = commands.add_parser("report", help="render the target test table")
    report.add_argument("--run", required=True)
    report.add_argument("--output")
    report.set_defaults(func=command_report)
    return root


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"field-validation: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
