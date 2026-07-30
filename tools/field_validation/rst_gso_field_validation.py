#!/usr/bin/env python3
"""Fail-closed H10 target validation for B4 RST/GSO hardening.

The harness never claims target success from workstation tests. Raw evidence stays
outside the run JSON; only kind, basename, size and SHA-256 are recorded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from pathlib import Path
from typing import Any, Iterable

_MODULE_DIR = str(Path(__file__).resolve().parent)
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

from field_common import (  # noqa: E402
    APIClient,
    identifier,
    markdown_cell,
    now_utc,
    safe_label,
    sanitize,
    sanitize_text,
    write_json,
)

SCHEMA_VERSION = 1
PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED_TARGET_VALIDATION"
RECORD_STATUSES = {"pass", "fail", "blocked"}
MAX_HASH_BYTES = 8 * 1024 * 1024 * 1024


def default_manifest_path() -> Path:
    return Path(__file__).with_name("rst_gso_manifest.json")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest = load_json(path or default_manifest_path())
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("stage") != "H10":
        raise ValueError("unsupported RST/GSO H10 manifest")
    scenarios = manifest.get("scenarios") or []
    ids = [str(item.get("id") or "") for item in scenarios]
    if not ids or any(not value for value in ids) or len(ids) != len(set(ids)):
        raise ValueError("scenario IDs must be non-empty and unique")
    suites = {item.get("suite") for item in scenarios}
    if suites != {"gso", "passive_rst", "combined"}:
        raise ValueError(f"manifest suites are incomplete: {sorted(str(v) for v in suites)}")
    allowed = set(manifest.get("allowed_artifact_kinds") or [])
    if not allowed:
        raise ValueError("allowed artifact kinds are missing")
    for section in (manifest.get("required_code_gates") or []) + (manifest.get("required_preflight") or []) + scenarios:
        for kind in section.get("required_artifacts") or []:
            if kind not in allowed:
                raise ValueError(f"unsupported artifact kind {kind!r} in {section.get('id')}")
    tags = {tag for scenario in scenarios for tag in scenario.get("tags", [])}
    if set(manifest.get("required_coverage") or []) != tags:
        raise ValueError("required_coverage must exactly equal scenario tags")
    return manifest


def finite_positive(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)) and value > 0


def finite_non_negative(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)) and value >= 0


def validate_budgets(budgets: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for name in ("max_cpu_pct", "max_memory_bytes", "min_throughput_bps"):
        value = budgets.get(name)
        if not finite_positive(value):
            reasons.append(f"budget {name} must be a finite positive value")
    for name in ("max_queue_drops", "max_latency_regression_pct"):
        value = budgets.get(name)
        if not finite_non_negative(value):
            reasons.append(f"budget {name} must be a finite non-negative value")
    if finite_positive(budgets.get("max_cpu_pct")) and float(budgets["max_cpu_pct"]) > 100:
        reasons.append("max_cpu_pct must be <= 100")
    return reasons


def empty_record(title: str = "") -> dict[str, Any]:
    return {
        "title": title,
        "status": "pending",
        "reason": "",
        "metrics": {},
        "artifacts": [],
        "notes": "",
        "updated_at": None,
        "validation_reasons": [],
    }


def new_run(args: argparse.Namespace, manifest: dict[str, Any]) -> dict[str, Any]:
    budgets = {
        "max_cpu_pct": args.max_cpu_pct,
        "max_memory_bytes": int(args.max_memory_mib * 1024 * 1024) if args.max_memory_mib is not None else None,
        "max_queue_drops": args.max_queue_drops,
        "min_throughput_bps": args.min_throughput_bps,
        "max_latency_regression_pct": args.max_latency_regression_pct,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "stage": "H10",
        "created_at": now_utc(),
        "updated_at": now_utc(),
        "target": {
            "router_id": identifier(args.router_url),
            "architecture": args.architecture,
            "target_client_id": identifier(args.target_client),
            "expected_generation": args.expected_generation,
            "b4_branch": args.branch,
            "b4_commit": args.commit,
        },
        "budgets": budgets,
        "code_gates": {item["id"]: empty_record(item["id"]) for item in manifest["required_code_gates"]},
        "preflight": {item["id"]: empty_record(item["id"]) for item in manifest["required_preflight"]},
        "scenarios": {item["id"]: empty_record(item["title"]) for item in manifest["scenarios"]},
        "snapshots": [],
        "certification": {
            "status": BLOCKED,
            "reasons": ["target Keenetic and Android/Chrome evidence has not been recorded"],
            "checked_at": now_utc(),
            "coverage": [],
        },
    }


def save_run(path: Path, run: dict[str, Any]) -> None:
    run["updated_at"] = now_utc()
    write_json(path, run)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_HASH_BYTES:
                raise ValueError(f"artifact exceeds {MAX_HASH_BYTES} bytes: {path.name}")
            digest.update(chunk)
    return digest.hexdigest()


def parse_artifact(spec: str, manifest: dict[str, Any]) -> dict[str, Any]:
    if "=" not in spec:
        raise ValueError(f"invalid artifact {spec!r}; expected kind=path")
    kind, raw_path = spec.split("=", 1)
    kind = kind.strip()
    if kind not in set(manifest["allowed_artifact_kinds"]):
        raise ValueError(f"artifact kind {kind!r} is not allowed")
    path = Path(raw_path).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"artifact must be a regular non-symlink file: {path}")
    size = path.stat().st_size
    if size <= 0:
        raise ValueError(f"artifact is empty: {path.name}")
    return {
        "kind": kind,
        "name": safe_label(path.name),
        "bytes": size,
        "sha256": "sha256:" + sha256_file(path),
        "recorded_at": now_utc(),
    }


def parse_artifacts(values: list[str] | None, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    records = [parse_artifact(value, manifest) for value in values or []]
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, Any]] = []
    for record in records:
        key = (record["kind"], record["sha256"])
        if key not in seen:
            seen.add(key)
            result.append(record)
    return result


def parse_metrics(path: str | None, pairs: list[str] | None) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    if path:
        value = load_json(Path(path))
        if not isinstance(value, dict):
            raise ValueError("metrics JSON must be an object")
        metrics.update(value)
    for pair in pairs or []:
        if "=" not in pair:
            raise ValueError(f"invalid metric {pair!r}; expected name=value")
        name, raw = pair.split("=", 1)
        name = name.strip()
        if not name:
            raise ValueError("metric name is empty")
        try:
            value: Any = json.loads(raw)
        except json.JSONDecodeError:
            value = raw.strip()
        metrics[name] = value
    return sanitize(metrics)


def artifact_kinds(record: dict[str, Any]) -> set[str]:
    return {str(item.get("kind") or "") for item in record.get("artifacts") or []}


def truth(value: Any) -> bool:
    if value is True or value == 1:
        return True
    return isinstance(value, str) and value.strip().lower() in {"true", "yes", "pass", "passed"}


def number(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return None


def evaluate_assertion(assertion: dict[str, Any], metrics: dict[str, Any], budgets: dict[str, Any]) -> str | None:
    metric = str(assertion.get("metric") or "")
    if metric not in metrics:
        return f"missing metric: {metric}"
    value = metrics[metric]
    op = assertion.get("op")
    expected = assertion.get("value")
    if op == "true":
        return None if truth(value) else f"{metric} must be true"
    if op == "false":
        return None if not truth(value) else f"{metric} must be false"
    current = number(value)
    if current is None:
        return f"{metric} must be a finite number for {op}"
    if op in {"lte_budget", "gte_budget"}:
        budget_name = str(assertion.get("budget") or "")
        expected = budgets.get(budget_name)
        if number(expected) is None:
            return f"budget {budget_name} is unavailable"
    expected_number = number(expected)
    if expected_number is None:
        return f"assertion value for {metric} is invalid"
    checks = {
        "eq": current == expected_number,
        "neq": current != expected_number,
        "lte": current <= expected_number,
        "gte": current >= expected_number,
        "lte_budget": current <= expected_number,
        "gte_budget": current >= expected_number,
    }
    if op not in checks:
        return f"unsupported assertion op: {op}"
    if checks[op]:
        return None
    return f"{metric}={current:g} violates {op} {expected_number:g}"


def evaluate_record(definition: dict[str, Any], record: dict[str, Any], budgets: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    metrics = record.get("metrics") or {}
    for name in definition.get("required_metrics") or []:
        if name not in metrics or metrics[name] in (None, ""):
            reasons.append(f"missing metric: {name}")
    missing_artifacts = sorted(set(definition.get("required_artifacts") or []) - artifact_kinds(record))
    if missing_artifacts:
        reasons.append("missing artifact kinds: " + ", ".join(missing_artifacts))
    for name, value in metrics.items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if not math.isfinite(float(value)):
                reasons.append(f"{name} must be finite")
    for assertion in definition.get("assertions") or []:
        failure = evaluate_assertion(assertion, metrics, budgets)
        if failure and failure not in reasons:
            reasons.append(failure)
    return reasons


def definitions_by_id(manifest: dict[str, Any], section: str) -> dict[str, dict[str, Any]]:
    key = {"code_gates": "required_code_gates", "preflight": "required_preflight", "scenarios": "scenarios"}[section]
    return {item["id"]: item for item in manifest[key]}


def record_entry(
    run: dict[str, Any], manifest: dict[str, Any], section: str, entry_id: str, status: str,
    reason: str, metrics: dict[str, Any], artifacts: list[dict[str, Any]], notes: str,
) -> dict[str, Any]:
    definitions = definitions_by_id(manifest, section)
    if entry_id not in definitions:
        raise ValueError(f"unknown {section} entry: {entry_id}")
    if status not in RECORD_STATUSES:
        raise ValueError("status must be pass, fail or blocked")
    record = run[section][entry_id]
    record.update({
        "status": status,
        "reason": sanitize_text(reason),
        "metrics": metrics,
        "artifacts": artifacts,
        "notes": sanitize_text(notes),
        "updated_at": now_utc(),
    })
    violations = evaluate_record(definitions[entry_id], record, run.get("budgets") or {})
    record["validation_reasons"] = violations
    if status == "pass" and violations:
        record["status"] = "fail"
    run["certification"] = {
        "status": BLOCKED,
        "reasons": ["certification must be recomputed after evidence changes"],
        "checked_at": now_utc(),
        "coverage": [],
    }
    return record


def certify(run: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    reasons = validate_budgets(run.get("budgets") or {})
    failed = bool(reasons)
    blocked = False
    coverage: set[str] = set()
    artifact_hashes: set[str] = set()

    for section in ("code_gates", "preflight", "scenarios"):
        definitions = definitions_by_id(manifest, section)
        records = run.get(section) or {}
        for entry_id, definition in definitions.items():
            record = records.get(entry_id)
            if not record:
                blocked = True
                reasons.append(f"missing {section} entry: {entry_id}")
                continue
            status = record.get("status")
            if status == "fail":
                failed = True
                reasons.append(f"{section} {entry_id} is FAIL")
            elif status != "pass":
                blocked = True
                reasons.append(f"{section} {entry_id} is {status or 'pending'}")
            violations = evaluate_record(definition, record, run.get("budgets") or {})
            if status == "pass" and violations:
                failed = True
                reasons.extend(f"{section} {entry_id}: {item}" for item in violations)
            if status == "pass" and not violations and section == "scenarios":
                coverage.update(definition.get("tags") or [])
            for artifact in record.get("artifacts") or []:
                value = str(artifact.get("sha256") or "")
                if value:
                    artifact_hashes.add(value)

    missing_coverage = sorted(set(manifest.get("required_coverage") or []) - coverage)
    if missing_coverage:
        blocked = True
        reasons.append("missing coverage: " + ", ".join(missing_coverage))
    if not artifact_hashes:
        blocked = True
        reasons.append("no raw artifact hashes recorded")

    status = FAIL if failed else BLOCKED if blocked else PASS
    return {
        "status": status,
        "reasons": reasons,
        "checked_at": now_utc(),
        "coverage": sorted(coverage),
        "artifact_count": len(artifact_hashes),
        "run_hash": identifier(json.dumps({
            "target": run.get("target"),
            "budgets": run.get("budgets"),
            "code_gates": run.get("code_gates"),
            "preflight": run.get("preflight"),
            "scenarios": run.get("scenarios"),
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)),
    }


def markdown_report(run: dict[str, Any], manifest: dict[str, Any]) -> str:
    certification = run.get("certification") or {}
    lines = [
        "# B4 H10 — RST/GSO combined target validation",
        "",
        f"- Updated: `{run.get('updated_at', '—')}`",
        f"- Target architecture: `{run.get('target', {}).get('architecture', 'unknown')}`",
        f"- B4 commit: `{run.get('target', {}).get('b4_commit', 'unknown')}`",
        f"- Config generation: `{run.get('target', {}).get('expected_generation', 'unknown')}`",
        f"- Verdict: **{certification.get('status', BLOCKED)}**",
        f"- Raw artifacts indexed: `{certification.get('artifact_count', 0)}`",
        "",
        "> A workstation or CI run cannot certify Keenetic/Android behavior. PASS is valid only when every target gate, scenario and raw artifact requirement is satisfied for this exact commit and generation.",
        "",
    ]
    for section, title, manifest_key in (
        ("code_gates", "Code gates", "required_code_gates"),
        ("preflight", "Target preflight", "required_preflight"),
    ):
        lines.extend([f"## {title}", "", "| Gate | Status | Artifacts | Reason |", "|---|---:|---:|---|"])
        for definition in manifest[manifest_key]:
            record = (run.get(section) or {}).get(definition["id"], {})
            lines.append(
                f"| `{definition['id']}` | {str(record.get('status', 'pending')).upper()} | {len(record.get('artifacts') or [])} | {markdown_cell(record.get('reason', ''))} |"
            )
        lines.append("")

    for suite, title in (("gso", "GSO kernel/integration matrix"), ("passive_rst", "Passive RST matrix"), ("combined", "Combined scenarios")):
        lines.extend([f"## {title}", "", "| Scenario | Status | Artifacts | Validation |", "|---|---:|---:|---|"])
        for definition in manifest["scenarios"]:
            if definition["suite"] != suite:
                continue
            record = (run.get("scenarios") or {}).get(definition["id"], {})
            validation = "; ".join(record.get("validation_reasons") or [])
            lines.append(
                f"| `{definition['id']}` | {str(record.get('status', 'pending')).upper()} | {len(record.get('artifacts') or [])} | {markdown_cell(validation)} |"
            )
        lines.append("")

    lines.extend(["## Verdict reasons", ""])
    lines.extend([f"- {sanitize_text(str(reason))}" for reason in certification.get("reasons") or []] or ["- None"])
    lines.extend([
        "",
        "## Artifact policy",
        "",
        "- Run JSON and Markdown contain only artifact kind, basename, byte size and SHA-256.",
        "- Packet captures, Android logs, Chrome traces and raw router commands remain in the operator-controlled artifact directory.",
        "- Public bundles must use the existing sanitizer; raw ClientHello and packet payloads are opt-in local evidence only.",
        "- Any new commit, config generation, kernel/offload state or router model requires a new H10 run.",
        "",
    ])
    return "\n".join(lines)


def command_init(args: argparse.Namespace) -> int:
    path = Path(args.run)
    if path.exists() and not args.force:
        raise ValueError(f"run already exists: {path}")
    manifest = load_manifest(Path(args.manifest) if args.manifest else None)
    run = new_run(args, manifest)
    save_run(path, run)
    print(BLOCKED)
    return 0


def command_snapshot(args: argparse.Namespace) -> int:
    run_path = Path(args.run)
    run = load_json(run_path)
    client = APIClient(args.router_url, args.token or os.getenv("B4_API_TOKEN", ""), args.timeout, args.insecure)
    endpoints = {
        "hardening": "/api/v2/classifier/hardening",
        "metrics": "/api/observability/metrics",
        "issue_bundle": "/api/diagnostics/issue-bundle",
        "runtime_control": "/api/v2/runtime-control/status",
        "system": "/api/system/info",
        "version": "/api/version",
    }
    values: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name, endpoint in endpoints.items():
        try:
            values[name] = client.get(endpoint)
        except RuntimeError as exc:
            errors[name] = str(exc)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "stage": "H10",
        "label": safe_label(args.label),
        "captured_at": now_utc(),
        "router_id": identifier(args.router_url),
        "values": sanitize(values),
        "errors": sanitize(errors),
    }
    target = Path(args.output) if args.output else run_path.parent / "snapshots" / f"{snapshot['label']}.json"
    write_json(target, snapshot)
    run.setdefault("snapshots", []).append({
        "label": snapshot["label"],
        "captured_at": snapshot["captured_at"],
        "name": safe_label(target.name),
        "bytes": target.stat().st_size,
        "sha256": "sha256:" + sha256_file(target),
    })
    save_run(run_path, run)
    print(target)
    return 0 if not errors else 2


def command_record(args: argparse.Namespace, section: str) -> int:
    path = Path(args.run)
    run = load_json(path)
    manifest = load_manifest(Path(args.manifest) if args.manifest else None)
    entry_id = getattr(args, "entry_id")
    record = record_entry(
        run, manifest, section, entry_id, args.status, args.reason or "",
        parse_metrics(args.metrics_json, args.metric), parse_artifacts(args.artifact, manifest), args.notes or "",
    )
    save_run(path, run)
    print(record["status"])
    return 0 if record["status"] == "pass" else 2


def command_certify(args: argparse.Namespace) -> int:
    path = Path(args.run)
    run = load_json(path)
    manifest = load_manifest(Path(args.manifest) if args.manifest else None)
    run["certification"] = certify(run, manifest)
    save_run(path, run)
    if args.markdown:
        output = Path(args.markdown)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(markdown_report(run, manifest), encoding="utf-8", newline="\n")
    print(run["certification"]["status"])
    return 0 if run["certification"]["status"] == PASS else 2


def command_report(args: argparse.Namespace) -> int:
    run = load_json(Path(args.run))
    manifest = load_manifest(Path(args.manifest) if args.manifest else None)
    report = markdown_report(run, manifest)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8", newline="\n")
    else:
        print(report)
    return 0


def command_validate_manifest(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest) if args.manifest else None)
    suites: dict[str, int] = {}
    for scenario in manifest["scenarios"]:
        suites[scenario["suite"]] = suites.get(scenario["suite"], 0) + 1
    print(json.dumps({"status": PASS, "scenarios": len(manifest["scenarios"]), "suites": suites}, sort_keys=True))
    return 0


def add_record_arguments(parser: argparse.ArgumentParser, id_name: str) -> None:
    parser.add_argument("--run", required=True)
    parser.add_argument(f"--{id_name}", dest="entry_id", required=True)
    parser.add_argument("--status", required=True, choices=sorted(RECORD_STATUSES))
    parser.add_argument("--reason")
    parser.add_argument("--metrics-json")
    parser.add_argument("--metric", action="append")
    parser.add_argument("--artifact", action="append", help="kind=path; raw file is hashed but not copied")
    parser.add_argument("--notes")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--manifest", help="override H10 manifest")
    commands = root.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a blocked target-validation run")
    init.add_argument("--run", required=True)
    init.add_argument("--router-url", required=True)
    init.add_argument("--architecture", required=True, choices=("armv7", "arm64"))
    init.add_argument("--target-client", required=True)
    init.add_argument("--expected-generation", required=True)
    init.add_argument("--branch", default="agent/classifier-v2.3-capture-envelope")
    init.add_argument("--commit", required=True)
    init.add_argument("--max-cpu-pct", type=float, required=True)
    init.add_argument("--max-memory-mib", type=float, required=True)
    init.add_argument("--max-queue-drops", type=int, required=True)
    init.add_argument("--min-throughput-bps", type=int, required=True)
    init.add_argument("--max-latency-regression-pct", type=float, required=True)
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=command_init)

    snapshot = commands.add_parser("snapshot", help="capture sanitized H10 control-plane state")
    snapshot.add_argument("--run", required=True)
    snapshot.add_argument("--router-url", required=True)
    snapshot.add_argument("--label", required=True)
    snapshot.add_argument("--output")
    snapshot.add_argument("--token", default="")
    snapshot.add_argument("--timeout", type=float, default=8.0)
    snapshot.add_argument("--insecure", action="store_true")
    snapshot.set_defaults(func=command_snapshot)

    code = commands.add_parser("record-code-gate", help="record unit/integration/race/fuzz/benchmark/UI evidence")
    add_record_arguments(code, "gate")
    code.set_defaults(func=lambda args: command_record(args, "code_gates"))

    preflight = commands.add_parser("record-preflight", help="record one target preflight gate")
    add_record_arguments(preflight, "gate")
    preflight.set_defaults(func=lambda args: command_record(args, "preflight"))

    scenario = commands.add_parser("record-scenario", help="record one target matrix scenario")
    add_record_arguments(scenario, "scenario")
    scenario.set_defaults(func=lambda args: command_record(args, "scenarios"))

    certify_cmd = commands.add_parser("certify", help="return PASS only with complete physical target evidence")
    certify_cmd.add_argument("--run", required=True)
    certify_cmd.add_argument("--markdown")
    certify_cmd.set_defaults(func=command_certify)

    report = commands.add_parser("report", help="render a privacy-safe H10 report")
    report.add_argument("--run", required=True)
    report.add_argument("--output")
    report.set_defaults(func=command_report)

    validate = commands.add_parser("validate-manifest", help="validate the normative H10 matrix")
    validate.set_defaults(func=command_validate_manifest)
    return root


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"rst-gso-field-validation: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
