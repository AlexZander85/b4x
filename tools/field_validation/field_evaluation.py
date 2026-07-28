from __future__ import annotations

import math
from typing import Any

from field_common import (
    PREFLIGHT_GATES,
    canonical_json,
    identifier,
    markdown_cell,
    now_utc,
    sanitize_text,
)


def metric_counter_map(snapshot: dict[str, Any]) -> dict[str, float]:
    result: dict[str, float] = {}
    for sample in (snapshot.get("counters") or []):
        name = str(sample.get("name") or "")
        labels = canonical_json(sample.get("labels") or {})
        value = sample.get("value")
        if name and isinstance(value, (int, float)):
            result[name + "|" + labels] = float(value)
    return result


def counter_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, float]:
    left = metric_counter_map(before)
    right = metric_counter_map(after)
    return {key: value - left.get(key, 0.0) for key, value in right.items() if value - left.get(key, 0.0) != 0}


def metric_truth(value: Any) -> bool:
    return value is True or value == 1 or (isinstance(value, str) and value.lower() in {"true", "pass", "passed", "yes"})


def metric_number(metrics: dict[str, Any], name: str) -> float | None:
    value = metrics.get(name)
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    return None


def evaluate_scenario(scenario: dict[str, Any], result: dict[str, Any], run: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    metrics = result.get("metrics") or {}
    for name in scenario.get("required_metrics", []):
        if name not in metrics or metrics[name] in (None, ""):
            reasons.append(f"missing metric: {name}")

    for name, value in metrics.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and (not math.isfinite(float(value)) or value < 0):
            reasons.append(f"{name} must be a finite non-negative value")

    for name in (
        "unclassified_first_flows",
        "queue_drops_delta",
        "collateral_failures",
        "clean_syn_raw_reinjects",
        "generated_packet_requeues",
        "retransmission_action_repeats",
        "post_server_progress_actions",
        "closed_flow_state_entries",
        "stale_runtime_entries",
        "held_packets_after_restart",
    ):
        value = metric_number(metrics, name)
        if value is not None and value != 0:
            reasons.append(f"{name} must be zero, got {value:g}")

    actions = metric_number(metrics, "actions_per_logical_clienthello")
    if actions is not None and actions > 1:
        reasons.append(f"actions_per_logical_clienthello must be <= 1, got {actions:g}")
    if "reassembly_completed" in metrics and not metric_truth(metrics["reassembly_completed"]):
        reasons.append("split ClientHello reassembly did not complete")
    if "cross_client_leakage" in metrics and metric_truth(metrics["cross_client_leakage"]):
        reasons.append("cross-client evidence leakage detected")
    confidence_value = metric_number(metrics, "confidence")
    if confidence_value is not None and confidence_value > 100:
        reasons.append("confidence must be <= 100")
    cpu_value = metric_number(metrics, "cpu_peak_pct")
    if cpu_value is not None and cpu_value > 100:
        reasons.append("cpu_peak_pct must be <= 100")

    for name in ("ipv4_pass", "ipv6_pass", "doh_pass", "system_dns_pass", "quic_initial_seen", "quic_tcp_handoff", "canary_pass", "promote_pass", "rollback_pass", "restart_cleanup_pass", "queue_chains_clean", "clienthello_segment_2_seen"):
        if name in metrics and not metric_truth(metrics[name]):
            reasons.append(f"{name} is not true")

    if scenario["id"] == "ech_split_clienthello":
        source = str(metrics.get("evidence_source") or "").lower()
        if not ("dns" in source or "quic" in source):
            reasons.append("ECH flow must use scoped DNS or QUIC evidence")

    budgets = run.get("budgets") or {}
    body = metric_number(metrics, "body_bytes")
    if body is not None and body < float(budgets.get("min_body_bytes") or 0):
        reasons.append(f"body_bytes below budget: {body:g}")
    throughput = metric_number(metrics, "throughput_bps")
    if throughput is not None and throughput < float(budgets.get("min_throughput_bps") or 0):
        reasons.append(f"throughput_bps below budget: {throughput:g}")
    cpu = metric_number(metrics, "cpu_peak_pct")
    if cpu is not None and cpu > float(budgets.get("max_cpu_pct") or 0):
        reasons.append(f"cpu_peak_pct exceeds budget: {cpu:g}")
    memory = metric_number(metrics, "memory_peak_bytes")
    if memory is not None and memory > float(budgets.get("max_memory_bytes") or 0):
        reasons.append(f"memory_peak_bytes exceeds budget: {memory:g}")

    confidence = metric_number(metrics, "confidence")
    classify_threshold = (((run.get("preflight") or {}).get("snapshot") or {}).get("classify_threshold"))
    if confidence is not None and isinstance(classify_threshold, (int, float)) and confidence < classify_threshold:
        reasons.append(f"confidence {confidence:g} below classifier threshold {classify_threshold:g}")
    return reasons


def certify(run: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    hard_fail = False
    blocked = False
    preflight_status = (run.get("preflight") or {}).get("status")
    if preflight_status == "fail":
        hard_fail = True
        reasons.append("preflight is FAIL")
    elif preflight_status != "pass":
        blocked = True
        reasons.append("preflight is not PASS")

    covered: set[str] = set()
    scenario_map = run.get("scenarios") or {}
    for scenario in manifest["scenarios"]:
        result = scenario_map.get(scenario["id"])
        if not result:
            blocked = True
            reasons.append(f"missing scenario result: {scenario['id']}")
            continue
        scenario_status = result.get("status")
        if scenario_status == "fail":
            hard_fail = True
            reasons.append(f"scenario {scenario['id']} is fail")
            continue
        if scenario_status != "pass":
            blocked = True
            reasons.append(f"scenario {scenario['id']} is {scenario_status or 'missing'}")
            continue
        scenario_reasons = evaluate_scenario(scenario, result, run)
        if scenario_reasons:
            hard_fail = True
            reasons.extend(f"{scenario['id']}: {reason}" for reason in scenario_reasons)
        else:
            covered.update(scenario.get("tags", []))

    missing_coverage = sorted(set(manifest.get("required_coverage", [])) - covered)
    if missing_coverage:
        blocked = True
        reasons.append("missing coverage: " + ", ".join(missing_coverage))

    status = "fail" if hard_fail else "blocked" if blocked else "pass"
    return {
        "status": status,
        "reasons": reasons,
        "checked_at": now_utc(),
        "coverage": sorted(covered),
        "run_hash": identifier(canonical_json({"target": run.get("target"), "scenarios": run.get("scenarios")})),
    }


def markdown_report(run: dict[str, Any], manifest: dict[str, Any]) -> str:
    lines = [
        "# B4 classifier v2.3 — controlled Keenetic validation",
        "",
        f"- Updated: `{run.get('updated_at', '—')}`",
        f"- Target architecture: `{run.get('target', {}).get('architecture') or 'unknown'}`",
        f"- B4 commit: `{run.get('target', {}).get('b4_commit') or 'unknown'}`",
        f"- Config generation: `{run.get('target', {}).get('expected_generation') or 'unknown'}`",
        f"- Certification: **{run.get('certification', {}).get('status', 'pending').upper()}**",
        "",
        "## Preflight",
        "",
        "| Gate | Status | Reason |",
        "|---|---:|---|",
    ]
    for name in PREFLIGHT_GATES:
        item = (run.get("preflight", {}).get("gates") or {}).get(name, {})
        lines.append(f"| `{name}` | {str(item.get('status', 'pending')).upper()} | {markdown_cell(item.get('reason', ''))} |")
    lines.extend(["", "## Android scenarios", "", "| Scenario | Status | Key metrics |", "|---|---:|---|"])
    for scenario in manifest["scenarios"]:
        result = (run.get("scenarios") or {}).get(scenario["id"], {})
        metrics = result.get("metrics") or {}
        summary = ", ".join(f"{key}={metrics[key]}" for key in scenario.get("required_metrics", []) if key in metrics)
        lines.append(f"| `{scenario['id']}` | {str(result.get('status', 'pending')).upper()} | {markdown_cell(summary)} |")
    lines.extend(["", "## Certification reasons", ""])
    reasons = run.get("certification", {}).get("reasons") or []
    lines.extend([f"- {sanitize_text(str(reason))}" for reason in reasons] or ["- None"])
    lines.extend(["", "## Residual risks", "", "- Raw packets and ClientHello payloads are not included in this report.", "- A PASS is valid only for the recorded router, configuration generation and target client group.", "- Kernel/offload changes or a new B4 generation require a new controlled run.", ""])
    return "\n".join(lines)
