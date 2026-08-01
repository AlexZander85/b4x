#!/usr/bin/env python3
"""B4X FB-03: generate canonical hard-gate registry.

Reads hard-gate sections from the normative addenda (owner = subsystem owner)
and emits `specs/registries/hard_gates.yaml` (single canonical source,
approved by owner decision: artifacts/audit/B4X_FB03_OWNER_DECISION.md).

Design rules (owner decision 2026-08-01):
- Import WITHOUT renaming: CanonicalMetricName = name as written in addendum.
- FT/IV are generated validation views, NOT canonical owners.
- Total is computed, never hard-coded.
- Each gate gets owner family + source section + class.

Usage:
    python tools/gen_hard_gates_registry.py [--check]
        (no args: regenerate specs/registries/hard_gates.yaml)
        --check: verify existing registry against document extraction
                 (duplicates, orphans, FT view coverage), exit non-zero on mismatch.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

REPO = Path(__file__).resolve().parent.parent
REGISTRY = REPO / "specs" / "registries" / "hard_gates.yaml"

# ---------------------------------------------------------------------------
# Extraction map: (file, section_name, [line ranges], class)
# Line ranges are 1-based inclusive; verified 2026-08-01 against current docs.
# ---------------------------------------------------------------------------

WARP_DOC = "B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md"
SPF_DOC = "B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md"
MON_DOC = "B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md"
FT_DOC = "B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md"
ABD_DOC = "B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md"
DDI_DOC = "B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md"
SP_DOC = "B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md"
CSI_DOC = "B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md"
RST_DOC = "B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md"
PPE_DOC = "B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md"

# family -> list of (doc, section, start, end, class)
SECTIONS: dict[str, list[tuple[str, str, int, int, str]]] = {
    "warp": [
        (WARP_DOC, "72", 3590, 3604, "base_transport"),
        (WARP_DOC, "73", 3605, 3617, "non_ru"),
        (WARP_DOC, "73A", 3618, 3634, "camouflage"),
        (WARP_DOC, "73B", 3635, 3705, "causal_trace"),
    ],
    "spf": [
        (SPF_DOC, "45", 1467, 1495, "mandatory"),
    ],
    "mon": [
        (MON_DOC, "84", 2064, 2073, "observation"),
        (MON_DOC, "85", 2075, 2085, "scope"),
        (MON_DOC, "86", 2087, 2096, "temporal"),
        (MON_DOC, "87", 2098, 2107, "resolution"),
        (MON_DOC, "88", 2109, 2120, "trigger_resource"),
        (MON_DOC, "89", 2122, 2130, "multi_vantage"),
        (MON_DOC, "90", 2132, 2142, "abd_ddi_discovery"),
        (MON_DOC, "91", 2144, 2152, "legacy_migration"),
        (MON_DOC, "92", 2154, 2164, "reliability_privacy"),
    ],
    "abd": [
        (ABD_DOC, "39", 3528, 3551, "detector_safety"),
        (ABD_DOC, "40", 3552, 3568, "dns_tls_quic"),
        (ABD_DOC, "41", 3569, 3580, "l4_threshold"),
        (ABD_DOC, "42", 3581, 3644, "blocking_profile_ddi"),
    ],
    "ddi_tgb": [
        (DDI_DOC, "discovery", 1588, 1601, "discovery_profile"),
        (DDI_DOC, "tgb", 1607, 1616, "mtproto_bridge"),
    ],
    "sp": [
        (SP_DOC, "warp_recommendation", 3512, 3525, "profile_warp"),
    ],
    "csi": [
        (CSI_DOC, "hard_gate", 1220, 1220, "unrelated_control"),
    ],
    "rst_gso": [
        (RST_DOC, "metrics", 834, 854, "classifier_gso_rst"),
    ],
    "ppe": [
        (PPE_DOC, "metrics", 795, 801, "capture_visibility"),
    ],
}

# FT view mapping: prefix -> canonical family owner (for non-WARP FT gates).
FT_OWNER_BY_PREFIX: list[tuple[str, str]] = [
    ("detector_", "abd"),
    ("blocking_profile_", "abd"),
    ("guided_search_", "abd"),
    ("discovery_profile_", "ddi_tgb"),
    ("mtproto_bridge_", "ddi_tgb"),
]

# IV v1.5 validation views: (doc, section, [line range], expected family).
IV_DOC = "B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md"
IV_VIEWS: list[tuple[str, str, int, int, str]] = [
    (IV_DOC, "38A.9", 2420, 2480, "warp"),
    (IV_DOC, "38B.9", 2638, 2663, "spf"),
]

# Canonical gates whose metric name does NOT end with _total (hard gates
# written without the counter suffix in the addendum).
NO_TOTAL_SUFFIX: set[str] = set()

# Runtime producers verified in code (2026-08-01): metric name -> producer
# descriptor. Gates without a verified producer have producer_status=missing
# and expected_producer_location (see below).
# NOTE: a *declared* producer file is NOT a *verified* producer. Only names
# listed here were confirmed by actual Metrics.Inc/owner-state call sites.
RUNTIME_PRODUCERS_VERIFIED: dict[str, dict] = {
    "unrelated_control_action_total": {
        "symbol": "UnrelatedControlActionTotal++ (validate) -> observability.Metrics.Inc(MetricUnrelatedControlAction) (store)",
        "file": "src/crossservice/validation.go",
        "line": 392,
        "mechanism": "increment-only counter via observability; report field incremented at validation.go:265",
        "production_root": "crossservice.Validate() / (*Store).ValidateAndStore (CSI-18 same-client negative control)",
    },
}

# Expected (normative) producer locations for gates whose producer is not yet
# implemented. Field runtime_producer stays null; the mapping below is only
# the owner-normative location where the producer must be wired (FB-27 for
# RST/GSO, PPE production wiring for PPE).
EXPECTED_PRODUCER_LOCATION: dict[str, str] = {
    "b4_capture_visibility_degrade_total": "capture/ppe/product_service.go",
    "b4_hold_disabled_visibility_total": "capture/ppe/product_service.go",
    "b4_ppe_rule_reapply_total": "capture/ppe/product_service.go",
    "b4_ppe_self_test_total": "capture/ppe/product_service.go",
    "classifier_layout_parity_fail_total": "nfq/classifier_decision.go",
    "classifier_reassembled_sni_total": "nfq/classifier_decision.go",
    "nfqueue_gso_action_suppressed_total": "nfq/gso_fastpath.go",
    "nfqueue_gso_bytes_total": "nfq/offload.go",
    "nfqueue_gso_csum_not_ready_total": "nfq/offload.go",
    "nfqueue_gso_decision_total": "nfq/gso_fastpath.go",
    "nfqueue_gso_normalized_total": "nfq/gso_fastpath.go",
    "nfqueue_gso_packets_total": "nfq/offload.go",
    "nfqueue_gso_token_miss_total": "nfq/gso_normalizer.go",
    "nfqueue_gso_transition_total": "http/handler/runtime_topology.go",
    "nfqueue_gso_truncated_total": "nfq/offload.go",
    "passive_rst_baseline_quality_total": "nfq/passive_rst_observe.go",
    "passive_rst_budget_exhausted_total": "nfq/passive_rst_observe.go",
    "passive_rst_decision_total": "nfq/passive_rst_observe.go",
    "passive_rst_fail_open_total": "nfq/passive_rst_observe.go",
    "passive_rst_observed_total": "nfq/passive_rst_observe.go",
    "passive_rst_reconnect_regression_total": "nfq/passive_rst_rollback.go",
    "passive_rst_rollback_total": "nfq/passive_rst_rollback.go",
    "passive_rst_suppressed_total": "nfq/passive_rst_observe.go",
}

# Verified-commit SHA recorded in the registry when a producer_status
# flips to verified (producer audited + negative fixture + mutation run in
# this commit). Filled by REGISTER_VERIFIED_COMMIT below.
REGISTER_VERIFIED_COMMIT = "7c0be90f"  # FB-03 phase A commit (2026-08-01)

# Gate kinds (owner-decision pending; classification is an ASSUMPTION,
# fail-closed by default — see artifacts/audit/B4X_FB03_OWNER_DECISION.md):
#   telemetry_counter                 — operational telemetry, NOT a blocker
#   zero_tolerance_violation_counter  — violation counter, verified == 0
#   threshold_violation_counter       — blocks above an owner-defined threshold
#   current_generation_readiness_state — readiness state bound to generation
#   required_evidence                 — evidence artifact required, not a counter
#   derived_blocker                   — derived verdict blocker (aggregation)
# Only zero_tolerance_violation_counter (and, when normatively justified,
# threshold/readiness/evidence/derived) may block promotion.
GATE_KINDS: dict[str, str] = {
    # --- telemetry (operational counters, never block) ---
    "classifier_reassembled_sni_total": "telemetry_counter",
    "nfqueue_gso_packets_total": "telemetry_counter",
    "nfqueue_gso_bytes_total": "telemetry_counter",
    "nfqueue_gso_decision_total": "telemetry_counter",
    "nfqueue_gso_normalized_total": "telemetry_counter",
    "nfqueue_gso_transition_total": "telemetry_counter",
    "nfqueue_gso_action_suppressed_total": "telemetry_counter",
    "passive_rst_observed_total": "telemetry_counter",
    "passive_rst_decision_total": "telemetry_counter",
    "passive_rst_suppressed_total": "telemetry_counter",
    "passive_rst_rollback_total": "telemetry_counter",
    "passive_rst_baseline_quality_total": "telemetry_counter",
    "passive_rst_budget_exhausted_total": "telemetry_counter",
    "b4_ppe_rule_reapply_total": "telemetry_counter",
    "b4_ppe_self_test_total": "telemetry_counter",
    # --- zero-tolerance violation counters (verified == 0) ---
    "unrelated_control_action_total": "zero_tolerance_violation_counter",
    "classifier_layout_parity_fail_total": "zero_tolerance_violation_counter",
    "nfqueue_gso_truncated_total": "zero_tolerance_violation_counter",
    "nfqueue_gso_csum_not_ready_total": "zero_tolerance_violation_counter",
    "nfqueue_gso_token_miss_total": "zero_tolerance_violation_counter",
    "passive_rst_fail_open_total": "zero_tolerance_violation_counter",
    "passive_rst_reconnect_regression_total": "zero_tolerance_violation_counter",
    "b4_capture_visibility_degrade_total": "zero_tolerance_violation_counter",
    "b4_hold_disabled_visibility_total": "zero_tolerance_violation_counter",
}

# Verdict consumers wired in production (2026-08-01): metric name -> list of
# machine-readable consumer descriptors. Only blocking gates need consumers;
# telemetry gates are not consumed by promotion. kind:
#   promotion_blocker   — blocks promotion when count != 0
#   aggregation_blocker — gate-evaluation aggregation (fail-closed)
#   http_report         — observable report endpoint
VERDICT_CONSUMERS: dict[str, list[dict]] = {
    "unrelated_control_action_total": [
        {
            "kind": "promotion_blocker",
            "symbol": "Validate() report.Passed / Store.RequirePromotion",
            "file": "src/crossservice/validation.go",
            "line": 312,
            "binding": "generation; family:csi",
        },
        {
            "kind": "aggregation_blocker",
            "symbol": "EvaluateHardGates",
            "file": "src/validation/gates.go",
            "line": 205,
            "binding": "scope.csi; fail-closed",
        },
        {
            "kind": "http_report",
            "symbol": "GET /api/v2/validation/gates",
            "file": "src/http/handler/validation_gates.go",
            "line": 0,
            "binding": "live snapshot",
        },
    ],
}

# Test fixtures that exercise each verified producer (negative fixture =
# violation must flip the verdict; positive fixture = clean path must pass).
TEST_PRODUCERS: dict[str, list[dict]] = {
    "unrelated_control_action_total": [
        {
            "kind": "positive_fixture",
            "name": "TestValidatePassingMatrixAllowsPromotion",
            "file": "src/crossservice/validation_test.go",
            "line": 29,
            "assertion": "UnrelatedControlActionTotal == 0 && PromotionAllowed == true",
        },
        {
            "kind": "negative_fixture",
            "name": "TestValidateRejectsYouTubeStateOnGmailSharedIPFlow",
            "file": "src/crossservice/validation_test.go",
            "line": 40,
            "assertion": "UnrelatedControlActionTotal == 1 && PromotionAllowed == false",
        },
        {
            "kind": "evaluator_fixture",
            "name": "TestEvaluateHardGatesViolation",
            "file": "src/validation/gates_test.go",
            "line": 117,
            "assertion": "counter != 0 -> GateFail",
        },
    ],
}

# Executed mutation tests per gate (removed/disabled producer must flip the
# verdict; empty = not yet executed for this gate).
MUTATION_TESTS: dict[str, list[dict]] = {
    "unrelated_control_action_total": [
        {
            "kind": "removed_inc",
            "name": "TestValidateRejectsYouTubeStateOnGmailSharedIPFlow (producer removed)",
            "file": "src/crossservice/validation_test.go",
            "line": 40,
            "status": "executed",
        },
    ],
}

# Evidence artifacts backing each verified gate (audit + remediation trail).
EVIDENCE_ARTIFACTS: dict[str, list[str]] = {
    "unrelated_control_action_total": [
        "artifacts/audit/hard_gates_audit.md",
        "artifacts/audit/csi_ppe_rstgso_audit.md",
        "artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md",
    ],
}

GATE_RE = re.compile(r"^([a-z][a-z0-9_]+)\s*==\s*0\s*$")
METRIC_RE = re.compile(r"^([a-z][a-z0-9_]+_total)(?:\{[^}]*\})?\s*$")


def read_lines(doc: str) -> list[str]:
    path = REPO / doc
    if not path.exists():
        sys.exit(f"ERROR: document not found: {doc}")
    with path.open(encoding="utf-8") as fh:
        return fh.read().splitlines()


def extract_gates(doc: str, start: int, end: int) -> list[str]:
    """Extract gate names from [start, end] lines (1-based, inclusive).

    Ranges are pre-verified against the addenda (2026-08-01) and correspond
    to the `== 0` gate lists; fence markers are therefore not required.
    """
    lines = read_lines(doc)
    gates: list[str] = []
    for idx in range(start - 1, min(end, len(lines))):
        m = GATE_RE.match(lines[idx].strip())
        if m:
            gates.append(m.group(1))
    return gates


def extract_metrics(doc: str, start: int, end: int) -> list[str]:
    """Extract metric names from [start, end] lines (for RST/GSO, PPE)."""
    lines = read_lines(doc)
    metrics: list[str] = []
    for idx in range(start - 1, min(end, len(lines))):
        m = METRIC_RE.match(lines[idx].strip())
        if m:
            metrics.append(m.group(1))
    return metrics


def build_gates() -> tuple[dict[str, list[dict]], dict[str, str]]:
    """Return (families, all_gate_names->family)."""
    families: dict[str, list[dict]] = {}
    index: dict[str, str] = {}
    for family, sections in SECTIONS.items():
        entries: list[dict] = []
        for doc, section, start, end, cls in sections:
            if family in ("rst_gso", "ppe"):
                names = extract_metrics(doc, start, end)
            else:
                names = extract_gates(doc, start, end)
            for name in names:
                if name in index:
                    print(f"WARN: duplicate gate {name!r} in family {family} "
                          f"(already owned by {index[name]})", file=sys.stderr)
                    continue
                index[name] = family
                producer = RUNTIME_PRODUCERS_VERIFIED.get(name)
                kind = GATE_KINDS.get(name, "zero_tolerance_violation_counter")
                entry = {
                    "gate_id": name,
                    "canonical_metric_name": name,
                    "global_gate_class": cls,
                    "owner_family": family,
                    "owner_stage": "apply",
                    "source_doc": doc,
                    "source_section": section,
                    "kind": kind,
                    "producer_status": "verified" if producer else "missing",
                    "runtime_producer": producer,
                    "verified_commit": REGISTER_VERIFIED_COMMIT if producer else None,
                    "expected_producer_location": EXPECTED_PRODUCER_LOCATION.get(name),
                    "verdict_consumer": VERDICT_CONSUMERS.get(name),
                    "promotion_blocker": kind == "zero_tolerance_violation_counter",
                    "reset_semantics": ("increment-only; verified == 0" if kind == "zero_tolerance_violation_counter"
                                        else "telemetry; not a blocker"),
                    "expiry_generation_binding": None,
                    "applicability": f"family:{family}",
                    "test_producer": TEST_PRODUCERS.get(name),
                    "mutation_test": MUTATION_TESTS.get(name),
                    "evidence_artifact": EVIDENCE_ARTIFACTS.get(name),
                }
                entries.append(entry)
        if entries:
            families[family] = entries
    return families, index


def build_ft_view(index: dict[str, str]) -> list[dict]:
    """FT v1.5 section 26 (82 gates) as a generated validation view."""
    names = extract_gates(FT_DOC, 3154, 3244)
    view = []
    for name in names:
        owner = None
        if name in index:
            owner = index[name]
        else:
            for prefix, fam in FT_OWNER_BY_PREFIX:
                if name.startswith(prefix):
                    owner = fam
                    break
        view.append({"ft_section": "26", "gate_name": name, "canonical_owner": owner})
    return view


def build_iv_views(index: dict[str, str]) -> list[dict]:
    """IV v1.5 sections 38A.9/38B.9 as generated validation views."""
    view = []
    for doc, section, start, end, expected in IV_VIEWS:
        names = extract_gates(doc, start, end)
        for name in names:
            owner = index.get(name)
            view.append({
                "iv_section": section,
                "gate_name": name,
                "canonical_owner": owner,
                "expected_owner": expected,
            })
    return view


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="validate existing registry, do not write")
    args = parser.parse_args()

    families, index = build_gates()

    if args.check:
        if not REGISTRY.exists():
            sys.exit(f"ERROR: registry missing: {REGISTRY}")
        with REGISTRY.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        errors = []
        stored = {}
        for fam, gates in (data.get("families") or {}).items():
            for g in gates:
                stored[g["gate_id"]] = fam
        # Orphans: gates in registry that are no longer extractable.
        for name in stored:
            if name not in index:
                errors.append(f"ORPHAN: {name!r} in registry family {stored[name]} "
                              f"not found in addenda extraction")
        # Missing: extractable gates not present in registry.
        for name, fam in index.items():
            if name not in stored:
                errors.append(f"MISSING: {name!r} (family {fam}) absent from registry")
        # Duplicate gate_id across families.
        seen: dict[str, str] = {}
        for fam, gates in (data.get("families") or {}).items():
            for g in gates:
                gid = g["gate_id"]
                if gid in seen and seen[gid] != fam:
                    errors.append(f"DUPLICATE gate_id {gid!r} in {seen[gid]} and {fam}")
                seen[gid] = fam
                # Producer integrity: runtime_producer must be null unless
                # producer_status == verified (a declared file is NOT proof).
                if g.get("producer_status") == "verified" and not g.get("runtime_producer"):
                    errors.append(f"PRODUCER: {gid!r} marked verified without runtime_producer")
                if g.get("producer_status") != "verified" and g.get("runtime_producer"):
                    errors.append(f"PRODUCER: {gid!r} has runtime_producer {g.get('runtime_producer')!r} "
                                  f"but producer_status={g.get('producer_status')!r} (not verified)")
                # Verified producers must carry machine-readable consumers,
                # tests and evidence (FB-03 verdict-consumer chain).
                if g.get("producer_status") == "verified":
                    if not g.get("verified_commit"):
                        errors.append(f"COMMIT: {gid!r} verified producer has no verified_commit")
                    vc = g.get("verdict_consumer")
                    if not vc:
                        errors.append(f"CONSUMER: {gid!r} verified producer has no verdict_consumer")
                    else:
                        for i, c in enumerate(vc):
                            if not (c.get("kind") and c.get("symbol") and c.get("file")):
                                errors.append(f"CONSUMER: {gid!r}[{i}] incomplete descriptor {c!r}")
                    tp = g.get("test_producer")
                    if not tp:
                        errors.append(f"TEST: {gid!r} verified producer has no test_producer")
                    else:
                        for i, t in enumerate(tp):
                            if not (t.get("kind") and t.get("name") and t.get("file")):
                                errors.append(f"TEST: {gid!r}[{i}] incomplete descriptor {t!r}")
                    if not g.get("evidence_artifact"):
                        errors.append(f"EVIDENCE: {gid!r} verified producer has no evidence_artifact")
                    rp = g.get("runtime_producer")
                    if not (rp.get("symbol") and rp.get("file") and rp.get("line")):
                        errors.append(f"PRODUCER: {gid!r} descriptor incomplete {rp!r}")
                # Missing producers with a normative owner mapping must carry
                # the expected location (FB-27 / PPE wiring targets); gates
                # without a normative mapping stay null (audit: no production
                # path exists, so fail-closed BLOCKED is the honest verdict).
                if g.get("producer_status") == "missing" and gid in EXPECTED_PRODUCER_LOCATION:
                    if not g.get("expected_producer_location"):
                        errors.append(f"PRODUCER: {gid!r} missing but no expected_producer_location")
                # Telemetry counters must not block promotion.
                if g.get("kind") == "telemetry_counter" and g.get("promotion_blocker"):
                    errors.append(f"KIND: {gid!r} is telemetry_counter but blocks promotion")
        # FT view coverage.
        view = build_ft_view(index)
        orphan_ft = [v for v in view if v["canonical_owner"] is None]
        for v in orphan_ft:
            errors.append(f"FT-ORPHAN: {v['gate_name']!r} has no canonical owner")
        # IV view coverage (38A.9 -> warp, 38B.9 -> spf).
        iv_view = build_iv_views(index)
        for v in iv_view:
            if v["canonical_owner"] is None:
                errors.append(f"IV-ORPHAN: {v['gate_name']!r} ({v['iv_section']}) "
                              f"has no canonical owner")
            elif v["canonical_owner"] != v["expected_owner"]:
                errors.append(f"IV-OWNER: {v['gate_name']!r} ({v['iv_section']}) "
                              f"maps to {v['canonical_owner']}, expected {v['expected_owner']}")
        if errors:
            print("VALIDATION FAILED:", file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            return 1
        total = sum(len(g) for g in (data.get("families") or {}).values())
        print(f"OK: {len(stored)} gates, {len(data.get('families', {}))} families, "
              f"FT view {len(view)} gates, IV view {len(iv_view)} gates, all mapped")
        return 0

    # Write registry.
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": "1.1",
        "generator": "tools/gen_hard_gates_registry.py",
        "generated_at": "2026-08-01",
        "status": "canonical (owner decision 2026-08-01)",
        "total_is_not_final": True,
        "families": families,
    }
    with REGISTRY.open("w", encoding="utf-8", newline="\n") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True,
                       width=120, default_flow_style=False)
    total = sum(len(g) for g in families.values())
    print(f"WROTE {REGISTRY}: {total} gates in {len(families)} families")
    for fam, gates in families.items():
        print(f"  {fam}: {len(gates)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
