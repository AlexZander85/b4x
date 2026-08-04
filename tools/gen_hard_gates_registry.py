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

# Extra canonical gates that are not extractable from the addenda (no `== 0`
# list in their normative source): hand-maintained entries kept in the
# registry by build_gates and indexed for --check, so regeneration never
# drops them. Must stay in sync with the registry schema (all fields present;
# kind/promotion_blocker follow the owner decision, readiness inputs never
# block promotion directly).
EXTRA_GATES: dict[str, dict] = {
    "mon_production_ready": {
        "gate_id": "mon_production_ready",
        "canonical_metric_name": "mon_production_ready",
        "global_gate_class": "monitoring_conformance",
        "owner_family": "mon",
        "owner_stage": "cutover",
        "source_doc": "B4X_AUDIT_FIX_TASKS v2.md §FB-28",
        "source_section": "FB-28",
        "kind": "current_generation_readiness_input",
        "producer_status": "verified",
        "runtime_producer": {
            "symbol": "MonProductionReady()",
            "file": "src/validation/iv18_reachability.go",
            "line": 235,
            "mechanism": "static reverse-reachability AST scan (legacy applyBatchResults unreachable) + production dependency wiring (ObservationBus, DiagnosticScheduler, ABD-DDI chain, /api/monitor/v1); readiness input, not a counter",
            "production_root": "validation suite + release pipeline root (FB-28 cutover readiness)",
        },
        "verified_commit": None,
        "expected_producer_location": "src/validation/iv18_reachability.go",
        "verdict_consumer": [
            {
                "kind": "registry_suite_verdict",
                "symbol": "RunIV18Suite + promotion readiness",
                "file": "src/validation/iv_suite.go",
                "line": 124,
                "binding": "IV-18 verdict cannot be PASS while legacy mutating path is reachable",
            },
        ],
        "promotion_blocker": False,
        "reset_semantics": "readiness; PASS only while legacy mutating path unreachable",
        "expiry_generation_binding": None,
        "applicability": "family:mon",
        "test_producer": [
            {
                "kind": "static_reachability_scan",
                "name": "TestIV18ReverseReachabilityBlocksProductionReadyWhileLegacyReachable",
                "file": "src/validation/iv18_reachability_test.go",
                "line": 1,
                "assertion": "applyBatchResults reachable -> mon_production_ready blocked",
            },
        ],
        "mutation_test": None,
        "evidence_artifact": [
            "B4X_AUDIT_FIX_TASKS v2.md §FB-28",
            "B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md",
            "src/validation/iv18_reachability.go",
            "src/validation/iv18_reachability_test.go",
        ],
    },
}

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
# All 24 gate producers in the FB-03 scope are now implemented: each metric
# has a real Metrics.Inc site reached from a production root (see
# FB03_GATE_PRODUCER_CONSUMER_MATRIX.md, "producer call sites" column).
RUNTIME_PRODUCERS_VERIFIED: dict[str, dict] = {
    "unrelated_control_action_total": {
        "symbol": "UnrelatedControlActionTotal++ (validate) -> observability.Metrics.Inc(MetricUnrelatedControlAction) (store)",
        "file": "src/crossservice/validation.go",
        "line": 392,
        "mechanism": "increment-only counter via observability; report field incremented at validation.go:265",
        "production_root": "crossservice.Validate() / (*Store).ValidateAndStore (CSI-18 same-client negative control)",
    },
    "classifier_reassembled_sni_total": {
        "symbol": "recordObservabilityDecision -> Metrics.Inc(MetricClassifierReassembledSNI)",
        "file": "src/nfq/classifier_decision.go",
        "line": 212,
        "mechanism": "increment-only counter via observability (label result=selected|unselected)",
        "production_root": "nfq.handleTCPPacket -> traceNFQDecision (reassembled-TCP-SNI evidence selected)",
    },
    "classifier_layout_parity_fail_total": {
        "symbol": "recordObservabilityDecision -> Metrics.Inc(MetricClassifierLayoutParityFail)",
        "file": "src/nfq/classifier_decision.go",
        "line": 214,
        "mechanism": "increment-only counter via observability (reassembled SNI without logical ID)",
        "production_root": "nfq.handleTCPPacket -> traceNFQDecision (layout parity violation)",
    },
    "nfqueue_gso_packets_total": {
        "symbol": "observeOffloadMetadata -> Metrics.Inc(MetricNFQueueGSOPackets)",
        "file": "src/nfq/offload.go",
        "line": 106,
        "mechanism": "increment-only counter via observability (per GSO-flagged packet)",
        "production_root": "nfq.handlePacket -> DecodeOffloadMetadata (NFQA_CFG_F_GSO metadata)",
    },
    "nfqueue_gso_bytes_total": {
        "symbol": "observeOffloadMetadata -> Metrics.Inc(MetricNFQueueGSOBytes)",
        "file": "src/nfq/offload.go",
        "line": 107,
        "mechanism": "increment-only byte counter via observability",
        "production_root": "nfq.handlePacket -> DecodeOffloadMetadata (NFQA_CFG_F_GSO metadata)",
    },
    "nfqueue_gso_truncated_total": {
        "symbol": "observeOffloadMetadata -> Metrics.Inc(MetricNFQueueGSOTruncated)",
        "file": "src/nfq/offload.go",
        "line": 109,
        "mechanism": "increment-only counter via observability (OriginalLength > PayloadLength)",
        "production_root": "nfq.handlePacket -> DecodeOffloadMetadata (truncated GSO envelope)",
    },
    "nfqueue_gso_csum_not_ready_total": {
        "symbol": "observeOffloadMetadata -> Metrics.Inc(MetricNFQueueGSOCsumNotReady)",
        "file": "src/nfq/offload.go",
        "line": 112,
        "mechanism": "increment-only counter via observability (NFQA_SKB_CSUMNOTREADY)",
        "production_root": "nfq.handlePacket -> DecodeOffloadMetadata (unverified checksum GSO)",
    },
    "nfqueue_gso_decision_total": {
        "symbol": "traceGSOFastPath -> Metrics.Inc(MetricNFQueueGSODecision)",
        "file": "src/nfq/gso_fastpath.go",
        "line": 209,
        "mechanism": "increment-only counter via observability (label path=result)",
        "production_root": "nfq.handleGSOFastPath (GSO fast-path verdict)",
    },
    "nfqueue_gso_normalized_total": {
        "symbol": "traceGSOFastPath -> Metrics.Inc(MetricNFQueueGSONormalized)",
        "file": "src/nfq/gso_fastpath.go",
        "line": 211,
        "mechanism": "increment-only counter via observability (normalize-queued path)",
        "production_root": "nfq.handleGSOFastPath (normalizer direct queue)",
    },
    "nfqueue_gso_action_suppressed_total": {
        "symbol": "traceGSOFastPath -> Metrics.Inc(MetricNFQueueGSOActionSuppressed)",
        "file": "src/nfq/gso_fastpath.go",
        "line": 214,
        "mechanism": "increment-only counter via observability (action-suppressed result)",
        "production_root": "nfq.handleGSOFastPath (suppression budget)",
    },
    "nfqueue_gso_token_miss_total": {
        "symbol": "traceGSONormalizerMiss -> Metrics.Inc(MetricNFQueueGSOTokenMiss)",
        "file": "src/nfq/gso_normalizer.go",
        "line": 61,
        "mechanism": "increment-only counter via observability (secondary-pass fail-open)",
        "production_root": "nfq GSO normalizer secondary pass (pass-token miss)",
    },
    "nfqueue_gso_transition_total": {
        "symbol": "ApplyRuntimeControlTopology defer -> Metrics.Inc(MetricNFQueueGSOTransition)",
        "file": "src/http/handler/runtime_topology.go",
        "line": 38,
        "mechanism": "increment-only counter via observability (deferred; result=success|rollback)",
        "production_root": "http API ApplyRuntimeControlTopology (double-buffered GSO topology switch)",
    },
    "passive_rst_observed_total": {
        "symbol": "recordPassiveRSTMetrics -> Metrics.Inc(MetricPassiveRSTObserved)",
        "file": "src/nfq/passive_rst_observe.go",
        "line": 106,
        "mechanism": "increment-only counter via observability (per signal)",
        "production_root": "nfq.observePassiveRSTIncoming/Outgoing (passive RST observation)",
    },
    "passive_rst_decision_total": {
        "symbol": "recordPassiveRSTMetrics -> Metrics.Inc(MetricPassiveRSTDecision)",
        "file": "src/nfq/passive_rst_observe.go",
        "line": 108,
        "mechanism": "increment-only counter via observability (label decision=...)",
        "production_root": "nfq.observePassiveRSTIncoming (enforcement decision)",
    },
    "passive_rst_baseline_quality_total": {
        "symbol": "recordPassiveRSTMetrics -> Metrics.Inc(MetricPassiveRSTBaselineQuality)",
        "file": "src/nfq/passive_rst_observe.go",
        "line": 109,
        "mechanism": "increment-only counter via observability (label quality=...)",
        "production_root": "nfq.observePassiveRSTIncoming (baseline quality)",
    },
    "passive_rst_suppressed_total": {
        "symbol": "recordPassiveRSTMetrics -> Metrics.Inc(MetricPassiveRSTSuppressed)",
        "file": "src/nfq/passive_rst_observe.go",
        "line": 113,
        "mechanism": "increment-only counter via observability (suppress decision)",
        "production_root": "nfq.observePassiveRSTIncoming (suppression)",
    },
    "passive_rst_fail_open_total": {
        "symbol": "recordPassiveRSTMetrics -> Metrics.Inc(MetricPassiveRSTFailOpen)",
        "file": "src/nfq/passive_rst_observe.go",
        "line": 116,
        "mechanism": "increment-only counter via observability (fail-open decision)",
        "production_root": "nfq.observePassiveRSTIncoming (fail-open enforcement)",
    },
    "passive_rst_budget_exhausted_total": {
        "symbol": "recordPassiveRSTMetrics -> Metrics.Inc(MetricPassiveRSTBudgetExhausted)",
        "file": "src/nfq/passive_rst_observe.go",
        "line": 118,
        "mechanism": "increment-only counter via observability (fail-open reason=budget)",
        "production_root": "nfq.observePassiveRSTIncoming (suppression budget exhausted)",
    },
    "passive_rst_rollback_total": {
        "symbol": "PassiveRSTStore.RecordHealth -> Metrics.Inc(MetricPassiveRSTRollback)",
        "file": "src/nfq/passive_rst_rollback.go",
        "line": 134,
        "mechanism": "increment-only counter via observability (scoped rollback commit)",
        "production_root": "pool.RecordPassiveRSTHealth -> PassiveRSTStore.RecordHealth (scope-local rollback)",
    },
    "passive_rst_reconnect_regression_total": {
        "symbol": "PassiveRSTStore.RecordHealth -> Metrics.Inc(MetricPassiveRSTReconnectRegression)",
        "file": "src/nfq/passive_rst_rollback.go",
        "line": 136,
        "mechanism": "increment-only counter via observability (reason=reconnect failure regression)",
        "production_root": "pool.RecordPassiveRSTHealth (reconnect failure regression)",
    },
    "b4_ppe_rule_reapply_total": {
        "symbol": "productLifecycleMetrics.Reapply -> Metrics.Inc(MetricPPERuleReapply)",
        "file": "src/capture/ppe/product_service.go",
        "line": 513,
        "mechanism": "increment-only counter via observability (label result=success|failure)",
        "production_root": "PPE lifecycle reapply (reconciler Assert/Reapply loop)",
    },
    "b4_ppe_self_test_total": {
        "symbol": "ProductService.RunSelfTest -> Metrics.Inc(MetricPPESelfTest)",
        "file": "src/capture/ppe/product_service.go",
        "line": 348,
        "mechanism": "increment-only counter via observability (label verdict=...)",
        "production_root": "PPE self-test controller run (visibility A/B probe)",
    },
    "b4_capture_visibility_degrade_total": {
        "symbol": "NewProductService gate.SubscribeBlocked callback -> Metrics.Inc(MetricCaptureVisibilityDegrade)",
        "file": "src/capture/ppe/product_service.go",
        "line": 110,
        "mechanism": "increment-only counter via observability (visibility gate degradation)",
        "production_root": "visibility gate Degrade -> ProductService subscriber",
    },
    "b4_hold_disabled_visibility_total": {
        "symbol": "NewProductService gate.SubscribeBlocked callback -> Metrics.Inc(MetricHoldDisabledVisibility)",
        "file": "src/capture/ppe/product_service.go",
        "line": 111,
        "mechanism": "increment-only counter via observability (hold disabled while visibility degraded)",
        "production_root": "visibility gate Degrade -> ProductService subscriber",
    },
    # --- WARP base-transport lifecycle producers (FB-02 WARP section,
    # 2026-08-04): every counter increments ONLY on the violating branch of
    # the production runtime (src/warp/runtime.go), reachable from main via
    # warp.NewRuntime/Start (controller loop root). ---
    "warp_secret_leak_total": {
        "symbol": "Runtime.PublishTrace -> Metrics.Inc(MetricWarpSecretLeak)",
        "file": "src/warp/runtime.go",
        "line": 407,
        "mechanism": "increment-only counter via observability (trace payload carries raw session secret)",
        "production_root": "warp.Runtime.PublishTrace (trace export redaction check; controller-loop root from main)",
    },
    "warp_foreign_interface_modified_total": {
        "symbol": "Runtime.ApplyRoute -> Metrics.Inc(MetricWarpForeignInterfaceModified)",
        "file": "src/warp/runtime.go",
        "line": 292,
        "mechanism": "increment-only counter via observability (TunRegistry.Claim rejects foreign session lease)",
        "production_root": "warp.Runtime.ApplyRoute (TUN ownership check; controller-loop root from main)",
    },
    "warp_recursive_control_route_total": {
        "symbol": "Runtime.ApplyRoute -> Metrics.Inc(MetricWarpRecursiveControlRoute)",
        "file": "src/warp/runtime.go",
        "line": 299,
        "mechanism": "increment-only counter via observability (policy.Mark == warp-control-direct mark 0x6001)",
        "production_root": "warp.Runtime.ApplyRoute (recursion guard, addendum §17/WARP-6; controller-loop root from main)",
    },
    "warp_mark_collision_total": {
        "symbol": "Runtime.ApplyRoute -> Metrics.Inc(MetricWarpMarkCollision)",
        "file": "src/warp/runtime.go",
        "line": 306,
        "mechanism": "increment-only counter via observability (policy-pinned mark owned by another session)",
        "production_root": "warp.Runtime.ApplyRoute (mark ownership; controller-loop root from main)",
    },
    "warp_route_without_liveness_total": {
        "symbol": "Runtime.ApplyRoute -> Metrics.Inc(MetricWarpRouteWithoutLiveness)",
        "file": "src/warp/runtime.go",
        "line": 284,
        "mechanism": "increment-only counter via observability (promotion while HealthTracker != data-alive)",
        "production_root": "warp.Runtime.ApplyRoute (liveness gate; controller-loop root from main)",
    },
    "warp_destination_set_partial_apply_total": {
        "symbol": "Runtime.ApplyRoute -> Metrics.Inc(MetricWarpDestinationSetPartialApply)",
        "file": "src/warp/runtime.go",
        "line": 317,
        "mechanism": "increment-only counter via observability (non-atomic destination set application)",
        "production_root": "warp.Runtime.ApplyRoute (atomic destination set; controller-loop root from main)",
    },
    "warp_unbounded_restart_total": {
        "symbol": "Runtime.Restart -> Metrics.Inc(MetricWarpUnboundedRestart)",
        "file": "src/warp/runtime.go",
        "line": 349,
        "mechanism": "increment-only counter via observability (restart beyond Config.MaxRestarts)",
        "production_root": "warp.Runtime.Restart (bounded restart budget; controller-loop root from main)",
    },
    "warp_unbounded_registration_total": {
        "symbol": "Runtime.Register -> Metrics.Inc(MetricWarpUnboundedRegistration)",
        "file": "src/warp/runtime.go",
        "line": 224,
        "mechanism": "increment-only counter via observability (enrollment attempt beyond policy MaxAttempts)",
        "production_root": "warp.Runtime.Register (bounded enrollment; controller-loop root from main)",
    },
    "warp_unrelated_control_action_total": {
        "symbol": "Runtime.ControlAction -> Metrics.Inc(MetricWarpUnrelatedControlAction)",
        "file": "src/warp/runtime.go",
        "line": 366,
        "mechanism": "increment-only counter via observability (control action on flow outside session authorization)",
        "production_root": "warp.Runtime.ControlAction (exact-scoped authorization; controller-loop root from main)",
    },
    "warp_rollback_failure_total": {
        "symbol": "Runtime.Rollback -> Metrics.Inc(MetricWarpRollbackFailure)",
        "file": "src/warp/runtime.go",
        "line": 383,
        "mechanism": "increment-only counter via observability (rollback with no previous applied state)",
        "production_root": "warp.Runtime.Rollback (lifecycle rollback; controller-loop root from main)",
    },
    # --- SPF lifecycle producers (FB-02 SPF section, 2026-08-04): every counter
    # increments ONLY on the violating branch of the production guards
    # (src/silentpath/hard_gate_producers.go), reachable from the validation
    # controller loop via the release pipeline. ---
    "silent_failure_action_without_authorization_total": {
        "symbol": "AuthorizeRecoveryAction -> Metrics.Inc(MetricSPFActionWithoutAuthorization)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 36,
        "mechanism": "increment-only counter via observability (recovery/canary action without a final action authorization)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_action_with_incomplete_visibility_total": {
        "symbol": "AuthorizeRecoveryAction -> Metrics.Inc(MetricSPFActionIncompleteVisibility)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 40,
        "mechanism": "increment-only counter via observability (active action while capture visibility proofs incomplete)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_destination_only_state_total": {
        "symbol": "DestinationOnlyStateUsed -> Metrics.Inc(MetricSPFDestinationOnlyState)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 69,
        "mechanism": "increment-only counter via observability (decision from destination-only scope)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_cross_client_action_total": {
        "symbol": "AuthorizeRecoveryAction -> Metrics.Inc(MetricSPFCrossClientAction)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 44,
        "mechanism": "increment-only counter via observability (scope.ClientKey != auth.Client)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_cross_service_action_total": {
        "symbol": "AuthorizeRecoveryAction -> Metrics.Inc(MetricSPFCrossServiceAction)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 48,
        "mechanism": "increment-only counter via observability (scope.DomainKey != auth.Domain)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_cross_component_action_total": {
        "symbol": "AuthorizeRecoveryAction -> Metrics.Inc(MetricSPFCrossComponentAction)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 52,
        "mechanism": "increment-only counter via observability (scope.ComponentID != authorized component)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_cross_generation_action_total": {
        "symbol": "AuthorizeRecoveryAction -> Metrics.Inc(MetricSPFCrossGenerationAction)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 56,
        "mechanism": "increment-only counter via observability (scope.ConfigGen != auth.ConfigGen)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_single_signal_auto_fallback_total": {
        "symbol": "AutoFallbackGate -> Metrics.Inc(MetricSPFSingleSignalAutoFallback)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 110,
        "mechanism": "increment-only counter via observability (auto-fallback with fewer than two independent evidence families)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_non_independent_evidence_auto_fallback_total": {
        "symbol": "AutoFallbackGate -> Metrics.Inc(MetricSPFNonIndependentAutoFallback)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 104,
        "mechanism": "increment-only counter via observability (auto-fallback using evidence without declared independent family)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_suppressor_ignored_total": {
        "symbol": "SuppressorGate -> Metrics.Inc(MetricSPFSuppressorIgnored)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 129,
        "mechanism": "increment-only counter via observability (active suppressor bypassed by recovery)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_fast_parallel_false_positive_total": {
        "symbol": "FastParallelFalsePositiveGate -> Metrics.Inc(MetricSPFFastParallelFalsePositive)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 142,
        "mechanism": "increment-only counter via observability (likely-parallel evidence treated as failure)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_recent_success_false_positive_total": {
        "symbol": "SuppressorGate -> Metrics.Inc(MetricSPFRecentSuccessFalsePositive)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 127,
        "mechanism": "increment-only counter via observability (fresh same-scope success suppressor bypassed)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_explicit_server_error_misclassified_total": {
        "symbol": "ExplicitServerErrorGate -> Metrics.Inc(MetricSPFExplicitServerErrorMisclass)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 154,
        "mechanism": "increment-only counter via observability (explicit server response treated as network failure)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_gso_mss_progress_mismatch_total": {
        "symbol": "GsoMssProgressMismatch -> Metrics.Inc(MetricSPFGsoMssProgressMismatch)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 169,
        "mechanism": "increment-only counter via observability (GSO segment bytes not MSS-aligned counted as wire progress)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_ppe_visibility_violation_total": {
        "symbol": "PPEVisibilityViolation -> Metrics.Inc(MetricSPFPPEVisibilityViolation)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 179,
        "mechanism": "increment-only counter via observability (promotion while PPE/offload or GSO-parity proof missing)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_unbounded_probe_total": {
        "symbol": "ProbeGate -> Metrics.Inc(MetricSPFUnboundedProbe)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 189,
        "mechanism": "increment-only counter via observability (differential probe beyond bounded budget)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_unbounded_rotation_total": {
        "symbol": "RotationGate -> Metrics.Inc(MetricSPFUnboundedRotation)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 199,
        "mechanism": "increment-only counter via observability (lease rotation beyond MaxAttempts)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_recursive_transport_fallback_total": {
        "symbol": "TransportFallbackGate -> Metrics.Inc(MetricSPFRecursiveTransportFallback)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 210,
        "mechanism": "increment-only counter via observability (recursive fallback onto the same transport path)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_recovery_without_rollback_target_total": {
        "symbol": "RollbackTargetGate -> Metrics.Inc(MetricSPFRecoveryWithoutRollbackTarget)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 220,
        "mechanism": "increment-only counter via observability (recovery lease without a known rollback target)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_control_regression_promoted_total": {
        "symbol": "ControlRegressionGate -> Metrics.Inc(MetricSPFControlRegressionPromoted)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 231,
        "mechanism": "increment-only counter via observability (promotion while control probe unhealthy/regressed)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_false_positive_budget_ignored_total": {
        "symbol": "FalsePositiveBudgetGate -> Metrics.Inc(MetricSPFFalsePositiveBudgetIgnored)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 242,
        "mechanism": "increment-only counter via observability (recovery while rollback monitor is observe-only after budget breach)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    "silent_failure_user_revert_not_rolled_back_total": {
        "symbol": "UserRevertRollsBack -> Metrics.Inc(MetricSPFUserRevertNotRolledBack)",
        "file": "src/silentpath/hard_gate_producers.go",
        "line": 254,
        "mechanism": "increment-only counter via observability (user revert without matching active lease)",
        "production_root": "silentpath lifecycle guards (authorization -> visibility -> correlation -> recovery -> rollback; release pipeline root from validation)",
    },
    # --- DDI/TGB producers (FB-02 DDI_TGB section, 2026-08-04): every counter
    # increments ONLY on the violating branch of the production guards
    # (src/discovery/hard_gate_producers.go, src/mtproto/hard_gate_producers.go),
    # reachable from the release pipeline via the guided-discovery/bridge
    # controller roots. ---
    "discovery_profile_without_context_validation_total": {
        "symbol": "UseProfileWithContext -> Metrics.Inc(MetricDiscoveryProfileWithoutContextValidation)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 34,
        "mechanism": "increment-only counter via observability (guided discovery from a context mismatch/expired profile)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_stale_without_revalidation_total": {
        "symbol": "UseProfileRevalidated -> Metrics.Inc(MetricDiscoveryProfileStaleWithoutRevalidation)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 44,
        "mechanism": "increment-only counter via observability (stale profile served without revalidation)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_cross_wan_use_total": {
        "symbol": "UseProfileSameWAN -> Metrics.Inc(MetricDiscoveryProfileCrossWANUse)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 54,
        "mechanism": "increment-only counter via observability (profile built for a different WAN fingerprint)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_mutable_runtime_pointer_total": {
        "symbol": "RuntimeProfileBinding -> Metrics.Inc(MetricDiscoveryProfileMutableRuntimePointer)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 65,
        "mechanism": "increment-only counter via observability (runtime handed a mutable profile pointer instead of a snapshot)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_hint_without_provenance_total": {
        "symbol": "UseSearchHint -> Metrics.Inc(MetricDiscoveryProfileHintWithoutProvenance)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 76,
        "mechanism": "increment-only counter via observability (hint with candidate but no provenance)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_hint_overrode_current_baseline_total": {
        "symbol": "HintOrderRespectsBaseline -> Metrics.Inc(MetricDiscoveryProfileHintOverrodeBaseline)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 87,
        "mechanism": "increment-only counter via observability (hint displaced the current baseline from the leading position)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_skipped_target_validation_total": {
        "symbol": "GuidedRunTargetValidated -> Metrics.Inc(MetricDiscoveryProfileSkippedTargetValidation)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 109,
        "mechanism": "increment-only counter via observability (guided run without target-specific validation)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_disabled_exhaustive_fallback_total": {
        "symbol": "ExhaustiveFallbackEnabled -> Metrics.Inc(MetricDiscoveryProfileDisabledExhaustiveFallback)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 119,
        "mechanism": "increment-only counter via observability (guided plan disabled exhaustive fallback)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_direct_production_write_total": {
        "symbol": "ProfileProductionWrite -> Metrics.Inc(MetricDiscoveryProfileDirectProductionWrite)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 129,
        "mechanism": "increment-only counter via observability (direct production write of an unstaged profile)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_allowed_sni_direct_promotion_total": {
        "symbol": "PromoteViaSNI -> Metrics.Inc(MetricDiscoveryProfileAllowedSNIDirectPromotion)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 139,
        "mechanism": "increment-only counter via observability (SNI direct promotion without target validation)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_threshold_out_of_budget_total": {
        "symbol": "CheckHintThreshold -> Metrics.Inc(MetricDiscoveryProfileThresholdOutOfBudget)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 149,
        "mechanism": "increment-only counter via observability (hint threshold above the bounded probe budget)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_capture_gate_bypass_total": {
        "symbol": "PromotionCaptureGate -> Metrics.Inc(MetricDiscoveryProfileCaptureGateBypass)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 159,
        "mechanism": "increment-only counter via observability (discovery promotion while capture gate not ready)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_cross_service_action_total": {
        "symbol": "ProfileActionScope -> Metrics.Inc(MetricDiscoveryProfileCrossServiceAction)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 169,
        "mechanism": "increment-only counter via observability (profile action scope differs from the target service scope)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "discovery_profile_false_pass_total": {
        "symbol": "PublishIssue -> Metrics.Inc(MetricDiscoveryProfileFalsePass)",
        "file": "src/discovery/hard_gate_producers.go",
        "line": 183,
        "mechanism": "increment-only counter via observability (causal A/B bundle published with false promotion)",
        "production_root": "discovery.guards (profile lifecycle -> context/revalidation -> hint planning -> guided run; release pipeline root from validation)",
    },
    "mtproto_bridge_zero_byte_handled_drop_total": {
        "symbol": "ZeroByteHandledDrop -> Metrics.Inc(MetricMTProtoZeroByteHandledDrop)",
        "file": "src/mtproto/hard_gate_producers.go",
        "line": 26,
        "mechanism": "increment-only counter via observability (zero-byte connection recorded as handled)",
        "production_root": "mtproto guards (bridge pending/prefix/route/failure lifecycle; controller-loop root from main)",
    },
    "mtproto_bridge_fixed_5s_destructive_timeout_total": {
        "symbol": "DestructiveTimeout -> Metrics.Inc(MetricMTProtoFixed5sDestructiveTimeout)",
        "file": "src/mtproto/hard_gate_producers.go",
        "line": 36,
        "mechanism": "increment-only counter via observability (fixed 5s destructive timeout instead of adaptive)",
        "production_root": "mtproto guards (bridge pending/prefix/route/failure lifecycle; controller-loop root from main)",
    },
    "mtproto_bridge_unbounded_pending_total": {
        "symbol": "PendingBudgetBounded -> Metrics.Inc(MetricMTProtoUnboundedPending)",
        "file": "src/mtproto/hard_gate_producers.go",
        "line": 46,
        "mechanism": "increment-only counter via observability (unbounded global pending-handshake budget)",
        "production_root": "mtproto guards (bridge pending/prefix/route/failure lifecycle; controller-loop root from main)",
    },
    "mtproto_bridge_pending_per_client_limit_bypass_total": {
        "symbol": "PerClientPendingBounded -> Metrics.Inc(MetricMTProtoPendingPerClientBypass)",
        "file": "src/mtproto/hard_gate_producers.go",
        "line": 57,
        "mechanism": "increment-only counter via observability (per-client pending limit disabled or above global bound)",
        "production_root": "mtproto guards (bridge pending/prefix/route/failure lifecycle; controller-loop root from main)",
    },
    "mtproto_bridge_prefix_loss_total": {
        "symbol": "PrefixHandoffComplete -> Metrics.Inc(MetricMTProtoPrefixLoss)",
        "file": "src/mtproto/hard_gate_producers.go",
        "line": 67,
        "mechanism": "increment-only counter via observability (prefix handoff delivered fewer bytes than captured)",
        "production_root": "mtproto guards (bridge pending/prefix/route/failure lifecycle; controller-loop root from main)",
    },
    "mtproto_bridge_prefix_duplicate_total": {
        "symbol": "PrefixHandoffNonDuplicate -> Metrics.Inc(MetricMTProtoPrefixDuplicate)",
        "file": "src/mtproto/hard_gate_producers.go",
        "line": 77,
        "mechanism": "increment-only counter via observability (prefix handoff replayed more bytes than captured)",
        "production_root": "mtproto guards (bridge pending/prefix/route/failure lifecycle; controller-loop root from main)",
    },
    "mtproto_bridge_route_recursion_total": {
        "symbol": "RoutePlanNonRecursive -> Metrics.Inc(MetricMTProtoRouteRecursion)",
        "file": "src/mtproto/hard_gate_producers.go",
        "line": 87,
        "mechanism": "increment-only counter via observability (route plan executed without recursion guard)",
        "production_root": "mtproto guards (bridge pending/prefix/route/failure lifecycle; controller-loop root from main)",
    },
    "mtproto_bridge_primary_failure_silent_drop_total": {
        "symbol": "PrimaryFailureDisposition -> Metrics.Inc(MetricMTProtoPrimaryFailureSilentDrop)",
        "file": "src/mtproto/hard_gate_producers.go",
        "line": 97,
        "mechanism": "increment-only counter via observability (primary route failure silently dropped instead of fail-open)",
        "production_root": "mtproto guards (bridge pending/prefix/route/failure lifecycle; controller-loop root from main)",
    },
    "mtproto_bridge_overflow_without_reason_total": {
        "symbol": "OverflowWithReason -> Metrics.Inc(MetricMTProtoOverflowWithoutReason)",
        "file": "src/mtproto/hard_gate_producers.go",
        "line": 107,
        "mechanism": "increment-only counter via observability (pending overflow reported without budget attribution)",
        "production_root": "mtproto guards (bridge pending/prefix/route/failure lifecycle; controller-loop root from main)",
    },
    "mtproto_bridge_shutdown_leak_total": {
        "symbol": "ShutdownPendingDrained -> Metrics.Inc(MetricMTProtoShutdownLeak)",
        "file": "src/mtproto/hard_gate_producers.go",
        "line": 121,
        "mechanism": "increment-only counter via observability (shutdown left pending handshake tokens unreleased)",
        "production_root": "mtproto guards (bridge pending/prefix/route/failure lifecycle; controller-loop root from main)",
    },
    # --- FB-29 resolution-erasure / FB-30 multi-vantage producers (mon + abd):
    # producers verified in the FB-29/FB-30 commits; registry entries were
    # hand-maintained in hard_gates_registry.gen.go and are now declared here
    # so regeneration keeps yaml and gen.go consistent (283 gates / 35
    # applicable; previously yaml said 24 verified while gen.go said 35). ---
    "monitor_first_success_erased_address_failures_total": {
        "symbol": "RecordResolutionErasure -> observability.Metrics.Inc(MetricMonitorFirstSuccessErasedAddressFailures)",
        "file": "src/detector/resolution_experiment.go",
        "line": 192,
        "mechanism": "increment-only counter via observability; first-success must never erase sibling address failures (FB-29)",
        "production_root": "detector.SummarizeResolutionDNS -> ErasedByFirstSuccess projection -> RecordResolutionErasure (masked sibling surfaced, never dropped)",
    },
    "monitor_http_hypothesis_from_tcp_tls_only_observer_total": {
        "symbol": "CompareVantage -> stage-aware capability gate -> RecordMultiVantageViolation(violationHTTPHypothesisFromTCPTLSOnly) -> observability.Metrics.Inc(MetricMonitorHttpHypothesisFromTCPTLSOnlyObserver)",
        "file": "src/detector/abd_path.go",
        "line": 164,
        "mechanism": "increment-only counter via observability; a TCP/TLS-only observer must never confirm an HTTP/body hypothesis (FB-30)",
        "production_root": "detector.CompareVantage stage-aware capability gate -> RecordMultiVantageViolation (rejection recorded, NO_OPINION returned)",
    },
    "monitor_observer_unavailable_as_target_failure_total": {
        "symbol": "CompareVantage -> observer unavailable branch -> NO_OPINION (never RecordMultiVantageViolation(violationObserverUnavailableAsFailure))",
        "file": "src/detector/abd_path.go",
        "line": 138,
        "mechanism": "increment-only counter via observability; an unavailable observer must never become a target-failure claim (FB-30)",
        "production_root": "detector.CompareVantage unavailable-gate -> NO_OPINION (no failure claim emitted for unavailable observers)",
    },
    "monitor_exact_endpoint_service_resolution_conflated_total": {
        "symbol": "CompareVantage -> identity/mode-gate -> RecordMultiVantageViolation(violationExactEndpointServiceResolutionConflated) -> observability.Metrics.Inc(MetricMonitorExactEndpointServiceResolutionConflated)",
        "file": "src/detector/abd_path.go",
        "line": 145,
        "mechanism": "increment-only counter via observability; exact-endpoint and independent-resolution evidence must never be conflated (FB-30)",
        "production_root": "detector.CompareVantage identity/mode gate -> RecordMultiVantageViolation (NO_OPINION returned, violation recorded)",
    },
    "monitor_observer_capability_unproven_total": {
        "symbol": "CompareVantage -> stage-aware capability gate (stale/unhealthy or unsupported stage) -> RecordMultiVantageViolation(violationObserverCapabilityUnproven) -> observability.Metrics.Inc(MetricMonitorObserverCapabilityUnproven)",
        "file": "src/detector/abd_path.go",
        "line": 158,
        "mechanism": "increment-only counter via observability; an observer with unproven capability must never produce an opinion (FB-30)",
        "production_root": "detector.CompareVantage stale/unsupported-capability branch -> RecordMultiVantageViolation (NO_OPINION returned)",
    },
    "detector_first_success_erased_address_failures_total": {
        "symbol": "RecordResolutionErasure -> observability.Metrics.Inc(MetricDetectorFirstSuccessErasedAddressFailures)",
        "file": "src/detector/resolution_experiment.go",
        "line": 192,
        "mechanism": "increment-only counter via observability; first-success must never erase sibling address failures (FB-29)",
        "production_root": "detector.SummarizeResolutionDNS -> ErasedByFirstSuccess projection -> RecordResolutionErasure (masked sibling surfaced, never dropped)",
    },
    "detector_multivantage_stage_mismatch_total": {
        "symbol": "CompareVantage -> stage-alignment gate -> RecordMultiVantageViolation(violationStageMismatch) -> observability.Metrics.Inc(MetricDetectorMultiVantageStageMismatch)",
        "file": "src/detector/abd_path.go",
        "line": 151,
        "mechanism": "increment-only counter via observability; multi-vantage comparison must be stage-aligned (FB-30)",
        "production_root": "detector.CompareVantage stage-alignment gate -> RecordMultiVantageViolation (NO_OPINION returned)",
    },
    "detector_http_hypothesis_from_tcp_tls_only_observer_total": {
        "symbol": "CompareVantage -> stage-aware capability gate -> RecordMultiVantageViolation(violationHTTPHypothesisFromTCPTLSOnly) -> observability.Metrics.Inc(MetricDetectorHttpHypothesisFromTCPTLSOnlyObserver)",
        "file": "src/detector/abd_path.go",
        "line": 164,
        "mechanism": "increment-only counter via observability; a TCP/TLS-only observer must never confirm an HTTP/body hypothesis (FB-30)",
        "production_root": "detector.CompareVantage stage-aware capability gate -> RecordMultiVantageViolation (NO_OPINION returned)",
    },
    "detector_observer_unavailable_as_target_failure_total": {
        "symbol": "CompareVantage -> observer unavailable branch -> NO_OPINION (never a failure claim; violation kind reserved until an external call site proves it reachable)",
        "file": "src/detector/abd_path.go",
        "line": 138,
        "mechanism": "increment-only counter via observability; an unavailable observer must never become a target-failure claim (FB-30)",
        "production_root": "detector.CompareVantage unavailable-gate -> NO_OPINION (no failure claim emitted)",
    },
    "detector_exact_endpoint_service_resolution_conflated_total": {
        "symbol": "CompareVantage -> identity/mode-gate -> RecordMultiVantageViolation(violationExactEndpointServiceResolutionConflated) -> observability.Metrics.Inc(MetricDetectorExactEndpointServiceResolutionConflated)",
        "file": "src/detector/abd_path.go",
        "line": 145,
        "mechanism": "increment-only counter via observability; exact-endpoint and independent-resolution evidence must never be conflated (FB-30)",
        "production_root": "detector.CompareVantage identity/mode gate -> RecordMultiVantageViolation (NO_OPINION returned, violation recorded)",
    },
    "detector_observer_capability_unproven_total": {
        "symbol": "CompareVantage -> stage-aware capability gate (stale/unhealthy or unsupported stage) -> RecordMultiVantageViolation(violationObserverCapabilityUnproven) -> observability.Metrics.Inc(MetricDetectorObserverCapabilityUnproven)",
        "file": "src/detector/abd_path.go",
        "line": 158,
        "mechanism": "increment-only counter via observability; an observer with unproven capability must never produce an opinion (FB-30)",
        "production_root": "detector.CompareVantage stale/unsupported-capability branch -> RecordMultiVantageViolation (NO_OPINION returned)",
    },

    # --- MON producers (FB-02 MON section, 2026-08-04): every counter
    # emitted by a guard in src/monitoring/hard_gate_producers.go (sect. 84-92),
    # reachable from the validation controller loop via the release pipeline. ---
    "monitor_observation_direct_action_total": {
        "symbol": "ObservationDirectActionAllowed -> Metrics.Inc(MetricMONObservationDirectAction)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 39,
        "mechanism": "increment-only counter via observability (Observation direct action; MON addendum v1.0 sect. 84)",
        "production_root": "monitoring lifecycle guards (sect. 84; release pipeline root from validation)",
    },
    "monitor_provisional_profile_compiled_total": {
        "symbol": "ProvisionalProfileCompiled -> Metrics.Inc(MetricMONProvisionalProfileCompiled)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 50,
        "mechanism": "increment-only counter via observability (Provisional profile compiled; MON addendum v1.0 sect. 84)",
        "production_root": "monitoring lifecycle guards (sect. 84; release pipeline root from validation)",
    },
    "monitor_passive_discovery_start_total": {
        "symbol": "PassiveDiscoveryStart -> Metrics.Inc(MetricMONPassiveDiscoveryStart)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 60,
        "mechanism": "increment-only counter via observability (Passive discovery start; MON addendum v1.0 sect. 84)",
        "production_root": "monitoring lifecycle guards (sect. 84; release pipeline root from validation)",
    },
    "monitor_passive_warp_enable_total": {
        "symbol": "PassiveWarpEnable -> Metrics.Inc(MetricMONPassiveWarpEnable)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 70,
        "mechanism": "increment-only counter via observability (Passive warp enable; MON addendum v1.0 sect. 84)",
        "production_root": "monitoring lifecycle guards (sect. 84; release pipeline root from validation)",
    },
    "monitor_fast_lane_action_total": {
        "symbol": "FastLaneActionTaken -> Metrics.Inc(MetricMONFastLaneAction)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 80,
        "mechanism": "increment-only counter via observability (Fast lane action; MON addendum v1.0 sect. 84)",
        "production_root": "monitoring lifecycle guards (sect. 84; release pipeline root from validation)",
    },
    "monitor_fast_lane_promoted_as_authoritative_total": {
        "symbol": "FastLanePromotedAsAuthoritative -> Metrics.Inc(MetricMONFastLanePromotedAsAuthoritative)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 91,
        "mechanism": "increment-only counter via observability (Fast lane promoted as authoritative; MON addendum v1.0 sect. 84)",
        "production_root": "monitoring lifecycle guards (sect. 84; release pipeline root from validation)",
    },
    "monitor_destination_only_deep_trigger_total": {
        "symbol": "DeepTriggerOnDestinationOnlyScope -> Metrics.Inc(MetricMONDestinationOnlyDeepTrigger)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 104,
        "mechanism": "increment-only counter via observability (Destination only deep trigger; MON addendum v1.0 sect. 85)",
        "production_root": "monitoring lifecycle guards (sect. 85; release pipeline root from validation)",
    },
    "monitor_cross_client_merge_total": {
        "symbol": "CrossClientMergeAllowed -> Metrics.Inc(MetricMONCrossClientMerge)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 114,
        "mechanism": "increment-only counter via observability (Cross client merge; MON addendum v1.0 sect. 85)",
        "production_root": "monitoring lifecycle guards (sect. 85; release pipeline root from validation)",
    },
    "monitor_cross_service_merge_total": {
        "symbol": "CrossServiceMergeAllowed -> Metrics.Inc(MetricMONCrossServiceMerge)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 123,
        "mechanism": "increment-only counter via observability (Cross service merge; MON addendum v1.0 sect. 85)",
        "production_root": "monitoring lifecycle guards (sect. 85; release pipeline root from validation)",
    },
    "monitor_cross_component_merge_total": {
        "symbol": "CrossComponentMergeAllowed -> Metrics.Inc(MetricMONCrossComponentMerge)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 132,
        "mechanism": "increment-only counter via observability (Cross component merge; MON addendum v1.0 sect. 85)",
        "production_root": "monitoring lifecycle guards (sect. 85; release pipeline root from validation)",
    },
    "monitor_cross_wan_evidence_merge_total": {
        "symbol": "CrossWanEvidenceMergeAllowed -> Metrics.Inc(MetricMONCrossWanEvidenceMerge)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 142,
        "mechanism": "increment-only counter via observability (Cross wan evidence merge; MON addendum v1.0 sect. 85)",
        "production_root": "monitoring lifecycle guards (sect. 85; release pipeline root from validation)",
    },
    "monitor_cross_generation_evidence_merge_total": {
        "symbol": "CrossGenerationEvidenceMergeAllowed -> Metrics.Inc(MetricMONCrossGenerationEvidenceMerge)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 152,
        "mechanism": "increment-only counter via observability (Cross generation evidence merge; MON addendum v1.0 sect. 85)",
        "production_root": "monitoring lifecycle guards (sect. 85; release pipeline root from validation)",
    },
    "monitor_router_origin_as_forwarded_proof_total": {
        "symbol": "RouterOriginAsForwardedProofAllowed -> Metrics.Inc(MetricMONRouterOriginAsForwardedProof)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 163,
        "mechanism": "increment-only counter via observability (Router origin as forwarded proof; MON addendum v1.0 sect. 85)",
        "production_root": "monitoring lifecycle guards (sect. 85; release pipeline root from validation)",
    },
    "monitor_duplicate_evidence_independence_total": {
        "symbol": "DuplicateEvidenceIndependenceAllowed -> Metrics.Inc(MetricMONDupEvidenceIndependence)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 180,
        "mechanism": "increment-only counter via observability (Duplicate evidence independence; MON addendum v1.0 sect. 86)",
        "production_root": "monitoring lifecycle guards (sect. 86; release pipeline root from validation)",
    },
    "monitor_temporal_persistence_without_time_separation_total": {
        "symbol": "TemporalPersistenceWithoutSeparationAllowed -> Metrics.Inc(MetricMONTemporalPersistenceNoSeparation)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 196,
        "mechanism": "increment-only counter via observability (Temporal persistence without time separation; MON addendum v1.0 sect. 86)",
        "production_root": "monitoring lifecycle guards (sect. 86; release pipeline root from validation)",
    },
    "monitor_success_suppressor_ignored_total": {
        "symbol": "SuccessSuppressorIgnoredAllowed -> Metrics.Inc(MetricMONSuccessSuppressorIgnored)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 206,
        "mechanism": "increment-only counter via observability (Success suppressor ignored; MON addendum v1.0 sect. 86)",
        "production_root": "monitoring lifecycle guards (sect. 86; release pipeline root from validation)",
    },
    "monitor_recovered_subject_not_demoted_total": {
        "symbol": "RecoveredSubjectNotDemotedAllowed -> Metrics.Inc(MetricMONRecoveredSubjectNotDemoted)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 217,
        "mechanism": "increment-only counter via observability (Recovered subject not demoted; MON addendum v1.0 sect. 86)",
        "production_root": "monitoring lifecycle guards (sect. 86; release pipeline root from validation)",
    },
    "monitor_expired_evidence_used_total": {
        "symbol": "ExpiredEvidenceUsedAllowed -> Metrics.Inc(MetricMONExpiredEvidenceUsed)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 226,
        "mechanism": "increment-only counter via observability (Expired evidence used; MON addendum v1.0 sect. 86)",
        "production_root": "monitoring lifecycle guards (sect. 86; release pipeline root from validation)",
    },
    "monitor_decay_disabled_without_policy_total": {
        "symbol": "DecayDisabledWithoutPolicyAllowed -> Metrics.Inc(MetricMONDecayDisabledWithoutPolicy)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 237,
        "mechanism": "increment-only counter via observability (Decay disabled without policy; MON addendum v1.0 sect. 86)",
        "production_root": "monitoring lifecycle guards (sect. 86; release pipeline root from validation)",
    },
    "monitor_probe_without_resolution_binding_total": {
        "symbol": "ProbeWithoutResolutionBindingAllowed -> Metrics.Inc(MetricMONProbeWithoutResolutionBinding)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 250,
        "mechanism": "increment-only counter via observability (Probe without resolution binding; MON addendum v1.0 sect. 87)",
        "production_root": "monitoring lifecycle guards (sect. 87; release pipeline root from validation)",
    },
    "monitor_client_dns_answer_replaced_silently_total": {
        "symbol": "ClientDNSAnswerReplacedSilentlyAllowed -> Metrics.Inc(MetricMONClientDNSAnswerReplacedSilently)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 261,
        "mechanism": "increment-only counter via observability (Client dns answer replaced silently; MON addendum v1.0 sect. 87)",
        "production_root": "monitoring lifecycle guards (sect. 87; release pipeline root from validation)",
    },
    "monitor_cname_terminal_ip_misattributed_total": {
        "symbol": "CnameTerminalIPMisattributedAllowed -> Metrics.Inc(MetricMONCnameTerminalIPMisattributed)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 277,
        "mechanism": "increment-only counter via observability (Cname terminal ip misattributed; MON addendum v1.0 sect. 87)",
        "production_root": "monitoring lifecycle guards (sect. 87; release pipeline root from validation)",
    },
    "monitor_multi_ip_partial_failure_hidden_total": {
        "symbol": "MultiIPPartialFailureHiddenAllowed -> Metrics.Inc(MetricMONMultiIPPartialFailureHidden)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 294,
        "mechanism": "increment-only counter via observability (Multi ip partial failure hidden; MON addendum v1.0 sect. 87)",
        "production_root": "monitoring lifecycle guards (sect. 87; release pipeline root from validation)",
    },
    "monitor_stale_resolution_used_as_exact_proof_total": {
        "symbol": "StaleResolutionUsedAsExactProofAllowed -> Metrics.Inc(MetricMONStaleResolutionExactProof)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 304,
        "mechanism": "increment-only counter via observability (Stale resolution used as exact proof; MON addendum v1.0 sect. 87)",
        "production_root": "monitoring lifecycle guards (sect. 87; release pipeline root from validation)",
    },
    "monitor_trigger_without_visibility_total": {
        "symbol": "TriggerWithoutVisibilityAllowed -> Metrics.Inc(MetricMONTriggerWithoutVisibility)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 316,
        "mechanism": "increment-only counter via observability (Trigger without visibility; MON addendum v1.0 sect. 88)",
        "production_root": "monitoring lifecycle guards (sect. 88; release pipeline root from validation)",
    },
    "monitor_trigger_without_budget_total": {
        "symbol": "TriggerWithoutBudgetAllowed -> Metrics.Inc(MetricMONTriggerWithoutBudget)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 326,
        "mechanism": "increment-only counter via observability (Trigger without budget; MON addendum v1.0 sect. 88)",
        "production_root": "monitoring lifecycle guards (sect. 88; release pipeline root from validation)",
    },
    "monitor_trigger_during_global_wan_failure_total": {
        "symbol": "TriggerDuringGlobalWanFailureAllowed -> Metrics.Inc(MetricMONTriggerDuringGlobalWanFailure)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 336,
        "mechanism": "increment-only counter via observability (Trigger during global wan failure; MON addendum v1.0 sect. 88)",
        "production_root": "monitoring lifecycle guards (sect. 88; release pipeline root from validation)",
    },
    "monitor_trigger_with_stale_source_heartbeat_total": {
        "symbol": "TriggerWithStaleSourceHeartbeatAllowed -> Metrics.Inc(MetricMONTriggerWithStaleHeartbeat)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 346,
        "mechanism": "increment-only counter via observability (Trigger with stale source heartbeat; MON addendum v1.0 sect. 88)",
        "production_root": "monitoring lifecycle guards (sect. 88; release pipeline root from validation)",
    },
    "monitor_duplicate_concurrent_abd_run_total": {
        "symbol": "DuplicateConcurrentABDRunAllowed -> Metrics.Inc(MetricMONDupConcurrentABDRun)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 357,
        "mechanism": "increment-only counter via observability (Duplicate concurrent abd run; MON addendum v1.0 sect. 88)",
        "production_root": "monitoring lifecycle guards (sect. 88; release pipeline root from validation)",
    },
    "monitor_unbounded_target_intake_total": {
        "symbol": "UnboundedTargetIntakeAllowed -> Metrics.Inc(MetricMONUnboundedTargetIntake)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 368,
        "mechanism": "increment-only counter via observability (Unbounded target intake; MON addendum v1.0 sect. 88)",
        "production_root": "monitoring lifecycle guards (sect. 88; release pipeline root from validation)",
    },
    "monitor_unbounded_probe_parallelism_total": {
        "symbol": "UnboundedProbeParallelismAllowed -> Metrics.Inc(MetricMONUnboundedProbeParallelism)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 378,
        "mechanism": "increment-only counter via observability (Unbounded probe parallelism; MON addendum v1.0 sect. 88)",
        "production_root": "monitoring lifecycle guards (sect. 88; release pipeline root from validation)",
    },
    "monitor_self_interference_total": {
        "symbol": "SelfInterferenceAllowed -> Metrics.Inc(MetricMONSelfInterference)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 388,
        "mechanism": "increment-only counter via observability (Self interference; MON addendum v1.0 sect. 88)",
        "production_root": "monitoring lifecycle guards (sect. 88; release pipeline root from validation)",
    },
    "monitor_reference_result_as_action_authorization_total": {
        "symbol": "ReferenceResultAsActionAuthorizationAllowed -> Metrics.Inc(MetricMONReferenceResultAsAuthorization)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 401,
        "mechanism": "increment-only counter via observability (Reference result as action authorization; MON addendum v1.0 sect. 89)",
        "production_root": "monitoring lifecycle guards (sect. 89; release pipeline root from validation)",
    },
    "monitor_abd_request_without_target_plan_total": {
        "symbol": "ABDRequestWithoutTargetPlanAllowed -> Metrics.Inc(MetricMONABDRequestWithoutTargetPlan)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 413,
        "mechanism": "increment-only counter via observability (Abd request without target plan; MON addendum v1.0 sect. 90)",
        "production_root": "monitoring lifecycle guards (sect. 90; release pipeline root from validation)",
    },
    "monitor_abd_partial_result_profile_ready_total": {
        "symbol": "ABDPartialResultProfileReadyAllowed -> Metrics.Inc(MetricMONABDPartialResultProfileReady)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 423,
        "mechanism": "increment-only counter via observability (Abd partial result profile ready; MON addendum v1.0 sect. 90)",
        "production_root": "monitoring lifecycle guards (sect. 90; release pipeline root from validation)",
    },
    "monitor_abd_result_bypassed_ddi_total": {
        "symbol": "ABDResultBypassedDDIAllowed -> Metrics.Inc(MetricMONABDResultBypassedDDI)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 433,
        "mechanism": "increment-only counter via observability (Abd result bypassed ddi; MON addendum v1.0 sect. 90)",
        "production_root": "monitoring lifecycle guards (sect. 90; release pipeline root from validation)",
    },
    "monitor_discovery_without_authoritative_profile_total": {
        "symbol": "DiscoveryWithoutAuthoritativeProfileAllowed -> Metrics.Inc(MetricMONDiscoveryWithoutAuthProfile)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 443,
        "mechanism": "increment-only counter via observability (Discovery without authoritative profile; MON addendum v1.0 sect. 90)",
        "production_root": "monitoring lifecycle guards (sect. 90; release pipeline root from validation)",
    },
    "monitor_discovery_skipped_mandatory_baseline_total": {
        "symbol": "DiscoverySkippedMandatoryBaselineAllowed -> Metrics.Inc(MetricMONDiscoverySkippedMandatoryBaseline)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 458,
        "mechanism": "increment-only counter via observability (Discovery skipped mandatory baseline; MON addendum v1.0 sect. 90)",
        "production_root": "monitoring lifecycle guards (sect. 90; release pipeline root from validation)",
    },
    "monitor_recommendation_without_scope_total": {
        "symbol": "RecommendationWithoutScopeAllowed -> Metrics.Inc(MetricMONRecommendationWithoutScope)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 469,
        "mechanism": "increment-only counter via observability (Recommendation without scope; MON addendum v1.0 sect. 90)",
        "production_root": "monitoring lifecycle guards (sect. 90; release pipeline root from validation)",
    },
    "monitor_warp_recommendation_without_ip_path_evidence_total": {
        "symbol": "WarpRecommendationWithoutIPPathAllowed -> Metrics.Inc(MetricMONWarpRecommendationWithoutIPPath)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 479,
        "mechanism": "increment-only counter via observability (Warp recommendation without ip path evidence; MON addendum v1.0 sect. 90)",
        "production_root": "monitoring lifecycle guards (sect. 90; release pipeline root from validation)",
    },
    "monitor_legacy_watchdog_direct_apply_total": {
        "symbol": "LegacyWatchdogDirectApplyAllowed -> Metrics.Inc(MetricMONLegacyWatchdogDirectApply)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 491,
        "mechanism": "increment-only counter via observability (Legacy watchdog direct apply; MON addendum v1.0 sect. 91)",
        "production_root": "monitoring lifecycle guards (sect. 91; release pipeline root from validation)",
    },
    "monitor_legacy_watchdog_created_unvalidated_set_total": {
        "symbol": "LegacyWatchdogCreatedUnvalidatedSetAllowed -> Metrics.Inc(MetricMONLegacyWatchdogUnvalidatedSet)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 501,
        "mechanism": "increment-only counter via observability (Legacy watchdog created unvalidated set; MON addendum v1.0 sect. 91)",
        "production_root": "monitoring lifecycle guards (sect. 91; release pipeline root from validation)",
    },
    "monitor_legacy_watchdog_overwrote_set_without_canary_total": {
        "symbol": "LegacyWatchdogOverwriteWithoutCanaryAllowed -> Metrics.Inc(MetricMONLegacyWatchdogOverwriteNoCanary)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 511,
        "mechanism": "increment-only counter via observability (Legacy watchdog overwrote set without canary; MON addendum v1.0 sect. 91)",
        "production_root": "monitoring lifecycle guards (sect. 91; release pipeline root from validation)",
    },
    "monitor_legacy_api_projection_mutation_total": {
        "symbol": "LegacyAPIProjectionMutationAllowed -> Metrics.Inc(MetricMONLegacyAPIProjectionMutation)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 522,
        "mechanism": "increment-only counter via observability (Legacy api projection mutation; MON addendum v1.0 sect. 91)",
        "production_root": "monitoring lifecycle guards (sect. 91; release pipeline root from validation)",
    },
    "monitor_shadow_and_active_writer_overlap_total": {
        "symbol": "ShadowActiveWriterOverlapAllowed -> Metrics.Inc(MetricMONShadowActiveWriterOverlap)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 532,
        "mechanism": "increment-only counter via observability (Shadow and active writer overlap; MON addendum v1.0 sect. 91)",
        "production_root": "monitoring lifecycle guards (sect. 91; release pipeline root from validation)",
    },
    "monitor_required_event_drop_hidden_total": {
        "symbol": "RequiredEventDropHiddenAllowed -> Metrics.Inc(MetricMONRequiredEventDropHidden)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 544,
        "mechanism": "increment-only counter via observability (Required event drop hidden; MON addendum v1.0 sect. 92)",
        "production_root": "monitoring lifecycle guards (sect. 92; release pipeline root from validation)",
    },
    "monitor_source_heartbeat_stale_auto_diagnose_total": {
        "symbol": "SourceHeartbeatStaleAutoDiagnoseAllowed -> Metrics.Inc(MetricMONSourceHeartbeatStaleAutoDiagnose)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 555,
        "mechanism": "increment-only counter via observability (Source heartbeat stale auto diagnose; MON addendum v1.0 sect. 92)",
        "production_root": "monitoring lifecycle guards (sect. 92; release pipeline root from validation)",
    },
    "monitor_checkpoint_corruption_false_ready_total": {
        "symbol": "CheckpointCorruptionFalseReadyAllowed -> Metrics.Inc(MetricMONCheckpointCorruptionFalseReady)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 565,
        "mechanism": "increment-only counter via observability (Checkpoint corruption false ready; MON addendum v1.0 sect. 92)",
        "production_root": "monitoring lifecycle guards (sect. 92; release pipeline root from validation)",
    },
    "monitor_restart_reused_expired_lease_total": {
        "symbol": "RestartReusedExpiredLeaseAllowed -> Metrics.Inc(MetricMONRestartReusedExpiredLease)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 575,
        "mechanism": "increment-only counter via observability (Restart reused expired lease; MON addendum v1.0 sect. 92)",
        "production_root": "monitoring lifecycle guards (sect. 92; release pipeline root from validation)",
    },
    "monitor_sensitive_dns_history_export_total": {
        "symbol": "SensitiveDNSHistoryExportAllowed -> Metrics.Inc(MetricMONSensitiveDNSHistoryExport)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 585,
        "mechanism": "increment-only counter via observability (Sensitive dns history export; MON addendum v1.0 sect. 92)",
        "production_root": "monitoring lifecycle guards (sect. 92; release pipeline root from validation)",
    },
    "monitor_secret_trace_leak_total": {
        "symbol": "SecretTraceLeakAllowed -> Metrics.Inc(MetricMONSecretTraceLeak)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 595,
        "mechanism": "increment-only counter via observability (Secret trace leak; MON addendum v1.0 sect. 92)",
        "production_root": "monitoring lifecycle guards (sect. 92; release pipeline root from validation)",
    },
    "monitor_high_cardinality_metric_label_total": {
        "symbol": "HighCardinalityMetricLabelAllowed -> Metrics.Inc(MetricMONHighCardinalityMetricLabel)",
        "file": "src/monitoring/hard_gate_producers.go",
        "line": 605,
        "mechanism": "increment-only counter via observability (High cardinality metric label; MON addendum v1.0 sect. 92)",
        "production_root": "monitoring lifecycle guards (sect. 92; release pipeline root from validation)",
    },

    # --- ABD producers (FB-02 ABD section, 2026-08-04): every counter
    # emitted by a guard in src/detector/hard_gate_producers.go (sect. 39-42),
    # reachable from the validation controller loop via the release pipeline. ---
    "detector_single_probe_confirmed_total": {
        "symbol": "SingleProbeConfirmedAllowed -> Metrics.Inc(MetricABDSingleProbeConfirmed)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 35,
        "mechanism": "increment-only counter via observability (Single probe confirmed; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_exception_string_only_confirmed_total": {
        "symbol": "ExceptionStringOnlyConfirmedAllowed -> Metrics.Inc(MetricABDExceptionStringOnlyConfirmed)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 45,
        "mechanism": "increment-only counter via observability (Exception string only confirmed; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_static_target_only_high_confidence_total": {
        "symbol": "StaticTargetOnlyHighConfidenceAllowed -> Metrics.Inc(MetricABDStaticTargetOnlyHighConfidence)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 55,
        "mechanism": "increment-only counter via observability (Static target only high confidence; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_self_interference_total": {
        "symbol": "SelfInterferenceAllowed -> Metrics.Inc(MetricABDSelfInterference)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 65,
        "mechanism": "increment-only counter via observability (Self interference; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_native_path_unproven_total": {
        "symbol": "NativePathUnprovenAllowed -> Metrics.Inc(MetricABDNativePathUnproven)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 75,
        "mechanism": "increment-only counter via observability (Native path unproven; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_capture_invalid_packet_verdict_total": {
        "symbol": "CaptureInvalidPacketVerdictAllowed -> Metrics.Inc(MetricABDCaptureInvalidPacketVerdict)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 85,
        "mechanism": "increment-only counter via observability (Capture invalid packet verdict; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_control_failure_ignored_total": {
        "symbol": "ControlFailureIgnoredAllowed -> Metrics.Inc(MetricABDControlFailureIgnored)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 95,
        "mechanism": "increment-only counter via observability (Control failure ignored; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_duplicate_evidence_confidence_increase_total": {
        "symbol": "DuplicateEvidenceConfidenceIncreaseAllowed -> Metrics.Inc(MetricABDDupEvidenceConfidenceIncrease)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 117,
        "mechanism": "increment-only counter via observability (Duplicate evidence confidence increase; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_cross_component_evidence_merge_total": {
        "symbol": "CrossComponentEvidenceMergeAllowed -> Metrics.Inc(MetricABDCrossComponentEvidenceMerge)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 127,
        "mechanism": "increment-only counter via observability (Cross component evidence merge; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_cross_generation_evidence_merge_total": {
        "symbol": "CrossGenerationEvidenceMergeAllowed -> Metrics.Inc(MetricABDCrossGenerationEvidenceMerge)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 137,
        "mechanism": "increment-only counter via observability (Cross generation evidence merge; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_unbounded_dynamic_scan_total": {
        "symbol": "UnboundedDynamicScanAllowed -> Metrics.Inc(MetricABDUnboundedDynamicScan)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 147,
        "mechanism": "increment-only counter via observability (Unbounded dynamic scan; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_resource_budget_bypass_total": {
        "symbol": "ResourceBudgetBypassAllowed -> Metrics.Inc(MetricABDResourceBudgetBypass)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 157,
        "mechanism": "increment-only counter via observability (Resource budget bypass; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_sensitive_export_total": {
        "symbol": "SensitiveExportAllowed -> Metrics.Inc(MetricABDSensitiveExport)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 166,
        "mechanism": "increment-only counter via observability (Sensitive export; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_host_dead_from_single_reference_failure_total": {
        "symbol": "HostDeadFromSingleReferenceFailureAllowed -> Metrics.Inc(MetricABDHostDeadSingleReferenceFailure)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 176,
        "mechanism": "increment-only counter via observability (Host dead from single reference failure; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_reference_path_unhealthy_used_total": {
        "symbol": "ReferencePathUnhealthyUsedAllowed -> Metrics.Inc(MetricABDReferencePathUnhealthyUsed)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 186,
        "mechanism": "increment-only counter via observability (Reference path unhealthy used; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_reference_path_used_as_action_authorization_total": {
        "symbol": "ReferencePathUsedAsActionAuthorizationAllowed -> Metrics.Inc(MetricABDReferencePathAsActionAuth)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 196,
        "mechanism": "increment-only counter via observability (Reference path used as action authorization; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_partial_run_profile_compiled_total": {
        "symbol": "PartialRunProfileCompiledAllowed -> Metrics.Inc(MetricABDPartialRunProfileCompiled)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 206,
        "mechanism": "increment-only counter via observability (Partial run profile compiled; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_resume_cross_network_context_total": {
        "symbol": "ResumeCrossNetworkContextAllowed -> Metrics.Inc(MetricABDResumeCrossNetworkContext)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 216,
        "mechanism": "increment-only counter via observability (Resume cross network context; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_capacity_self_interference_total": {
        "symbol": "CapacitySelfInterferenceAllowed -> Metrics.Inc(MetricABDCapacitySelfInterference)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 226,
        "mechanism": "increment-only counter via observability (Capacity self interference; ABD addendum v1.2 sect. 39)",
        "production_root": "detector lifecycle guards (sect. 39; release pipeline root from validation)",
    },
    "detector_dns_single_resolver_spoof_confirmed_total": {
        "symbol": "DNSSingleResolverSpoofConfirmedAllowed -> Metrics.Inc(MetricABDDNSSingleResolverSpoof)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 238,
        "mechanism": "increment-only counter via observability (Dns single resolver spoof confirmed; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_dns_cdn_variance_misclassified_total": {
        "symbol": "DNSCdnVarianceMisclassifiedAllowed -> Metrics.Inc(MetricABDDNSCdnVarianceMisclassified)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 248,
        "mechanism": "increment-only counter via observability (Dns cdn variance misclassified; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_unverified_mitm_verdict_total": {
        "symbol": "UnverifiedMITMVerdictAllowed -> Metrics.Inc(MetricABDUnverifiedMITMVerdict)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 257,
        "mechanism": "increment-only counter via observability (Unverified mitm verdict; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_tls_availability_integrity_conflation_total": {
        "symbol": "TLSAvailabilityIntegrityConflationAllowed -> Metrics.Inc(MetricABDTLSAvailabilityIntegrityConflate)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 267,
        "mechanism": "increment-only counter via observability (Tls availability integrity conflation; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_tls_fingerprint_unlabeled_total": {
        "symbol": "TLSFingerprintUnlabeledAllowed -> Metrics.Inc(MetricABDTLSFingerprintUnlabeled)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 276,
        "mechanism": "increment-only counter via observability (Tls fingerprint unlabeled; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_quic_single_target_global_udp_verdict_total": {
        "symbol": "QUICSingleTargetGlobalUDPVerdictAllowed -> Metrics.Inc(MetricABDQUICSingleTargetGlobalUDP)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 286,
        "mechanism": "increment-only counter via observability (Quic single target global udp verdict; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_quic_tcp_evidence_conflation_total": {
        "symbol": "QUICTCPEvidenceConflationAllowed -> Metrics.Inc(MetricABDQUICTCPEvidenceConflation)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 296,
        "mechanism": "increment-only counter via observability (Quic tcp evidence conflation; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_valid_application_error_dpi_total": {
        "symbol": "ValidApplicationErrorDPIAllowed -> Metrics.Inc(MetricABDValidAppErrorDPI)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 306,
        "mechanism": "increment-only counter via observability (Valid application error dpi; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_head_only_available_verdict_total": {
        "symbol": "HeadOnlyAvailableVerdictAllowed -> Metrics.Inc(MetricABDHeadOnlyAvailableVerdict)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 315,
        "mechanism": "increment-only counter via observability (Head only available verdict; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_partial_progress_discarded_total": {
        "symbol": "PartialProgressDiscardedAllowed -> Metrics.Inc(MetricABDPartialProgressDiscarded)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 325,
        "mechanism": "increment-only counter via observability (Partial progress discarded; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_small_object_classified_throttled_total": {
        "symbol": "SmallObjectClassifiedThrottledAllowed -> Metrics.Inc(MetricABDSmallObjectClassifiedThrottled)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 335,
        "mechanism": "increment-only counter via observability (Small object classified throttled; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_fixed_16kb_window_confirmed_without_profile_total": {
        "symbol": "Fixed16kbWindowConfirmedWithoutProfileAllowed -> Metrics.Inc(MetricABDFixed16kbWindowNoProfile)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 345,
        "mechanism": "increment-only counter via observability (Fixed 16kb window confirmed without profile; ABD addendum v1.2 sect. 40)",
        "production_root": "detector lifecycle guards (sect. 40; release pipeline root from validation)",
    },
    "detector_packet_threshold_reported_as_byte_threshold_total": {
        "symbol": "PacketThresholdReportedAsByteThresholdAllowed -> Metrics.Inc(MetricABDPacketThresholdAsByte)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 357,
        "mechanism": "increment-only counter via observability (Packet threshold reported as byte threshold; ABD addendum v1.2 sect. 41)",
        "production_root": "detector lifecycle guards (sect. 41; release pipeline root from validation)",
    },
    "detector_byte_threshold_reported_as_packet_threshold_total": {
        "symbol": "ByteThresholdReportedAsPacketThresholdAllowed -> Metrics.Inc(MetricABDByteThresholdAsPacket)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 367,
        "mechanism": "increment-only counter via observability (Byte threshold reported as packet threshold; ABD addendum v1.2 sect. 41)",
        "production_root": "detector lifecycle guards (sect. 41; release pipeline root from validation)",
    },
    "detector_gso_skb_count_as_wire_packet_total": {
        "symbol": "GsoSkbCountAsWirePacketAllowed -> Metrics.Inc(MetricABDGsoSkbCountAsWirePacket)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 377,
        "mechanism": "increment-only counter via observability (Gso skb count as wire packet; ABD addendum v1.2 sect. 41)",
        "production_root": "detector lifecycle guards (sect. 41; release pipeline root from validation)",
    },
    "detector_single_origin_l4_budget_confirmed_total": {
        "symbol": "SingleOriginL4BudgetConfirmedAllowed -> Metrics.Inc(MetricABDSingleOriginL4BudgetConfirmed)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 387,
        "mechanism": "increment-only counter via observability (Single origin l4 budget confirmed; ABD addendum v1.2 sect. 41)",
        "production_root": "detector lifecycle guards (sect. 41; release pipeline root from validation)",
    },
    "detector_server_header_limit_dpi_total": {
        "symbol": "ServerHeaderLimitDPIDeniedAllowed -> Metrics.Inc(MetricABDServerHeaderLimitDPI)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 397,
        "mechanism": "increment-only counter via observability (Server header limit dpi; ABD addendum v1.2 sect. 41)",
        "production_root": "detector lifecycle guards (sect. 41; release pipeline root from validation)",
    },
    "detector_retransmission_counted_as_progress_total": {
        "symbol": "RetransmissionCountedAsProgressAllowed -> Metrics.Inc(MetricABDRetransmissionAsProgress)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 407,
        "mechanism": "increment-only counter via observability (Retransmission counted as progress; ABD addendum v1.2 sect. 41)",
        "production_root": "detector lifecycle guards (sect. 41; release pipeline root from validation)",
    },
    "detector_l4_threshold_without_controls_total": {
        "symbol": "L4ThresholdWithoutControlsAllowed -> Metrics.Inc(MetricABDL4ThresholdWithoutControls)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 417,
        "mechanism": "increment-only counter via observability (L4 threshold without controls; ABD addendum v1.2 sect. 41)",
        "production_root": "detector lifecycle guards (sect. 41; release pipeline root from validation)",
    },
    "blocking_profile_without_target_plan_total": {
        "symbol": "BlockingProfileWithoutTargetPlanAllowed -> Metrics.Inc(MetricABDBlockingProfileWithoutTargetPlan)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 429,
        "mechanism": "increment-only counter via observability (Without target plan; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "blocking_profile_without_network_context_total": {
        "symbol": "BlockingProfileWithoutNetworkContextAllowed -> Metrics.Inc(MetricABDBlockingProfileWithoutNetCtx)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 439,
        "mechanism": "increment-only counter via observability (Without network context; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "blocking_profile_without_provenance_total": {
        "symbol": "BlockingProfileWithoutProvenanceAllowed -> Metrics.Inc(MetricABDBlockingProfileWithoutProvenance)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 449,
        "mechanism": "increment-only counter via observability (Without provenance; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "blocking_profile_mutated_after_compile_total": {
        "symbol": "BlockingProfileMutatedAfterCompileAllowed -> Metrics.Inc(MetricABDBlockingProfileMutatedAfterCompile)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 459,
        "mechanism": "increment-only counter via observability (Mutated after compile; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "blocking_profile_high_confidence_with_contradiction_total": {
        "symbol": "BlockingProfileHighConfidenceWithContradictionAllowed -> Metrics.Inc(MetricABDBlockingProfileHighConfidenceContradiction)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 469,
        "mechanism": "increment-only counter via observability (High confidence with contradiction; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "blocking_profile_direct_action_authorization_total": {
        "symbol": "BlockingProfileDirectActionAuthorizationAllowed -> Metrics.Inc(MetricABDBlockingProfileDirectActionAuth)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 479,
        "mechanism": "increment-only counter via observability (Direct action authorization; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "blocking_profile_direct_production_write_total": {
        "symbol": "BlockingProfileDirectProductionWriteAllowed -> Metrics.Inc(MetricABDBlockingProfileDirectProdWrite)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 489,
        "mechanism": "increment-only counter via observability (Direct production write; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_skipped_baseline_total": {
        "symbol": "GuidedSearchSkippedBaselineAllowed -> Metrics.Inc(MetricABDGuidedSearchSkippedBaseline)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 504,
        "mechanism": "increment-only counter via observability (Skipped baseline; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_disabled_full_fallback_total": {
        "symbol": "GuidedSearchDisabledFullFallbackAllowed -> Metrics.Inc(MetricABDGuidedSearchDisabledFullFallback)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 515,
        "mechanism": "increment-only counter via observability (Disabled full fallback; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_profile_overrode_current_baseline_total": {
        "symbol": "GuidedSearchProfileOverrodeBaselineAllowed -> Metrics.Inc(MetricABDGuidedSearchOverrodeBaseline)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 525,
        "mechanism": "increment-only counter via observability (Profile overrode current baseline; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_target_unvalidated_promotion_total": {
        "symbol": "GuidedSearchTargetUnvalidatedPromotionAllowed -> Metrics.Inc(MetricABDGuidedSearchUnvalidatedPromotion)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 535,
        "mechanism": "increment-only counter via observability (Target unvalidated promotion; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_cross_service_action_total": {
        "symbol": "GuidedSearchCrossServiceActionAllowed -> Metrics.Inc(MetricABDGuidedSearchCrossServiceAction)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 545,
        "mechanism": "increment-only counter via observability (Cross service action; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_white_sni_direct_promotion_total": {
        "symbol": "GuidedSearchWhiteSNIDirectPromotionAllowed -> Metrics.Inc(MetricABDGuidedSearchWhiteSNIDirectPromotion)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 555,
        "mechanism": "increment-only counter via observability (White sni direct promotion; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_false_savings_report_total": {
        "symbol": "GuidedSearchFalseSavingsReportAllowed -> Metrics.Inc(MetricABDGuidedSearchFalseSavingsReport)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 565,
        "mechanism": "increment-only counter via observability (False savings report; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_required_component_uncovered_total": {
        "symbol": "GuidedSearchRequiredComponentUncoveredAllowed -> Metrics.Inc(MetricABDGuidedSearchRequiredComponentUncovered)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 580,
        "mechanism": "increment-only counter via observability (Required component uncovered; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_coverage_ignored_control_regression_total": {
        "symbol": "GuidedSearchCoverageIgnoredControlRegressionAllowed -> Metrics.Inc(MetricABDGuidedSearchCoverageIgnoredControlRegression)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 591,
        "mechanism": "increment-only counter via observability (Coverage ignored control regression; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_cross_service_set_cover_total": {
        "symbol": "GuidedSearchCrossServiceSetCoverAllowed -> Metrics.Inc(MetricABDGuidedSearchCrossServiceSetCover)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 601,
        "mechanism": "increment-only counter via observability (Cross service set cover; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_excluded_target_hidden_total": {
        "symbol": "GuidedSearchExcludedTargetHiddenAllowed -> Metrics.Inc(MetricABDGuidedSearchExcludedTargetHidden)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 616,
        "mechanism": "increment-only counter via observability (Excluded target hidden; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_more_complex_candidate_preferred_without_gain_total": {
        "symbol": "GuidedSearchMoreComplexPreferredWithoutGainAllowed -> Metrics.Inc(MetricABDGuidedSearchMoreComplexPreferredNoGain)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 627,
        "mechanism": "increment-only counter via observability (More complex candidate preferred without gain; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "guided_search_unverified_shortlist_promotion_total": {
        "symbol": "GuidedSearchUnverifiedShortlistPromotionAllowed -> Metrics.Inc(MetricABDGuidedSearchUnverifiedShortlist)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 637,
        "mechanism": "increment-only counter via observability (Unverified shortlist promotion; ABD addendum v1.2 sect. 42)",
        "production_root": "detector lifecycle guards (sect. 42; release pipeline root from validation)",
    },
    "detector_monitor_request_direct_action_total": {
        "symbol": "MonitorRequestDirectActionAllowed -> Metrics.Inc(MetricABDMonitorRequestDirectAction)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 649,
        "mechanism": "increment-only counter via observability (Monitor request direct action; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_monitor_request_without_target_plan_overlay_total": {
        "symbol": "MonitorRequestWithoutTargetPlanOverlayAllowed -> Metrics.Inc(MetricABDMonitorRequestWithoutTargetPlan)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 659,
        "mechanism": "increment-only counter via observability (Monitor request without target plan overlay; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_monitor_request_without_network_context_total": {
        "symbol": "MonitorRequestWithoutNetworkContextAllowed -> Metrics.Inc(MetricABDMonitorRequestWithoutNetworkCtx)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 669,
        "mechanism": "increment-only counter via observability (Monitor request without network context; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_monitor_request_without_config_generation_total": {
        "symbol": "MonitorRequestWithoutConfigGenerationAllowed -> Metrics.Inc(MetricABDMonitorRequestWithoutConfigGen)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 679,
        "mechanism": "increment-only counter via observability (Monitor request without config generation; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_monitor_request_without_budget_token_total": {
        "symbol": "MonitorRequestWithoutBudgetTokenAllowed -> Metrics.Inc(MetricABDMonitorRequestWithoutBudgetToken)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 689,
        "mechanism": "increment-only counter via observability (Monitor request without budget token; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_monitor_request_expired_accepted_total": {
        "symbol": "MonitorRequestExpiredAcceptedAllowed -> Metrics.Inc(MetricABDMonitorRequestExpiredAccepted)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 699,
        "mechanism": "increment-only counter via observability (Monitor request expired accepted; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_provisional_monitor_evidence_profile_compiled_total": {
        "symbol": "ProvisionalMonitorEvidenceProfileCompiledAllowed -> Metrics.Inc(MetricABDProvisionalMonitorProfileCompiled)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 709,
        "mechanism": "increment-only counter via observability (Provisional monitor evidence profile compiled; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_passive_observation_counted_as_independent_probe_total": {
        "symbol": "PassiveObservationCountedAsIndependentProbeAllowed -> Metrics.Inc(MetricABDPassiveObservationAsIndependentProbe)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 719,
        "mechanism": "increment-only counter via observability (Passive observation counted as independent probe; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_monitor_recurrence_counted_as_evidence_independence_total": {
        "symbol": "MonitorRecurrenceCountedAsIndependenceAllowed -> Metrics.Inc(MetricABDMonitorRecurrenceAsIndependence)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 729,
        "mechanism": "increment-only counter via observability (Monitor recurrence counted as evidence independence; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_client_resolution_replaced_silently_total": {
        "symbol": "ClientResolutionReplacedSilentlyAllowed -> Metrics.Inc(MetricABDClientResolutionReplacedSilently)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 739,
        "mechanism": "increment-only counter via observability (Client resolution replaced silently; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_probe_without_resolution_binding_total": {
        "symbol": "ProbeWithoutResolutionBindingAllowed -> Metrics.Inc(MetricABDProbeWithoutResolutionBinding)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 749,
        "mechanism": "increment-only counter via observability (Probe without resolution binding; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_cname_terminal_ip_misattributed_total": {
        "symbol": "CnameTerminalIPMisattributedAllowed -> Metrics.Inc(MetricABDCnameTerminalIPMisattributed)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 764,
        "mechanism": "increment-only counter via observability (Cname terminal ip misattributed; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_multi_ip_partial_failure_hidden_total": {
        "symbol": "MultiIPPartialFailureHiddenAllowed -> Metrics.Inc(MetricABDMultiIPPartialFailureHidden)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 781,
        "mechanism": "increment-only counter via observability (Multi ip partial failure hidden; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_stale_client_resolution_used_total": {
        "symbol": "StaleClientResolutionUsedAllowed -> Metrics.Inc(MetricABDStaleClientResolutionUsed)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 790,
        "mechanism": "increment-only counter via observability (Stale client resolution used; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_result_without_monitor_assessment_link_total": {
        "symbol": "ResultWithoutMonitorAssessmentLinkAllowed -> Metrics.Inc(MetricABDResultWithoutAssessmentLink)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 800,
        "mechanism": "increment-only counter via observability (Result without monitor assessment link; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_result_cross_network_context_total": {
        "symbol": "ResultCrossNetworkContextAllowed -> Metrics.Inc(MetricABDResultCrossNetworkContext)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 810,
        "mechanism": "increment-only counter via observability (Result cross network context; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_result_cross_config_generation_total": {
        "symbol": "ResultCrossConfigGenerationAllowed -> Metrics.Inc(MetricABDResultCrossConfigGeneration)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 820,
        "mechanism": "increment-only counter via observability (Result cross config generation; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_result_cross_monitoring_epoch_total": {
        "symbol": "ResultCrossMonitoringEpochAllowed -> Metrics.Inc(MetricABDResultCrossMonitoringEpoch)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 830,
        "mechanism": "increment-only counter via observability (Result cross monitoring epoch; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_incomplete_run_final_profile_total": {
        "symbol": "IncompleteRunFinalProfileAllowed -> Metrics.Inc(MetricABDIncompleteRunFinalProfile)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 840,
        "mechanism": "increment-only counter via observability (Incomplete run final profile; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_monitor_result_action_authorization_total": {
        "symbol": "MonitorResultActionAuthorizationAllowed -> Metrics.Inc(MetricABDMonitorResultActionAuthorization)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 850,
        "mechanism": "increment-only counter via observability (Monitor result action authorization; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    "detector_monitor_result_delivery_identity_mismatch_total": {
        "symbol": "MonitorResultDeliveryIdentityMismatchAllowed -> Metrics.Inc(MetricABDMonitorResultDeliveryIdentityMismatch)",
        "file": "src/detector/hard_gate_producers.go",
        "line": 860,
        "mechanism": "increment-only counter via observability (Monitor result delivery identity mismatch; ABD addendum v1.2 sect. 43)",
        "production_root": "detector lifecycle guards (sect. 43; release pipeline root from validation)",
    },
    # --- SP WARP-recommendation producers (FB-02 sp section, 2026-08-04):
    # every counter increments ONLY on the violating branch of the production
    # guards in src/serviceprofile/hard_gate_producers.go (§28A.11 of
    # B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md), reachable from the
    # validation controller loop via the release pipeline. ---
    "profile_warp_recommended_without_ip_path_evidence_total": {
        "symbol": "RecommendedWithoutIPPathEvidenceAllowed -> Metrics.Inc(MetricSPRecommendedWithoutIPPathEvidence)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 36,
        "mechanism": "increment-only counter via observability (recommendation without IP-path evidence; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_recommended_from_destination_ip_only_total": {
        "symbol": "RecommendedFromDestinationIPOnlyAllowed -> Metrics.Inc(MetricSPRecommendedFromDestinationIPOnly)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 47,
        "mechanism": "increment-only counter via observability (recommendation from destination-only scope; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_recommended_for_origin_dead_total": {
        "symbol": "RecommendedForOriginDeadAllowed -> Metrics.Inc(MetricSPRecommendedForOriginDead)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 58,
        "mechanism": "increment-only counter via observability (recommendation for dead origin; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_recommended_with_unhealthy_controls_total": {
        "symbol": "RecommendedWithUnhealthyControlsAllowed -> Metrics.Inc(MetricSPRecommendedWithUnhealthyControls)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 69,
        "mechanism": "increment-only counter via observability (recommendation while control probes unhealthy; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_recommendation_cross_service_total": {
        "symbol": "CrossServiceRecommendationAllowed -> Metrics.Inc(MetricSPCrossService)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 81,
        "mechanism": "increment-only counter via observability (recommendation consumed by another service; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_recommendation_stale_profile_total": {
        "symbol": "StaleProfileRecommendationAllowed -> Metrics.Inc(MetricSPStaleProfile)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 92,
        "mechanism": "increment-only counter via observability (eligible recommendation from non-current profile; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_recommendation_without_causal_trace_gate_total": {
        "symbol": "WithoutCausalTraceGateAllowed -> Metrics.Inc(MetricSPWithoutCausalTraceGate)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 103,
        "mechanism": "increment-only counter via observability (recommendation while causal trace gate not ready; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_enabled_without_target_canary_total": {
        "symbol": "EnabledWithoutTargetCanaryAllowed -> Metrics.Inc(MetricSPEnabledWithoutTargetCanary)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 115,
        "mechanism": "increment-only counter via observability (WARP enabled without passed target canary; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_test_token_reused_as_production_authorization_total": {
        "symbol": "TestTokenReusedAsProductionAuthorizationAllowed -> Metrics.Inc(MetricSPTestTokenReusedAsProdAuthorization)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 127,
        "mechanism": "increment-only counter via observability (live test token authorizing production; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_recommendation_ignored_control_regression_total": {
        "symbol": "IgnoredControlRegressionAllowed -> Metrics.Inc(MetricSPIgnoredControlRegression)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 138,
        "mechanism": "increment-only counter via observability (control regression reported as healthy; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_recommendation_hidden_fail_policy_total": {
        "symbol": "HiddenFailPolicyAllowed -> Metrics.Inc(MetricSPHiddenFailPolicy)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 149,
        "mechanism": "increment-only counter via observability (recommendation without explicit failure policy; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_nonru_suggested_without_geo_requirement_total": {
        "symbol": "NonRUSuggestedWithoutGeoRequirementAllowed -> Metrics.Inc(MetricSPNonRUSuggestedWithoutGeoRequirement)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 160,
        "mechanism": "increment-only counter via observability (non-RU option without declared geo requirement; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_camouflage_suggested_for_target_ip_block_total": {
        "symbol": "CamouflageSuggestedForTargetIPBlockAllowed -> Metrics.Inc(MetricSPCamouflageSuggestedForTargetIPBlock)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 171,
        "mechanism": "increment-only counter via observability (camouflage suggested for IP-blocked target; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
    "profile_warp_recommendation_cleanup_failure_total": {
        "symbol": "RecommendationCleanupFailureAllowed -> Metrics.Inc(MetricSPCleanupFailure)",
        "file": "src/serviceprofile/hard_gate_producers.go",
        "line": 182,
        "mechanism": "increment-only counter via observability (validation result with incomplete cleanup; SP addendum v1.6 sect. 28A.11)",
        "production_root": "serviceprofile WARP-recommendation guards (sect. 28A.11; release pipeline root from validation)",
    },
}

# Expected (normative) producer locations for gates whose producer is not yet
# implemented. Field runtime_producer stays null; the mapping below is only
# the owner-normative location where the producer must be wired (FB-27 for
# RST/GSO, PPE production wiring for PPE).
# As of 2026-08-01 every FB-03 gate producer is implemented and verified, so
# this mapping is empty; it is kept as the normative fallback for any future
# gate added without a producer.
EXPECTED_PRODUCER_LOCATION: dict[str, str] = {}

# Verified-commit SHA recorded in the registry when a producer_status
# flips to verified (producer audited + negative fixture + mutation run in
# this commit). Filled by REGISTER_VERIFIED_COMMIT below.
REGISTER_VERIFIED_COMMIT = "04c35ccf"  # FB-02 SP: 14 WARP-recommendation lifecycle producers verified (2026-08-04); 236 applicable

# Gate kinds (owner decision 2026-08-01, APPROVED —
# artifacts/audit/B4X_FB03_OWNER_DECISION.md, фаза E):
#   telemetry_counter                    — operational telemetry, NOT a blocker
#   zero_tolerance_violation_counter     — violation counter, evaluated on the
#                                          current validation-window delta
#                                          (never on lifetime absolute total)
#   current_generation_readiness_input   — invalidates/limits current-generation
#                                          readiness ONLY together with owner
#                                          state and applicability; never blocks
#                                          directly
#   threshold_violation_counter          — blocks above an owner-defined threshold
#   required_evidence                    — evidence artifact required, not a counter
#   derived_blocker                      — derived verdict blocker (aggregation)
# Only zero_tolerance_violation_counter (and, when normatively justified,
# threshold/evidence/derived) may block promotion.
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
    # safe-degradation / safety-guard telemetry (owner decision: not violations)
    "passive_rst_fail_open_total": "telemetry_counter",
    "b4_hold_disabled_visibility_total": "telemetry_counter",
    # --- zero-tolerance violation counters (window delta == 0) ---
    "unrelated_control_action_total": "zero_tolerance_violation_counter",
    "classifier_layout_parity_fail_total": "zero_tolerance_violation_counter",
    "passive_rst_reconnect_regression_total": "zero_tolerance_violation_counter",
    # --- DDI guided-discovery / TGB bridge zero-tolerance counters (addendum v1.0 32/33) ---
    "discovery_profile_without_context_validation_total": "zero_tolerance_violation_counter",
    "discovery_profile_stale_without_revalidation_total": "zero_tolerance_violation_counter",
    "discovery_profile_cross_wan_use_total": "zero_tolerance_violation_counter",
    "discovery_profile_mutable_runtime_pointer_total": "zero_tolerance_violation_counter",
    "discovery_profile_hint_without_provenance_total": "zero_tolerance_violation_counter",
    "discovery_profile_hint_overrode_current_baseline_total": "zero_tolerance_violation_counter",
    "discovery_profile_skipped_target_validation_total": "zero_tolerance_violation_counter",
    "discovery_profile_disabled_exhaustive_fallback_total": "zero_tolerance_violation_counter",
    "discovery_profile_direct_production_write_total": "zero_tolerance_violation_counter",
    "discovery_profile_allowed_sni_direct_promotion_total": "zero_tolerance_violation_counter",
    "discovery_profile_threshold_out_of_budget_total": "zero_tolerance_violation_counter",
    "discovery_profile_capture_gate_bypass_total": "zero_tolerance_violation_counter",
    "discovery_profile_cross_service_action_total": "zero_tolerance_violation_counter",
    "discovery_profile_false_pass_total": "zero_tolerance_violation_counter",
    "mtproto_bridge_zero_byte_handled_drop_total": "zero_tolerance_violation_counter",
    "mtproto_bridge_fixed_5s_destructive_timeout_total": "zero_tolerance_violation_counter",
    "mtproto_bridge_unbounded_pending_total": "zero_tolerance_violation_counter",
    "mtproto_bridge_pending_per_client_limit_bypass_total": "zero_tolerance_violation_counter",
    "mtproto_bridge_prefix_loss_total": "zero_tolerance_violation_counter",
    "mtproto_bridge_prefix_duplicate_total": "zero_tolerance_violation_counter",
    "mtproto_bridge_route_recursion_total": "zero_tolerance_violation_counter",
    "mtproto_bridge_primary_failure_silent_drop_total": "zero_tolerance_violation_counter",
    "mtproto_bridge_overflow_without_reason_total": "zero_tolerance_violation_counter",
    "mtproto_bridge_shutdown_leak_total": "zero_tolerance_violation_counter",
            # --- ABD detector zero-tolerance counters (addendum v1.2 39-42) ---
    "detector_single_probe_confirmed_total": "zero_tolerance_violation_counter",
    "detector_exception_string_only_confirmed_total": "zero_tolerance_violation_counter",
    "detector_static_target_only_high_confidence_total": "zero_tolerance_violation_counter",
    "detector_self_interference_total": "zero_tolerance_violation_counter",
    "detector_native_path_unproven_total": "zero_tolerance_violation_counter",
    "detector_capture_invalid_packet_verdict_total": "zero_tolerance_violation_counter",
    "detector_control_failure_ignored_total": "zero_tolerance_violation_counter",
    "detector_duplicate_evidence_confidence_increase_total": "zero_tolerance_violation_counter",
    "detector_cross_component_evidence_merge_total": "zero_tolerance_violation_counter",
    "detector_cross_generation_evidence_merge_total": "zero_tolerance_violation_counter",
    "detector_unbounded_dynamic_scan_total": "zero_tolerance_violation_counter",
    "detector_resource_budget_bypass_total": "zero_tolerance_violation_counter",
    "detector_sensitive_export_total": "zero_tolerance_violation_counter",
    "detector_host_dead_from_single_reference_failure_total": "zero_tolerance_violation_counter",
    "detector_reference_path_unhealthy_used_total": "zero_tolerance_violation_counter",
    "detector_reference_path_used_as_action_authorization_total": "zero_tolerance_violation_counter",
    "detector_partial_run_profile_compiled_total": "zero_tolerance_violation_counter",
    "detector_resume_cross_network_context_total": "zero_tolerance_violation_counter",
    "detector_capacity_self_interference_total": "zero_tolerance_violation_counter",
    "detector_dns_single_resolver_spoof_confirmed_total": "zero_tolerance_violation_counter",
    "detector_dns_cdn_variance_misclassified_total": "zero_tolerance_violation_counter",
    "detector_unverified_mitm_verdict_total": "zero_tolerance_violation_counter",
    "detector_tls_availability_integrity_conflation_total": "zero_tolerance_violation_counter",
    "detector_tls_fingerprint_unlabeled_total": "zero_tolerance_violation_counter",
    "detector_quic_single_target_global_udp_verdict_total": "zero_tolerance_violation_counter",
    "detector_quic_tcp_evidence_conflation_total": "zero_tolerance_violation_counter",
    "detector_valid_application_error_dpi_total": "zero_tolerance_violation_counter",
    "detector_head_only_available_verdict_total": "zero_tolerance_violation_counter",
    "detector_partial_progress_discarded_total": "zero_tolerance_violation_counter",
    "detector_small_object_classified_throttled_total": "zero_tolerance_violation_counter",
    "detector_fixed_16kb_window_confirmed_without_profile_total": "zero_tolerance_violation_counter",
    "detector_packet_threshold_reported_as_byte_threshold_total": "zero_tolerance_violation_counter",
    "detector_byte_threshold_reported_as_packet_threshold_total": "zero_tolerance_violation_counter",
    "detector_gso_skb_count_as_wire_packet_total": "zero_tolerance_violation_counter",
    "detector_single_origin_l4_budget_confirmed_total": "zero_tolerance_violation_counter",
    "detector_server_header_limit_dpi_total": "zero_tolerance_violation_counter",
    "detector_retransmission_counted_as_progress_total": "zero_tolerance_violation_counter",
    "detector_l4_threshold_without_controls_total": "zero_tolerance_violation_counter",
    "blocking_profile_without_target_plan_total": "zero_tolerance_violation_counter",
    "blocking_profile_without_network_context_total": "zero_tolerance_violation_counter",
    "blocking_profile_without_provenance_total": "zero_tolerance_violation_counter",
    "blocking_profile_mutated_after_compile_total": "zero_tolerance_violation_counter",
    "blocking_profile_high_confidence_with_contradiction_total": "zero_tolerance_violation_counter",
    "blocking_profile_direct_action_authorization_total": "zero_tolerance_violation_counter",
    "blocking_profile_direct_production_write_total": "zero_tolerance_violation_counter",
    "guided_search_skipped_baseline_total": "zero_tolerance_violation_counter",
    "guided_search_disabled_full_fallback_total": "zero_tolerance_violation_counter",
    "guided_search_profile_overrode_current_baseline_total": "zero_tolerance_violation_counter",
    "guided_search_target_unvalidated_promotion_total": "zero_tolerance_violation_counter",
    "guided_search_cross_service_action_total": "zero_tolerance_violation_counter",
    "guided_search_white_sni_direct_promotion_total": "zero_tolerance_violation_counter",
    "guided_search_false_savings_report_total": "zero_tolerance_violation_counter",
    "guided_search_required_component_uncovered_total": "zero_tolerance_violation_counter",
    "guided_search_coverage_ignored_control_regression_total": "zero_tolerance_violation_counter",
    "guided_search_cross_service_set_cover_total": "zero_tolerance_violation_counter",
    "guided_search_excluded_target_hidden_total": "zero_tolerance_violation_counter",
    "guided_search_more_complex_candidate_preferred_without_gain_total": "zero_tolerance_violation_counter",
    "guided_search_unverified_shortlist_promotion_total": "zero_tolerance_violation_counter",
    "detector_monitor_request_direct_action_total": "zero_tolerance_violation_counter",
    "detector_monitor_request_without_target_plan_overlay_total": "zero_tolerance_violation_counter",
    "detector_monitor_request_without_network_context_total": "zero_tolerance_violation_counter",
    "detector_monitor_request_without_config_generation_total": "zero_tolerance_violation_counter",
    "detector_monitor_request_without_budget_token_total": "zero_tolerance_violation_counter",
    "detector_monitor_request_expired_accepted_total": "zero_tolerance_violation_counter",
    "detector_provisional_monitor_evidence_profile_compiled_total": "zero_tolerance_violation_counter",
    "detector_passive_observation_counted_as_independent_probe_total": "zero_tolerance_violation_counter",
    "detector_monitor_recurrence_counted_as_evidence_independence_total": "zero_tolerance_violation_counter",
    "detector_client_resolution_replaced_silently_total": "zero_tolerance_violation_counter",
    "detector_probe_without_resolution_binding_total": "zero_tolerance_violation_counter",
    "detector_cname_terminal_ip_misattributed_total": "zero_tolerance_violation_counter",
    "detector_multi_ip_partial_failure_hidden_total": "zero_tolerance_violation_counter",
    "detector_stale_client_resolution_used_total": "zero_tolerance_violation_counter",
    "detector_result_without_monitor_assessment_link_total": "zero_tolerance_violation_counter",
    "detector_result_cross_network_context_total": "zero_tolerance_violation_counter",
    "detector_result_cross_config_generation_total": "zero_tolerance_violation_counter",
    "detector_result_cross_monitoring_epoch_total": "zero_tolerance_violation_counter",
    "detector_incomplete_run_final_profile_total": "zero_tolerance_violation_counter",
    "detector_monitor_result_action_authorization_total": "zero_tolerance_violation_counter",
    "detector_monitor_result_delivery_identity_mismatch_total": "zero_tolerance_violation_counter",
# --- MON continuous-blocking monitoring zero-tolerance counters (addendum v1.0 84-92) ---
    "monitor_observation_direct_action_total": "zero_tolerance_violation_counter",
    "monitor_provisional_profile_compiled_total": "zero_tolerance_violation_counter",
    "monitor_passive_discovery_start_total": "zero_tolerance_violation_counter",
    "monitor_passive_warp_enable_total": "zero_tolerance_violation_counter",
    "monitor_fast_lane_action_total": "zero_tolerance_violation_counter",
    "monitor_fast_lane_promoted_as_authoritative_total": "zero_tolerance_violation_counter",
    "monitor_destination_only_deep_trigger_total": "zero_tolerance_violation_counter",
    "monitor_cross_client_merge_total": "zero_tolerance_violation_counter",
    "monitor_cross_service_merge_total": "zero_tolerance_violation_counter",
    "monitor_cross_component_merge_total": "zero_tolerance_violation_counter",
    "monitor_cross_wan_evidence_merge_total": "zero_tolerance_violation_counter",
    "monitor_cross_generation_evidence_merge_total": "zero_tolerance_violation_counter",
    "monitor_router_origin_as_forwarded_proof_total": "zero_tolerance_violation_counter",
    "monitor_duplicate_evidence_independence_total": "zero_tolerance_violation_counter",
    "monitor_temporal_persistence_without_time_separation_total": "zero_tolerance_violation_counter",
    "monitor_success_suppressor_ignored_total": "zero_tolerance_violation_counter",
    "monitor_recovered_subject_not_demoted_total": "zero_tolerance_violation_counter",
    "monitor_expired_evidence_used_total": "zero_tolerance_violation_counter",
    "monitor_decay_disabled_without_policy_total": "zero_tolerance_violation_counter",
    "monitor_probe_without_resolution_binding_total": "zero_tolerance_violation_counter",
    "monitor_client_dns_answer_replaced_silently_total": "zero_tolerance_violation_counter",
    "monitor_cname_terminal_ip_misattributed_total": "zero_tolerance_violation_counter",
    "monitor_multi_ip_partial_failure_hidden_total": "zero_tolerance_violation_counter",
    "monitor_stale_resolution_used_as_exact_proof_total": "zero_tolerance_violation_counter",
    "monitor_trigger_without_visibility_total": "zero_tolerance_violation_counter",
    "monitor_trigger_without_budget_total": "zero_tolerance_violation_counter",
    "monitor_trigger_during_global_wan_failure_total": "zero_tolerance_violation_counter",
    "monitor_trigger_with_stale_source_heartbeat_total": "zero_tolerance_violation_counter",
    "monitor_duplicate_concurrent_abd_run_total": "zero_tolerance_violation_counter",
    "monitor_unbounded_target_intake_total": "zero_tolerance_violation_counter",
    "monitor_unbounded_probe_parallelism_total": "zero_tolerance_violation_counter",
    "monitor_self_interference_total": "zero_tolerance_violation_counter",
    "monitor_reference_result_as_action_authorization_total": "zero_tolerance_violation_counter",
    "monitor_abd_request_without_target_plan_total": "zero_tolerance_violation_counter",
    "monitor_abd_partial_result_profile_ready_total": "zero_tolerance_violation_counter",
    "monitor_abd_result_bypassed_ddi_total": "zero_tolerance_violation_counter",
    "monitor_discovery_without_authoritative_profile_total": "zero_tolerance_violation_counter",
    "monitor_discovery_skipped_mandatory_baseline_total": "zero_tolerance_violation_counter",
    "monitor_recommendation_without_scope_total": "zero_tolerance_violation_counter",
    "monitor_warp_recommendation_without_ip_path_evidence_total": "zero_tolerance_violation_counter",
    "monitor_legacy_watchdog_direct_apply_total": "zero_tolerance_violation_counter",
    "monitor_legacy_watchdog_created_unvalidated_set_total": "zero_tolerance_violation_counter",
    "monitor_legacy_watchdog_overwrote_set_without_canary_total": "zero_tolerance_violation_counter",
    "monitor_legacy_api_projection_mutation_total": "zero_tolerance_violation_counter",
    "monitor_shadow_and_active_writer_overlap_total": "zero_tolerance_violation_counter",
    "monitor_required_event_drop_hidden_total": "zero_tolerance_violation_counter",
    "monitor_source_heartbeat_stale_auto_diagnose_total": "zero_tolerance_violation_counter",
    "monitor_checkpoint_corruption_false_ready_total": "zero_tolerance_violation_counter",
    "monitor_restart_reused_expired_lease_total": "zero_tolerance_violation_counter",
    "monitor_sensitive_dns_history_export_total": "zero_tolerance_violation_counter",
    "monitor_secret_trace_leak_total": "zero_tolerance_violation_counter",
    "monitor_high_cardinality_metric_label_total": "zero_tolerance_violation_counter",
# --- SPF silent-path failure zero-tolerance counters (addendum v1.0 45) ---
    "silent_failure_action_without_authorization_total": "zero_tolerance_violation_counter",
    "silent_failure_action_with_incomplete_visibility_total": "zero_tolerance_violation_counter",
    "silent_failure_destination_only_state_total": "zero_tolerance_violation_counter",
    "silent_failure_cross_client_action_total": "zero_tolerance_violation_counter",
    "silent_failure_cross_service_action_total": "zero_tolerance_violation_counter",
    "silent_failure_cross_component_action_total": "zero_tolerance_violation_counter",
    "silent_failure_cross_generation_action_total": "zero_tolerance_violation_counter",
    "silent_failure_single_signal_auto_fallback_total": "zero_tolerance_violation_counter",
    "silent_failure_non_independent_evidence_auto_fallback_total": "zero_tolerance_violation_counter",
    "silent_failure_suppressor_ignored_total": "zero_tolerance_violation_counter",
    "silent_failure_fast_parallel_false_positive_total": "zero_tolerance_violation_counter",
    "silent_failure_recent_success_false_positive_total": "zero_tolerance_violation_counter",
    "silent_failure_explicit_server_error_misclassified_total": "zero_tolerance_violation_counter",
    "silent_failure_gso_mss_progress_mismatch_total": "zero_tolerance_violation_counter",
    "silent_failure_ppe_visibility_violation_total": "zero_tolerance_violation_counter",
    "silent_failure_unbounded_probe_total": "zero_tolerance_violation_counter",
    "silent_failure_unbounded_rotation_total": "zero_tolerance_violation_counter",
    "silent_failure_recursive_transport_fallback_total": "zero_tolerance_violation_counter",
    "silent_failure_recovery_without_rollback_target_total": "zero_tolerance_violation_counter",
    "silent_failure_control_regression_promoted_total": "zero_tolerance_violation_counter",
    "silent_failure_false_positive_budget_ignored_total": "zero_tolerance_violation_counter",
    "silent_failure_user_revert_not_rolled_back_total": "zero_tolerance_violation_counter",
    # --- WARP base-transport zero-tolerance counters (§72; narrow causal
    # verdict set, FB-14 decision 9) ---
    "warp_secret_leak_total": "zero_tolerance_violation_counter",
    "warp_foreign_interface_modified_total": "zero_tolerance_violation_counter",
    "warp_recursive_control_route_total": "zero_tolerance_violation_counter",
    "warp_mark_collision_total": "zero_tolerance_violation_counter",
    "warp_route_without_liveness_total": "zero_tolerance_violation_counter",
    "warp_destination_set_partial_apply_total": "zero_tolerance_violation_counter",
    "warp_unbounded_restart_total": "zero_tolerance_violation_counter",
    "warp_unbounded_registration_total": "zero_tolerance_violation_counter",
    "warp_unrelated_control_action_total": "zero_tolerance_violation_counter",
    "warp_rollback_failure_total": "zero_tolerance_violation_counter",
    # --- current-generation readiness inputs (never block directly) ---
    "nfqueue_gso_truncated_total": "current_generation_readiness_input",
    "nfqueue_gso_csum_not_ready_total": "current_generation_readiness_input",
    "nfqueue_gso_token_miss_total": "current_generation_readiness_input",
    "b4_capture_visibility_degrade_total": "current_generation_readiness_input",
    # --- SP WARP-recommendation zero-tolerance counters (addendum v1.6 28A.11) ---
    "profile_warp_recommended_without_ip_path_evidence_total": "zero_tolerance_violation_counter",
    "profile_warp_recommended_from_destination_ip_only_total": "zero_tolerance_violation_counter",
    "profile_warp_recommended_for_origin_dead_total": "zero_tolerance_violation_counter",
    "profile_warp_recommended_with_unhealthy_controls_total": "zero_tolerance_violation_counter",
    "profile_warp_recommendation_cross_service_total": "zero_tolerance_violation_counter",
    "profile_warp_recommendation_stale_profile_total": "zero_tolerance_violation_counter",
    "profile_warp_recommendation_without_causal_trace_gate_total": "zero_tolerance_violation_counter",
    "profile_warp_enabled_without_target_canary_total": "zero_tolerance_violation_counter",
    "profile_warp_test_token_reused_as_production_authorization_total": "zero_tolerance_violation_counter",
    "profile_warp_recommendation_ignored_control_regression_total": "zero_tolerance_violation_counter",
    "profile_warp_recommendation_hidden_fail_policy_total": "zero_tolerance_violation_counter",
    "profile_nonru_suggested_without_geo_requirement_total": "zero_tolerance_violation_counter",
    "profile_warp_camouflage_suggested_for_target_ip_block_total": "zero_tolerance_violation_counter",
    "profile_warp_recommendation_cleanup_failure_total": "zero_tolerance_violation_counter",
}

# Verdict consumers wired in production (2026-08-01): metric name -> list of
# machine-readable consumer descriptors. kind:
#   promotion_blocker   — blocks promotion when count != 0
#   aggregation_blocker — gate-evaluation aggregation (fail-closed)
#   aggregation_observer — informational telemetry aggregation (never blocks)
#   http_report         — observable report endpoint
# Zero-tolerance gates are consumed by the promotion path (fail-closed);
# telemetry gates are only aggregated into Telemetry and reported.
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
    "classifier_layout_parity_fail_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateHardGates verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.rstgso; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    # --- WARP base-transport consumers (FB-02 WARP section): the narrow
    # causal-trace verdict evaluates exactly these ten gates (FB-14
            # --- ABD zero-tolerance counters (addendum v1.2 39-42; fail-closed via
    # EvaluateHardGates scope.abd, release pipeline) ---
    "detector_single_probe_confirmed_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_exception_string_only_confirmed_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_static_target_only_high_confidence_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_self_interference_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_native_path_unproven_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_capture_invalid_packet_verdict_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_control_failure_ignored_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_duplicate_evidence_confidence_increase_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_cross_component_evidence_merge_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_cross_generation_evidence_merge_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_unbounded_dynamic_scan_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_resource_budget_bypass_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_sensitive_export_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_host_dead_from_single_reference_failure_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_reference_path_unhealthy_used_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_reference_path_used_as_action_authorization_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_partial_run_profile_compiled_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_resume_cross_network_context_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_capacity_self_interference_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_dns_single_resolver_spoof_confirmed_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_dns_cdn_variance_misclassified_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_unverified_mitm_verdict_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_tls_availability_integrity_conflation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_tls_fingerprint_unlabeled_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_quic_single_target_global_udp_verdict_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_quic_tcp_evidence_conflation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_valid_application_error_dpi_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_head_only_available_verdict_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_partial_progress_discarded_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_small_object_classified_throttled_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_fixed_16kb_window_confirmed_without_profile_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_packet_threshold_reported_as_byte_threshold_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_byte_threshold_reported_as_packet_threshold_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_gso_skb_count_as_wire_packet_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_single_origin_l4_budget_confirmed_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_server_header_limit_dpi_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_retransmission_counted_as_progress_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_l4_threshold_without_controls_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "blocking_profile_without_target_plan_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "blocking_profile_without_network_context_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "blocking_profile_without_provenance_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "blocking_profile_mutated_after_compile_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "blocking_profile_high_confidence_with_contradiction_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "blocking_profile_direct_action_authorization_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "blocking_profile_direct_production_write_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_skipped_baseline_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_disabled_full_fallback_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_profile_overrode_current_baseline_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_target_unvalidated_promotion_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_cross_service_action_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_white_sni_direct_promotion_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_false_savings_report_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_required_component_uncovered_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_coverage_ignored_control_regression_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_cross_service_set_cover_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_excluded_target_hidden_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_more_complex_candidate_preferred_without_gain_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "guided_search_unverified_shortlist_promotion_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_monitor_request_direct_action_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_monitor_request_without_target_plan_overlay_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_monitor_request_without_network_context_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_monitor_request_without_config_generation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_monitor_request_without_budget_token_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_monitor_request_expired_accepted_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_provisional_monitor_evidence_profile_compiled_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_passive_observation_counted_as_independent_probe_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_monitor_recurrence_counted_as_evidence_independence_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_client_resolution_replaced_silently_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_probe_without_resolution_binding_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_cname_terminal_ip_misattributed_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_multi_ip_partial_failure_hidden_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_stale_client_resolution_used_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_result_without_monitor_assessment_link_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_result_cross_network_context_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_result_cross_config_generation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_result_cross_monitoring_epoch_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_incomplete_run_final_profile_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_monitor_result_action_authorization_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_monitor_result_delivery_identity_mismatch_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.abd; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
# --- MON zero-tolerance counters (addendum v1.0 84-92; fail-closed via
    # EvaluateHardGates scope.mon, release pipeline) ---
    "monitor_observation_direct_action_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_provisional_profile_compiled_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_passive_discovery_start_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_passive_warp_enable_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_fast_lane_action_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_fast_lane_promoted_as_authoritative_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_destination_only_deep_trigger_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_cross_client_merge_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_cross_service_merge_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_cross_component_merge_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_cross_wan_evidence_merge_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_cross_generation_evidence_merge_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_router_origin_as_forwarded_proof_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_duplicate_evidence_independence_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_temporal_persistence_without_time_separation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_success_suppressor_ignored_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_recovered_subject_not_demoted_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_expired_evidence_used_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_decay_disabled_without_policy_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_probe_without_resolution_binding_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_client_dns_answer_replaced_silently_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_cname_terminal_ip_misattributed_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_multi_ip_partial_failure_hidden_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_stale_resolution_used_as_exact_proof_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_trigger_without_visibility_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_trigger_without_budget_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_trigger_during_global_wan_failure_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_trigger_with_stale_source_heartbeat_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_duplicate_concurrent_abd_run_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_unbounded_target_intake_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_unbounded_probe_parallelism_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_self_interference_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_reference_result_as_action_authorization_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_abd_request_without_target_plan_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_abd_partial_result_profile_ready_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_abd_result_bypassed_ddi_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_discovery_without_authoritative_profile_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_discovery_skipped_mandatory_baseline_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_recommendation_without_scope_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_warp_recommendation_without_ip_path_evidence_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_legacy_watchdog_direct_apply_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_legacy_watchdog_created_unvalidated_set_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_legacy_watchdog_overwrote_set_without_canary_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_legacy_api_projection_mutation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_shadow_and_active_writer_overlap_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_required_event_drop_hidden_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_source_heartbeat_stale_auto_diagnose_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_checkpoint_corruption_false_ready_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_restart_reused_expired_lease_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_sensitive_dns_history_export_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_secret_trace_leak_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_high_cardinality_metric_label_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.mon; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
# --- SPF zero-tolerance counters (addendum v1.0 45; fail-closed via
    # EvaluateHardGates scope.spf, release pipeline) ---
    "silent_failure_action_without_authorization_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_action_with_incomplete_visibility_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_destination_only_state_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_cross_client_action_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_cross_service_action_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_cross_component_action_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_cross_generation_action_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_single_signal_auto_fallback_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_non_independent_evidence_auto_fallback_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_suppressor_ignored_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_fast_parallel_false_positive_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_recent_success_false_positive_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_explicit_server_error_misclassified_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_gso_mss_progress_mismatch_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_ppe_visibility_violation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_unbounded_probe_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_unbounded_rotation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_recursive_transport_fallback_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_recovery_without_rollback_target_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_control_regression_promoted_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_false_positive_budget_ignored_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "silent_failure_user_revert_not_rolled_back_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.spf; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    # --- DDI/TGB zero-tolerance counters (addendum v1.0 32/33; fail-closed via
    # EvaluateHardGates scope.ddi_tgb, release pipeline) ---
    "discovery_profile_without_context_validation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_stale_without_revalidation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_cross_wan_use_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_mutable_runtime_pointer_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_hint_without_provenance_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_hint_overrode_current_baseline_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_skipped_target_validation_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_disabled_exhaustive_fallback_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_direct_production_write_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_allowed_sni_direct_promotion_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_threshold_out_of_budget_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_capture_gate_bypass_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_cross_service_action_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "discovery_profile_false_pass_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "mtproto_bridge_zero_byte_handled_drop_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "mtproto_bridge_fixed_5s_destructive_timeout_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "mtproto_bridge_unbounded_pending_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "mtproto_bridge_pending_per_client_limit_bypass_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "mtproto_bridge_prefix_loss_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "mtproto_bridge_prefix_duplicate_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "mtproto_bridge_route_recursion_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "mtproto_bridge_primary_failure_silent_drop_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "mtproto_bridge_overflow_without_reason_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "mtproto_bridge_shutdown_leak_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.ddi_tgb; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    # decision 9) via evaluateGateSet, fail-closed on any non-zero delta. ---
    "warp_secret_leak_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateCausalTraceWindow zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateCausalTraceWindow verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.warp; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "warp_foreign_interface_modified_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateCausalTraceWindow zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateCausalTraceWindow verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.warp; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "warp_recursive_control_route_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateCausalTraceWindow zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateCausalTraceWindow verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.warp; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "warp_mark_collision_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateCausalTraceWindow zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateCausalTraceWindow verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.warp; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "warp_route_without_liveness_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateCausalTraceWindow zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateCausalTraceWindow verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.warp; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "warp_destination_set_partial_apply_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateCausalTraceWindow zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateCausalTraceWindow verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.warp; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "warp_unbounded_restart_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateCausalTraceWindow zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateCausalTraceWindow verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.warp; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "warp_unbounded_registration_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateCausalTraceWindow zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateCausalTraceWindow verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.warp; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "warp_unrelated_control_action_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateCausalTraceWindow zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateCausalTraceWindow verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.warp; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "warp_rollback_failure_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateCausalTraceWindow zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateCausalTraceWindow verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.warp; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    # --- FB-29 / FB-30 consumers (mon + abd): promotion path via
    # EvaluateHardGates, fail-closed on the owning scope. ---
    "monitor_first_success_erased_address_failures_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.mon; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_http_hypothesis_from_tcp_tls_only_observer_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.mon; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_observer_unavailable_as_target_failure_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.mon; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_exact_endpoint_service_resolution_conflated_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.mon; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "monitor_observer_capability_unproven_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.mon; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_first_success_erased_address_failures_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.abd; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_multivantage_stage_mismatch_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.abd; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_http_hypothesis_from_tcp_tls_only_observer_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.abd; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_observer_unavailable_as_target_failure_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.abd; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_exact_endpoint_service_resolution_conflated_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.abd; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "detector_observer_capability_unproven_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates", "file": "src/validation/gates.go", "line": 205, "binding": "scope.abd; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "nfqueue_gso_truncated_total": [
        {"kind": "readiness_observer", "symbol": "EvaluateHardGatesWindow readiness branch", "file": "src/validation/gates.go", "line": 244, "binding": "window delta; owner-state bound; never blocks directly"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "nfqueue_gso_csum_not_ready_total": [
        {"kind": "readiness_observer", "symbol": "EvaluateHardGatesWindow readiness branch", "file": "src/validation/gates.go", "line": 244, "binding": "window delta; owner-state bound; never blocks directly"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "nfqueue_gso_token_miss_total": [
        {"kind": "readiness_observer", "symbol": "EvaluateHardGatesWindow readiness branch", "file": "src/validation/gates.go", "line": 244, "binding": "window delta; owner-state bound; never blocks directly"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "passive_rst_fail_open_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGatesWindow telemetry branch", "file": "src/validation/gates.go", "line": 239, "binding": "safe degradation telemetry (derived state may gate re-claim)"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "passive_rst_reconnect_regression_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch", "file": "src/validation/gates.go", "line": 233, "binding": "count != 0 -> GateFail"},
        {"kind": "aggregation_blocker", "symbol": "EvaluateHardGates verdict aggregation", "file": "src/validation/gates.go", "line": 239, "binding": "scope.rstgso; fail-closed"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "b4_capture_visibility_degrade_total": [
        {"kind": "readiness_observer", "symbol": "EvaluateHardGatesWindow readiness branch", "file": "src/validation/gates.go", "line": 244, "binding": "window delta; current capture visibility; never blocks directly"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "b4_hold_disabled_visibility_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGatesWindow telemetry branch", "file": "src/validation/gates.go", "line": 239, "binding": "safety-guard trigger telemetry (not a violation; separate GateID for hold-active-under-incomplete-visibility if needed)"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "classifier_reassembled_sni_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "nfqueue_gso_packets_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "nfqueue_gso_bytes_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "nfqueue_gso_decision_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "nfqueue_gso_normalized_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "nfqueue_gso_action_suppressed_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "nfqueue_gso_transition_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "passive_rst_observed_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "passive_rst_decision_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "passive_rst_suppressed_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "passive_rst_baseline_quality_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "passive_rst_budget_exhausted_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "passive_rst_rollback_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "b4_ppe_rule_reapply_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "b4_ppe_self_test_total": [
        {"kind": "aggregation_observer", "symbol": "EvaluateHardGates telemetry branch", "file": "src/validation/gates.go", "line": 222, "binding": "informational aggregation"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    # --- SP WARP-recommendation consumers (addendum v1.6 28A.11; fail-closed
    # via EvaluateHardGates scope.sp, PROFILE_WARP_RECOMMENDATION_READY) ---
    "profile_warp_recommended_without_ip_path_evidence_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_recommended_from_destination_ip_only_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_recommended_for_origin_dead_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_recommended_with_unhealthy_controls_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_recommendation_cross_service_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_recommendation_stale_profile_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_recommendation_without_causal_trace_gate_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_enabled_without_target_canary_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_test_token_reused_as_production_authorization_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_recommendation_ignored_control_regression_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_recommendation_hidden_fail_policy_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_nonru_suggested_without_geo_requirement_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_camouflage_suggested_for_target_ip_block_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
    ],
    "profile_warp_recommendation_cleanup_failure_total": [
        {"kind": "promotion_blocker", "symbol": "EvaluateHardGates zero-tolerance branch (evaluateGateSet)", "file": "src/validation/gates.go", "line": 329, "binding": "scope.sp; count != 0 -> GateFail"},
        {"kind": "http_report", "symbol": "GET /api/v2/validation/gates", "file": "src/http/handler/validation_gates.go", "line": 0, "binding": "live snapshot"},
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
    "nfqueue_gso_packets_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_GSOOffloadMetadata", "file": "src/nfq/hard_gate_producers_test.go", "line": 37, "assertion": "IsGSO metadata -> counter > 0"},
    ],
    "nfqueue_gso_bytes_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_GSOOffloadMetadata", "file": "src/nfq/hard_gate_producers_test.go", "line": 37, "assertion": "IsGSO metadata -> counter > 0"},
    ],
    "nfqueue_gso_truncated_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_GSOOffloadMetadata", "file": "src/nfq/hard_gate_producers_test.go", "line": 37, "assertion": "truncated metadata -> counter > 0 (mutation run executed)"},
    ],
    "nfqueue_gso_csum_not_ready_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_GSOOffloadMetadata", "file": "src/nfq/hard_gate_producers_test.go", "line": 37, "assertion": "checksum-not-ready metadata -> counter > 0 (mutation run executed)"},
    ],
    "nfqueue_gso_decision_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_GSOFastPathDecisions", "file": "src/nfq/hard_gate_producers_test.go", "line": 66, "assertion": "fast-path verdict -> counter > 0"},
    ],
    "nfqueue_gso_normalized_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_GSOFastPathDecisions", "file": "src/nfq/hard_gate_producers_test.go", "line": 66, "assertion": "normalize-queued path -> counter > 0"},
    ],
    "nfqueue_gso_action_suppressed_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_GSOFastPathDecisions", "file": "src/nfq/hard_gate_producers_test.go", "line": 66, "assertion": "action-suppressed path -> counter > 0"},
    ],
    "nfqueue_gso_token_miss_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_GSOTokenMiss", "file": "src/nfq/hard_gate_producers_test.go", "line": 90, "assertion": "normalizer secondary miss -> counter > 0 (mutation run executed)"},
    ],
    "nfqueue_gso_transition_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_GSOTransition", "file": "src/http/handler/hard_gate_producers_test.go", "line": 34, "assertion": "topology apply defer -> counter > 0"},
    ],
    "passive_rst_observed_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_PassiveRSTMetrics", "file": "src/nfq/hard_gate_producers_test.go", "line": 102, "assertion": "2 signals -> counter == 2"},
    ],
    "passive_rst_decision_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_PassiveRSTMetrics", "file": "src/nfq/hard_gate_producers_test.go", "line": 102, "assertion": "enforcement decision -> counter > 0"},
    ],
    "passive_rst_suppressed_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_PassiveRSTMetrics", "file": "src/nfq/hard_gate_producers_test.go", "line": 102, "assertion": "suppress decision -> counter > 0"},
    ],
    "passive_rst_fail_open_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_PassiveRSTMetrics", "file": "src/nfq/hard_gate_producers_test.go", "line": 102, "assertion": "fail-open decision -> counter > 0 (mutation run executed)"},
    ],
    "passive_rst_baseline_quality_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_PassiveRSTMetrics", "file": "src/nfq/hard_gate_producers_test.go", "line": 102, "assertion": "baseline quality -> counter > 0"},
    ],
    "passive_rst_budget_exhausted_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_PassiveRSTMetrics", "file": "src/nfq/hard_gate_producers_test.go", "line": 102, "assertion": "budget fail-open -> counter > 0"},
    ],
    "passive_rst_rollback_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_PassiveRSTRollback", "file": "src/nfq/hard_gate_producers_test.go", "line": 141, "assertion": "RecordHealth triggered -> counter > 0"},
    ],
    "passive_rst_reconnect_regression_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_PassiveRSTRollback", "file": "src/nfq/hard_gate_producers_test.go", "line": 141, "assertion": "reconnect regression -> counter > 0 (mutation run executed)"},
    ],
    "classifier_reassembled_sni_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_ClassifierLayoutParity", "file": "src/nfq/hard_gate_producers_test.go", "line": 175, "assertion": "reassembled-SNI selection -> counter > 0"},
    ],
    "classifier_layout_parity_fail_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_ClassifierLayoutParity", "file": "src/nfq/hard_gate_producers_test.go", "line": 175, "assertion": "reassembled-SNI without logical ID -> counter > 0 (mutation run executed)"},
    ],
    "b4_ppe_rule_reapply_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_PPERuleReapply", "file": "src/capture/ppe/hard_gate_producers_test.go", "line": 85, "assertion": "lifecycle Reapply -> counter > 0"},
    ],
    "b4_ppe_self_test_total": [
        {"kind": "positive_fixture", "name": "TestHardGateProducer_PPESelfTest", "file": "src/capture/ppe/hard_gate_producers_test.go", "line": 52, "assertion": "RunSelfTest -> counter > 0"},
    ],
    "b4_capture_visibility_degrade_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_CaptureVisibilityDegrade", "file": "src/capture/ppe/hard_gate_producers_test.go", "line": 31, "assertion": "gate Degrade -> counter > 0 (mutation run executed)"},
    ],
    "b4_hold_disabled_visibility_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_CaptureVisibilityDegrade", "file": "src/capture/ppe/hard_gate_producers_test.go", "line": 31, "assertion": "gate Degrade -> counter > 0 (mutation run executed)"},
    ],
    # --- WARP base-transport negative fixtures (FB-02 WARP section):
    # each test drives the violating branch of the production runtime and
            # --- ABD negative fixtures (addendum v1.2 39-42): each test drives the
    # violating branch of the production guard and asserts the
    # zero-tolerance counter moved. ---
    "detector_single_probe_confirmed_total": [
        {"kind": "negative_fixture", "name": "TestABDSingleProbeConfirmed", "file": "src/detector/hard_gate_producers_test.go", "line": 122, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_exception_string_only_confirmed_total": [
        {"kind": "negative_fixture", "name": "TestABDExceptionStringOnlyConfirmed", "file": "src/detector/hard_gate_producers_test.go", "line": 128, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_static_target_only_high_confidence_total": [
        {"kind": "negative_fixture", "name": "TestABDStaticTargetOnlyHighConfidence", "file": "src/detector/hard_gate_producers_test.go", "line": 134, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_self_interference_total": [
        {"kind": "negative_fixture", "name": "TestABDSelfInterference", "file": "src/detector/hard_gate_producers_test.go", "line": 140, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_native_path_unproven_total": [
        {"kind": "negative_fixture", "name": "TestABDNativePathUnproven", "file": "src/detector/hard_gate_producers_test.go", "line": 146, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_capture_invalid_packet_verdict_total": [
        {"kind": "negative_fixture", "name": "TestABDCaptureInvalidPacketVerdict", "file": "src/detector/hard_gate_producers_test.go", "line": 152, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_control_failure_ignored_total": [
        {"kind": "negative_fixture", "name": "TestABDControlFailureIgnored", "file": "src/detector/hard_gate_producers_test.go", "line": 158, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_duplicate_evidence_confidence_increase_total": [
        {"kind": "negative_fixture", "name": "TestABDDupEvidenceConfidenceIncrease", "file": "src/detector/hard_gate_producers_test.go", "line": 164, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_cross_component_evidence_merge_total": [
        {"kind": "negative_fixture", "name": "TestABDCrossComponentEvidenceMerge", "file": "src/detector/hard_gate_producers_test.go", "line": 172, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_cross_generation_evidence_merge_total": [
        {"kind": "negative_fixture", "name": "TestABDCrossGenerationEvidenceMerge", "file": "src/detector/hard_gate_producers_test.go", "line": 180, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_unbounded_dynamic_scan_total": [
        {"kind": "negative_fixture", "name": "TestABDUnboundedDynamicScan", "file": "src/detector/hard_gate_producers_test.go", "line": 186, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_resource_budget_bypass_total": [
        {"kind": "negative_fixture", "name": "TestABDResourceBudgetBypass", "file": "src/detector/hard_gate_producers_test.go", "line": 192, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_sensitive_export_total": [
        {"kind": "negative_fixture", "name": "TestABDSensitiveExport", "file": "src/detector/hard_gate_producers_test.go", "line": 198, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_host_dead_from_single_reference_failure_total": [
        {"kind": "negative_fixture", "name": "TestABDHostDeadSingleReferenceFailure", "file": "src/detector/hard_gate_producers_test.go", "line": 204, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_reference_path_unhealthy_used_total": [
        {"kind": "negative_fixture", "name": "TestABDReferencePathUnhealthyUsed", "file": "src/detector/hard_gate_producers_test.go", "line": 210, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_reference_path_used_as_action_authorization_total": [
        {"kind": "negative_fixture", "name": "TestABDReferencePathAsActionAuth", "file": "src/detector/hard_gate_producers_test.go", "line": 216, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_partial_run_profile_compiled_total": [
        {"kind": "negative_fixture", "name": "TestABDPartialRunProfileCompiled", "file": "src/detector/hard_gate_producers_test.go", "line": 222, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_resume_cross_network_context_total": [
        {"kind": "negative_fixture", "name": "TestABDResumeCrossNetworkContext", "file": "src/detector/hard_gate_producers_test.go", "line": 228, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_capacity_self_interference_total": [
        {"kind": "negative_fixture", "name": "TestABDCapacitySelfInterference", "file": "src/detector/hard_gate_producers_test.go", "line": 234, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_dns_single_resolver_spoof_confirmed_total": [
        {"kind": "negative_fixture", "name": "TestABDDNSSingleResolverSpoof", "file": "src/detector/hard_gate_producers_test.go", "line": 242, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_dns_cdn_variance_misclassified_total": [
        {"kind": "negative_fixture", "name": "TestABDDNSCdnVarianceMisclassified", "file": "src/detector/hard_gate_producers_test.go", "line": 248, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_unverified_mitm_verdict_total": [
        {"kind": "negative_fixture", "name": "TestABDUnverifiedMITMVerdict", "file": "src/detector/hard_gate_producers_test.go", "line": 254, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_tls_availability_integrity_conflation_total": [
        {"kind": "negative_fixture", "name": "TestABDTLSAvailabilityIntegrityConflation", "file": "src/detector/hard_gate_producers_test.go", "line": 260, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_tls_fingerprint_unlabeled_total": [
        {"kind": "negative_fixture", "name": "TestABDTLSFingerprintUnlabeled", "file": "src/detector/hard_gate_producers_test.go", "line": 266, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_quic_single_target_global_udp_verdict_total": [
        {"kind": "negative_fixture", "name": "TestABDQUICSingleTargetGlobalUDP", "file": "src/detector/hard_gate_producers_test.go", "line": 272, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_quic_tcp_evidence_conflation_total": [
        {"kind": "negative_fixture", "name": "TestABDQUICTCPEvidenceConflation", "file": "src/detector/hard_gate_producers_test.go", "line": 278, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_valid_application_error_dpi_total": [
        {"kind": "negative_fixture", "name": "TestABDValidAppErrorDPI", "file": "src/detector/hard_gate_producers_test.go", "line": 284, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_head_only_available_verdict_total": [
        {"kind": "negative_fixture", "name": "TestABDHeadOnlyAvailableVerdict", "file": "src/detector/hard_gate_producers_test.go", "line": 290, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_partial_progress_discarded_total": [
        {"kind": "negative_fixture", "name": "TestABDPartialProgressDiscarded", "file": "src/detector/hard_gate_producers_test.go", "line": 296, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_small_object_classified_throttled_total": [
        {"kind": "negative_fixture", "name": "TestABDSmallObjectClassifiedThrottled", "file": "src/detector/hard_gate_producers_test.go", "line": 302, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_fixed_16kb_window_confirmed_without_profile_total": [
        {"kind": "negative_fixture", "name": "TestABDFixed16kbWindowNoProfile", "file": "src/detector/hard_gate_producers_test.go", "line": 308, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_packet_threshold_reported_as_byte_threshold_total": [
        {"kind": "negative_fixture", "name": "TestABDPacketThresholdAsByte", "file": "src/detector/hard_gate_producers_test.go", "line": 316, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_byte_threshold_reported_as_packet_threshold_total": [
        {"kind": "negative_fixture", "name": "TestABDByteThresholdAsPacket", "file": "src/detector/hard_gate_producers_test.go", "line": 322, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_gso_skb_count_as_wire_packet_total": [
        {"kind": "negative_fixture", "name": "TestABDGsoSkbCountAsWirePacket", "file": "src/detector/hard_gate_producers_test.go", "line": 328, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_single_origin_l4_budget_confirmed_total": [
        {"kind": "negative_fixture", "name": "TestABDSingleOriginL4BudgetConfirmed", "file": "src/detector/hard_gate_producers_test.go", "line": 334, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_server_header_limit_dpi_total": [
        {"kind": "negative_fixture", "name": "TestABDServerHeaderLimitDPI", "file": "src/detector/hard_gate_producers_test.go", "line": 340, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_retransmission_counted_as_progress_total": [
        {"kind": "negative_fixture", "name": "TestABDRetransmissionAsProgress", "file": "src/detector/hard_gate_producers_test.go", "line": 346, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_l4_threshold_without_controls_total": [
        {"kind": "negative_fixture", "name": "TestABDL4ThresholdWithoutControls", "file": "src/detector/hard_gate_producers_test.go", "line": 352, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "blocking_profile_without_target_plan_total": [
        {"kind": "negative_fixture", "name": "TestABDBlockingProfileWithoutTargetPlan", "file": "src/detector/hard_gate_producers_test.go", "line": 360, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "blocking_profile_without_network_context_total": [
        {"kind": "negative_fixture", "name": "TestABDBlockingProfileWithoutNetCtx", "file": "src/detector/hard_gate_producers_test.go", "line": 368, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "blocking_profile_without_provenance_total": [
        {"kind": "negative_fixture", "name": "TestABDBlockingProfileWithoutProvenance", "file": "src/detector/hard_gate_producers_test.go", "line": 376, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "blocking_profile_mutated_after_compile_total": [
        {"kind": "negative_fixture", "name": "TestABDBlockingProfileMutatedAfterCompile", "file": "src/detector/hard_gate_producers_test.go", "line": 382, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "blocking_profile_high_confidence_with_contradiction_total": [
        {"kind": "negative_fixture", "name": "TestABDBlockingProfileHighConfidenceContradiction", "file": "src/detector/hard_gate_producers_test.go", "line": 388, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "blocking_profile_direct_action_authorization_total": [
        {"kind": "negative_fixture", "name": "TestABDBlockingProfileDirectActionAuth", "file": "src/detector/hard_gate_producers_test.go", "line": 394, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "blocking_profile_direct_production_write_total": [
        {"kind": "negative_fixture", "name": "TestABDBlockingProfileDirectProdWrite", "file": "src/detector/hard_gate_producers_test.go", "line": 400, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_skipped_baseline_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchSkippedBaseline", "file": "src/detector/hard_gate_producers_test.go", "line": 407, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_disabled_full_fallback_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchDisabledFullFallback", "file": "src/detector/hard_gate_producers_test.go", "line": 413, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_profile_overrode_current_baseline_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchOverrodeBaseline", "file": "src/detector/hard_gate_producers_test.go", "line": 419, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_target_unvalidated_promotion_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchUnvalidatedPromotion", "file": "src/detector/hard_gate_producers_test.go", "line": 425, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_cross_service_action_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchCrossServiceAction", "file": "src/detector/hard_gate_producers_test.go", "line": 433, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_white_sni_direct_promotion_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchWhiteSNIDirectPromotion", "file": "src/detector/hard_gate_producers_test.go", "line": 439, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_false_savings_report_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchFalseSavingsReport", "file": "src/detector/hard_gate_producers_test.go", "line": 445, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_required_component_uncovered_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchRequiredComponentUncovered", "file": "src/detector/hard_gate_producers_test.go", "line": 451, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_coverage_ignored_control_regression_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchCoverageIgnoredControlRegression", "file": "src/detector/hard_gate_producers_test.go", "line": 457, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_cross_service_set_cover_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchCrossServiceSetCover", "file": "src/detector/hard_gate_producers_test.go", "line": 463, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_excluded_target_hidden_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchExcludedTargetHidden", "file": "src/detector/hard_gate_producers_test.go", "line": 469, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_more_complex_candidate_preferred_without_gain_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchMoreComplexPreferredNoGain", "file": "src/detector/hard_gate_producers_test.go", "line": 475, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "guided_search_unverified_shortlist_promotion_total": [
        {"kind": "negative_fixture", "name": "TestABDGuidedSearchUnverifiedShortlist", "file": "src/detector/hard_gate_producers_test.go", "line": 481, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_monitor_request_direct_action_total": [
        {"kind": "negative_fixture", "name": "TestABDMonitorRequestDirectAction", "file": "src/detector/hard_gate_producers_test.go", "line": 489, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_monitor_request_without_target_plan_overlay_total": [
        {"kind": "negative_fixture", "name": "TestABDMonitorRequestWithoutTargetPlan", "file": "src/detector/hard_gate_producers_test.go", "line": 497, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_monitor_request_without_network_context_total": [
        {"kind": "negative_fixture", "name": "TestABDMonitorRequestWithoutNetworkCtx", "file": "src/detector/hard_gate_producers_test.go", "line": 505, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_monitor_request_without_config_generation_total": [
        {"kind": "negative_fixture", "name": "TestABDMonitorRequestWithoutConfigGen", "file": "src/detector/hard_gate_producers_test.go", "line": 513, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_monitor_request_without_budget_token_total": [
        {"kind": "negative_fixture", "name": "TestABDMonitorRequestWithoutBudgetToken", "file": "src/detector/hard_gate_producers_test.go", "line": 519, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_monitor_request_expired_accepted_total": [
        {"kind": "negative_fixture", "name": "TestABDMonitorRequestExpiredAccepted", "file": "src/detector/hard_gate_producers_test.go", "line": 526, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_provisional_monitor_evidence_profile_compiled_total": [
        {"kind": "negative_fixture", "name": "TestABDProvisionalMonitorProfileCompiled", "file": "src/detector/hard_gate_producers_test.go", "line": 532, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_passive_observation_counted_as_independent_probe_total": [
        {"kind": "negative_fixture", "name": "TestABDPassiveObservationAsIndependentProbe", "file": "src/detector/hard_gate_producers_test.go", "line": 538, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_monitor_recurrence_counted_as_evidence_independence_total": [
        {"kind": "negative_fixture", "name": "TestABDMonitorRecurrenceAsIndependence", "file": "src/detector/hard_gate_producers_test.go", "line": 544, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_client_resolution_replaced_silently_total": [
        {"kind": "negative_fixture", "name": "TestABDClientResolutionReplacedSilently", "file": "src/detector/hard_gate_producers_test.go", "line": 550, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_probe_without_resolution_binding_total": [
        {"kind": "negative_fixture", "name": "TestABDProbeWithoutResolutionBinding", "file": "src/detector/hard_gate_producers_test.go", "line": 556, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_cname_terminal_ip_misattributed_total": [
        {"kind": "negative_fixture", "name": "TestABDCnameTerminalIPMisattributed", "file": "src/detector/hard_gate_producers_test.go", "line": 564, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_multi_ip_partial_failure_hidden_total": [
        {"kind": "negative_fixture", "name": "TestABDMultiIPPartialFailureHidden", "file": "src/detector/hard_gate_producers_test.go", "line": 574, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_stale_client_resolution_used_total": [
        {"kind": "negative_fixture", "name": "TestABDStaleClientResolutionUsed", "file": "src/detector/hard_gate_producers_test.go", "line": 582, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_result_without_monitor_assessment_link_total": [
        {"kind": "negative_fixture", "name": "TestABDResultWithoutAssessmentLink", "file": "src/detector/hard_gate_producers_test.go", "line": 588, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_result_cross_network_context_total": [
        {"kind": "negative_fixture", "name": "TestABDResultCrossNetworkContext", "file": "src/detector/hard_gate_producers_test.go", "line": 594, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_result_cross_config_generation_total": [
        {"kind": "negative_fixture", "name": "TestABDResultCrossConfigGeneration", "file": "src/detector/hard_gate_producers_test.go", "line": 600, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_result_cross_monitoring_epoch_total": [
        {"kind": "negative_fixture", "name": "TestABDResultCrossMonitoringEpoch", "file": "src/detector/hard_gate_producers_test.go", "line": 606, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_incomplete_run_final_profile_total": [
        {"kind": "negative_fixture", "name": "TestABDIncompleteRunFinalProfile", "file": "src/detector/hard_gate_producers_test.go", "line": 612, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_monitor_result_action_authorization_total": [
        {"kind": "negative_fixture", "name": "TestABDMonitorResultActionAuthorization", "file": "src/detector/hard_gate_producers_test.go", "line": 618, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "detector_monitor_result_delivery_identity_mismatch_total": [
        {"kind": "negative_fixture", "name": "TestABDMonitorResultDeliveryIdentityMismatch", "file": "src/detector/hard_gate_producers_test.go", "line": 627, "assertion": "violating branch -> denied && counter > 0"},
    ],
# --- MON negative fixtures (addendum v1.0 84-92): each test drives the
    # violating branch of the production guard and asserts the
    # zero-tolerance counter moved. ---
    "monitor_observation_direct_action_total": [
        {"kind": "negative_fixture", "name": "TestMONObservationDirectAction", "file": "src/monitoring/hard_gate_producers_test.go", "line": 122, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_provisional_profile_compiled_total": [
        {"kind": "negative_fixture", "name": "TestMONProvisionalProfileCompiled", "file": "src/monitoring/hard_gate_producers_test.go", "line": 128, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_passive_discovery_start_total": [
        {"kind": "negative_fixture", "name": "TestMONPassiveDiscoveryStart", "file": "src/monitoring/hard_gate_producers_test.go", "line": 134, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_passive_warp_enable_total": [
        {"kind": "negative_fixture", "name": "TestMONPassiveWarpEnable", "file": "src/monitoring/hard_gate_producers_test.go", "line": 140, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_fast_lane_action_total": [
        {"kind": "negative_fixture", "name": "TestMONFastLaneAction", "file": "src/monitoring/hard_gate_producers_test.go", "line": 146, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_fast_lane_promoted_as_authoritative_total": [
        {"kind": "negative_fixture", "name": "TestMONFastLanePromotedAsAuthoritative", "file": "src/monitoring/hard_gate_producers_test.go", "line": 152, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_destination_only_deep_trigger_total": [
        {"kind": "negative_fixture", "name": "TestMONDestinationOnlyDeepTrigger", "file": "src/monitoring/hard_gate_producers_test.go", "line": 162, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_cross_client_merge_total": [
        {"kind": "negative_fixture", "name": "TestMONCrossClientMerge", "file": "src/monitoring/hard_gate_producers_test.go", "line": 168, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_cross_service_merge_total": [
        {"kind": "negative_fixture", "name": "TestMONCrossServiceMerge", "file": "src/monitoring/hard_gate_producers_test.go", "line": 176, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_cross_component_merge_total": [
        {"kind": "negative_fixture", "name": "TestMONCrossComponentMerge", "file": "src/monitoring/hard_gate_producers_test.go", "line": 184, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_cross_wan_evidence_merge_total": [
        {"kind": "negative_fixture", "name": "TestMONCrossWanEvidenceMerge", "file": "src/monitoring/hard_gate_producers_test.go", "line": 192, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_cross_generation_evidence_merge_total": [
        {"kind": "negative_fixture", "name": "TestMONCrossGenerationEvidenceMerge", "file": "src/monitoring/hard_gate_producers_test.go", "line": 200, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_router_origin_as_forwarded_proof_total": [
        {"kind": "negative_fixture", "name": "TestMONRouterOriginAsForwardedProof", "file": "src/monitoring/hard_gate_producers_test.go", "line": 206, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_duplicate_evidence_independence_total": [
        {"kind": "negative_fixture", "name": "TestMONDupEvidenceIndependence", "file": "src/monitoring/hard_gate_producers_test.go", "line": 214, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_temporal_persistence_without_time_separation_total": [
        {"kind": "negative_fixture", "name": "TestMONTemporalPersistenceNoSeparation", "file": "src/monitoring/hard_gate_producers_test.go", "line": 221, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_success_suppressor_ignored_total": [
        {"kind": "negative_fixture", "name": "TestMONSuccessSuppressorIgnored", "file": "src/monitoring/hard_gate_producers_test.go", "line": 227, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_recovered_subject_not_demoted_total": [
        {"kind": "negative_fixture", "name": "TestMONRecoveredSubjectNotDemoted", "file": "src/monitoring/hard_gate_producers_test.go", "line": 233, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_expired_evidence_used_total": [
        {"kind": "negative_fixture", "name": "TestMONExpiredEvidenceUsed", "file": "src/monitoring/hard_gate_producers_test.go", "line": 240, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_decay_disabled_without_policy_total": [
        {"kind": "negative_fixture", "name": "TestMONDecayDisabledWithoutPolicy", "file": "src/monitoring/hard_gate_producers_test.go", "line": 246, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_probe_without_resolution_binding_total": [
        {"kind": "negative_fixture", "name": "TestMONProbeWithoutResolutionBinding", "file": "src/monitoring/hard_gate_producers_test.go", "line": 254, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_client_dns_answer_replaced_silently_total": [
        {"kind": "negative_fixture", "name": "TestMONClientDNSAnswerReplacedSilently", "file": "src/monitoring/hard_gate_producers_test.go", "line": 261, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_cname_terminal_ip_misattributed_total": [
        {"kind": "negative_fixture", "name": "TestMONCnameTerminalIPMisattributed", "file": "src/monitoring/hard_gate_producers_test.go", "line": 269, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_multi_ip_partial_failure_hidden_total": [
        {"kind": "negative_fixture", "name": "TestMONMultiIPPartialFailureHidden", "file": "src/monitoring/hard_gate_producers_test.go", "line": 279, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_stale_resolution_used_as_exact_proof_total": [
        {"kind": "negative_fixture", "name": "TestMONStaleResolutionExactProof", "file": "src/monitoring/hard_gate_producers_test.go", "line": 287, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_trigger_without_visibility_total": [
        {"kind": "negative_fixture", "name": "TestMONTriggerWithoutVisibility", "file": "src/monitoring/hard_gate_producers_test.go", "line": 295, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_trigger_without_budget_total": [
        {"kind": "negative_fixture", "name": "TestMONTriggerWithoutBudget", "file": "src/monitoring/hard_gate_producers_test.go", "line": 301, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_trigger_during_global_wan_failure_total": [
        {"kind": "negative_fixture", "name": "TestMONTriggerDuringGlobalWanFailure", "file": "src/monitoring/hard_gate_producers_test.go", "line": 307, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_trigger_with_stale_source_heartbeat_total": [
        {"kind": "negative_fixture", "name": "TestMONTriggerWithStaleHeartbeat", "file": "src/monitoring/hard_gate_producers_test.go", "line": 314, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_duplicate_concurrent_abd_run_total": [
        {"kind": "negative_fixture", "name": "TestMONDupConcurrentABDRun", "file": "src/monitoring/hard_gate_producers_test.go", "line": 320, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_unbounded_target_intake_total": [
        {"kind": "negative_fixture", "name": "TestMONUnboundedTargetIntake", "file": "src/monitoring/hard_gate_producers_test.go", "line": 326, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_unbounded_probe_parallelism_total": [
        {"kind": "negative_fixture", "name": "TestMONUnboundedProbeParallelism", "file": "src/monitoring/hard_gate_producers_test.go", "line": 332, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_self_interference_total": [
        {"kind": "negative_fixture", "name": "TestMONSelfInterference", "file": "src/monitoring/hard_gate_producers_test.go", "line": 338, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_reference_result_as_action_authorization_total": [
        {"kind": "negative_fixture", "name": "TestMONReferenceResultAsAuthorization", "file": "src/monitoring/hard_gate_producers_test.go", "line": 346, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_abd_request_without_target_plan_total": [
        {"kind": "negative_fixture", "name": "TestMONABDRequestWithoutTargetPlan", "file": "src/monitoring/hard_gate_producers_test.go", "line": 356, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_abd_partial_result_profile_ready_total": [
        {"kind": "negative_fixture", "name": "TestMONABDPartialResultProfileReady", "file": "src/monitoring/hard_gate_producers_test.go", "line": 362, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_abd_result_bypassed_ddi_total": [
        {"kind": "negative_fixture", "name": "TestMONABDResultBypassedDDI", "file": "src/monitoring/hard_gate_producers_test.go", "line": 368, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_discovery_without_authoritative_profile_total": [
        {"kind": "negative_fixture", "name": "TestMONDiscoveryWithoutAuthProfile", "file": "src/monitoring/hard_gate_producers_test.go", "line": 374, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_discovery_skipped_mandatory_baseline_total": [
        {"kind": "negative_fixture", "name": "TestMONDiscoverySkippedMandatoryBaseline", "file": "src/monitoring/hard_gate_producers_test.go", "line": 384, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_recommendation_without_scope_total": [
        {"kind": "negative_fixture", "name": "TestMONRecommendationWithoutScope", "file": "src/monitoring/hard_gate_producers_test.go", "line": 390, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_warp_recommendation_without_ip_path_evidence_total": [
        {"kind": "negative_fixture", "name": "TestMONWarpRecommendationWithoutIPPath", "file": "src/monitoring/hard_gate_producers_test.go", "line": 397, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_legacy_watchdog_direct_apply_total": [
        {"kind": "negative_fixture", "name": "TestMONLegacyWatchdogDirectApply", "file": "src/monitoring/hard_gate_producers_test.go", "line": 405, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_legacy_watchdog_created_unvalidated_set_total": [
        {"kind": "negative_fixture", "name": "TestMONLegacyWatchdogUnvalidatedSet", "file": "src/monitoring/hard_gate_producers_test.go", "line": 411, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_legacy_watchdog_overwrote_set_without_canary_total": [
        {"kind": "negative_fixture", "name": "TestMONLegacyWatchdogOverwriteNoCanary", "file": "src/monitoring/hard_gate_producers_test.go", "line": 417, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_legacy_api_projection_mutation_total": [
        {"kind": "negative_fixture", "name": "TestMONLegacyAPIProjectionMutation", "file": "src/monitoring/hard_gate_producers_test.go", "line": 423, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_shadow_and_active_writer_overlap_total": [
        {"kind": "negative_fixture", "name": "TestMONShadowActiveWriterOverlap", "file": "src/monitoring/hard_gate_producers_test.go", "line": 429, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_required_event_drop_hidden_total": [
        {"kind": "negative_fixture", "name": "TestMONRequiredEventDropHidden", "file": "src/monitoring/hard_gate_producers_test.go", "line": 437, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_source_heartbeat_stale_auto_diagnose_total": [
        {"kind": "negative_fixture", "name": "TestMONSourceHeartbeatStaleAutoDiagnose", "file": "src/monitoring/hard_gate_producers_test.go", "line": 444, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_checkpoint_corruption_false_ready_total": [
        {"kind": "negative_fixture", "name": "TestMONCheckpointCorruptionFalseReady", "file": "src/monitoring/hard_gate_producers_test.go", "line": 450, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_restart_reused_expired_lease_total": [
        {"kind": "negative_fixture", "name": "TestMONRestartReusedExpiredLease", "file": "src/monitoring/hard_gate_producers_test.go", "line": 458, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_sensitive_dns_history_export_total": [
        {"kind": "negative_fixture", "name": "TestMONSensitiveDNSHistoryExport", "file": "src/monitoring/hard_gate_producers_test.go", "line": 464, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_secret_trace_leak_total": [
        {"kind": "negative_fixture", "name": "TestMONSecretTraceLeak", "file": "src/monitoring/hard_gate_producers_test.go", "line": 470, "assertion": "violating branch -> denied && counter > 0"},
    ],
    "monitor_high_cardinality_metric_label_total": [
        {"kind": "negative_fixture", "name": "TestMONHighCardinalityMetricLabel", "file": "src/monitoring/hard_gate_producers_test.go", "line": 476, "assertion": "violating branch -> denied && counter > 0"},
    ],
# --- SPF negative fixtures (addendum v1.0 45): each test drives the
    # violating branch of the production guard and asserts the
    # zero-tolerance counter moved. ---
    "silent_failure_action_without_authorization_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFActionWithoutAuthorization", "file": "src/silentpath/hard_gate_producers_test.go", "line": 83, "assertion": "auth.ID empty / !auth.Final / zero client -> denied && counter > 0"},
    ],
    "silent_failure_action_with_incomplete_visibility_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFActionWithIncompleteVisibility", "file": "src/silentpath/hard_gate_producers_test.go", "line": 92, "assertion": "incomplete CapabilitySnapshot -> denied && counter > 0"},
    ],
    "silent_failure_destination_only_state_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFDestinationOnlyState", "file": "src/silentpath/hard_gate_producers_test.go", "line": 98, "assertion": "destination-only scope -> true && counter > 0"},
    ],
    "silent_failure_cross_client_action_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFCrossClientAction", "file": "src/silentpath/hard_gate_producers_test.go", "line": 106, "assertion": "scope client differs from authorized client -> denied && counter > 0"},
    ],
    "silent_failure_cross_service_action_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFCrossServiceAction", "file": "src/silentpath/hard_gate_producers_test.go", "line": 114, "assertion": "scope domain differs from authorized domain -> denied && counter > 0"},
    ],
    "silent_failure_cross_component_action_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFCrossComponentAction", "file": "src/silentpath/hard_gate_producers_test.go", "line": 122, "assertion": "scope component differs from authorized component -> denied && counter > 0"},
    ],
    "silent_failure_cross_generation_action_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFCrossGenerationAction", "file": "src/silentpath/hard_gate_producers_test.go", "line": 128, "assertion": "scope generation differs from authorized generation -> denied && counter > 0"},
    ],
    "silent_failure_single_signal_auto_fallback_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFSingleSignalAutoFallback", "file": "src/silentpath/hard_gate_producers_test.go", "line": 136, "assertion": "one evidence family -> denied && counter > 0"},
    ],
    "silent_failure_non_independent_evidence_auto_fallback_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFNonIndependentEvidenceAutoFallback", "file": "src/silentpath/hard_gate_producers_test.go", "line": 142, "assertion": "evidence without independent family -> denied && counter > 0"},
    ],
    "silent_failure_suppressor_ignored_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFSuppressorIgnored", "file": "src/silentpath/hard_gate_producers_test.go", "line": 153, "assertion": "active resource suppressor + proceed -> counter > 0"},
    ],
    "silent_failure_fast_parallel_false_positive_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFFastParallelFalsePositive", "file": "src/silentpath/hard_gate_producers_test.go", "line": 161, "assertion": "ReasonLikelyParallel evidence -> counter > 0"},
    ],
    "silent_failure_recent_success_false_positive_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFRecentSuccessFalsePositive", "file": "src/silentpath/hard_gate_producers_test.go", "line": 167, "assertion": "fresh success suppressor + proceed -> counter > 0"},
    ],
    "silent_failure_explicit_server_error_misclassified_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFExplicitServerErrorMisclassified", "file": "src/silentpath/hard_gate_producers_test.go", "line": 175, "assertion": "ReasonExplicitServerResponse evidence -> counter > 0"},
    ],
    "silent_failure_gso_mss_progress_mismatch_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFGsoMssProgressMismatch", "file": "src/silentpath/hard_gate_producers_test.go", "line": 181, "assertion": "2900 bytes with MSS 1460 -> counter > 0"},
    ],
    "silent_failure_ppe_visibility_violation_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFPpeVisibilityViolation", "file": "src/silentpath/hard_gate_producers_test.go", "line": 187, "assertion": "OffloadProven=false promote=true -> counter > 0"},
    ],
    "silent_failure_unbounded_probe_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFUnboundedProbe", "file": "src/silentpath/hard_gate_producers_test.go", "line": 195, "assertion": "attempts >= maxAttempts -> denied && counter > 0"},
    ],
    "silent_failure_unbounded_rotation_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFUnboundedRotation", "file": "src/silentpath/hard_gate_producers_test.go", "line": 201, "assertion": "attempts >= MaxAttempts -> denied && counter > 0"},
    ],
    "silent_failure_recursive_transport_fallback_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFRecursiveTransportFallback", "file": "src/silentpath/hard_gate_producers_test.go", "line": 207, "assertion": "current==candidate transport path -> denied && counter > 0"},
    ],
    "silent_failure_recovery_without_rollback_target_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFRecoveryWithoutRollbackTarget", "file": "src/silentpath/hard_gate_producers_test.go", "line": 213, "assertion": "lease with empty Rollback -> denied && counter > 0"},
    ],
    "silent_failure_control_regression_promoted_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFControlRegressionPromoted", "file": "src/silentpath/hard_gate_producers_test.go", "line": 219, "assertion": "unhealthy control probe -> denied && counter > 0"},
    ],
    "silent_failure_false_positive_budget_ignored_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFFalsePositiveBudgetIgnored", "file": "src/silentpath/hard_gate_producers_test.go", "line": 229, "assertion": "ObserveOnly monitor -> denied && counter > 0"},
    ],
    "silent_failure_user_revert_not_rolled_back_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_SPFUserRevertNotRolledBack", "file": "src/silentpath/hard_gate_producers_test.go", "line": 237, "assertion": "unknown lease id -> Rollback false && counter > 0"},
    ],
    # --- DDI/TGB negative fixtures (addendum v1.0 32/33): each test drives the
    # violating branch of the production guard and asserts the
    # zero-tolerance counter moved. ---
    "discovery_profile_without_context_validation_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDIContextValidation", "file": "src/discovery/hard_gate_producers_test.go", "line": 58, "assertion": "mismatched context ID -> denied && counter > 0"},
    ],
    "discovery_profile_stale_without_revalidation_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDIStaleWithoutRevalidation", "file": "src/discovery/hard_gate_producers_test.go", "line": 67, "assertion": "expired profile + not revalidated -> denied && counter > 0"},
    ],
    "discovery_profile_cross_wan_use_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDICrossWANUse", "file": "src/discovery/hard_gate_producers_test.go", "line": 76, "assertion": "WAN fingerprint mismatch -> denied && counter > 0"},
    ],
    "discovery_profile_mutable_runtime_pointer_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDIMutableRuntimePointer", "file": "src/discovery/hard_gate_producers_test.go", "line": 82, "assertion": "mutable binding -> denied && counter > 0"},
    ],
    "discovery_profile_hint_without_provenance_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDIHintWithoutProvenance", "file": "src/discovery/hard_gate_producers_test.go", "line": 88, "assertion": "candidate without provenance -> denied && counter > 0"},
    ],
    "discovery_profile_hint_overrode_current_baseline_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDIHintOverrodeBaseline", "file": "src/discovery/hard_gate_producers_test.go", "line": 94, "assertion": "leading candidate not in baseline -> denied && counter > 0"},
    ],
    "discovery_profile_skipped_target_validation_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDISkippedTargetValidation", "file": "src/discovery/hard_gate_producers_test.go", "line": 101, "assertion": "not target-validated -> denied && counter > 0"},
    ],
    "discovery_profile_disabled_exhaustive_fallback_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDIDisabledExhaustiveFallback", "file": "src/discovery/hard_gate_producers_test.go", "line": 107, "assertion": "ExhaustiveFallback=false -> denied && counter > 0"},
    ],
    "discovery_profile_direct_production_write_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDIDirectProductionWrite", "file": "src/discovery/hard_gate_producers_test.go", "line": 113, "assertion": "unstaged write -> denied && counter > 0"},
    ],
    "discovery_profile_allowed_sni_direct_promotion_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDIAllowedSNIDirectPromotion", "file": "src/discovery/hard_gate_producers_test.go", "line": 119, "assertion": "SNI promotion of unvalidated target -> denied && counter > 0"},
    ],
    "discovery_profile_threshold_out_of_budget_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDIThresholdOutOfBudget", "file": "src/discovery/hard_gate_producers_test.go", "line": 125, "assertion": "threshold 100 > budget 50 -> denied && counter > 0"},
    ],
    "discovery_profile_capture_gate_bypass_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDICaptureGateBypass", "file": "src/discovery/hard_gate_producers_test.go", "line": 131, "assertion": "capture not ready -> denied && counter > 0"},
    ],
    "discovery_profile_cross_service_action_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDICrossServiceAction", "file": "src/discovery/hard_gate_producers_test.go", "line": 137, "assertion": "service profile / component mismatch -> denied && counter > 0"},
    ],
    "discovery_profile_false_pass_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_DDIFalsePass", "file": "src/discovery/hard_gate_producers_test.go", "line": 146, "assertion": "FalsePromotion=true -> denied && counter > 0"},
    ],
    "mtproto_bridge_zero_byte_handled_drop_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_TGBZeroByteHandledDrop", "file": "src/mtproto/hard_gate_producers_test.go", "line": 45, "assertion": "ReasonZeroByte + BridgeHandled -> denied && counter > 0"},
    ],
    "mtproto_bridge_fixed_5s_destructive_timeout_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_TGBFixed5sDestructiveTimeout", "file": "src/mtproto/hard_gate_producers_test.go", "line": 51, "assertion": "fixed 5s timeout -> denied && counter > 0"},
    ],
    "mtproto_bridge_unbounded_pending_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_TGBUnboundedPending", "file": "src/mtproto/hard_gate_producers_test.go", "line": 57, "assertion": "maxGlobal <= 0 -> denied && counter > 0"},
    ],
    "mtproto_bridge_pending_per_client_limit_bypass_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_TGBPendingPerClientBypass", "file": "src/mtproto/hard_gate_producers_test.go", "line": 63, "assertion": "maxClient <= 0 -> denied && counter > 0"},
    ],
    "mtproto_bridge_prefix_loss_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_TGBPrefixLoss", "file": "src/mtproto/hard_gate_producers_test.go", "line": 69, "assertion": "delivered < len(prefix) -> denied && counter > 0"},
    ],
    "mtproto_bridge_prefix_duplicate_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_TGBPrefixDuplicate", "file": "src/mtproto/hard_gate_producers_test.go", "line": 75, "assertion": "delivered > len(prefix) -> denied && counter > 0"},
    ],
    "mtproto_bridge_route_recursion_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_TGBRouteRecursion", "file": "src/mtproto/hard_gate_producers_test.go", "line": 81, "assertion": "RecursionGuard=false -> denied && counter > 0"},
    ],
    "mtproto_bridge_primary_failure_silent_drop_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_TGBPrimaryFailureSilentDrop", "file": "src/mtproto/hard_gate_producers_test.go", "line": 87, "assertion": "ReasonDialFailed + BridgeDrop -> denied && counter > 0"},
    ],
    "mtproto_bridge_overflow_without_reason_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_TGBOverflowWithoutReason", "file": "src/mtproto/hard_gate_producers_test.go", "line": 93, "assertion": "ErrPendingOverflow + empty reason -> denied && counter > 0"},
    ],
    "mtproto_bridge_shutdown_leak_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_TGBShutdownLeak", "file": "src/mtproto/hard_gate_producers_test.go", "line": 99, "assertion": "pending tokens at shutdown -> denied && counter > 0"},
    ],
    # asserts the zero-tolerance counter moved. ---
    "warp_secret_leak_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_WARPSecretLeak", "file": "src/warp/hard_gate_producers_test.go", "line": 42, "assertion": "trace payload with raw secret -> PublishTrace false && counter > 0"},
    ],
    "warp_foreign_interface_modified_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_WARPForeignInterfaceModified", "file": "src/warp/hard_gate_producers_test.go", "line": 72, "assertion": "foreign session claims owned TUN -> ApplyRoute err && counter > 0"},
    ],
    "warp_recursive_control_route_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_WARPRecursiveControlRoute", "file": "src/warp/hard_gate_producers_test.go", "line": 102, "assertion": "control route with warp-control-direct mark -> ApplyRoute err && counter > 0"},
    ],
    "warp_mark_collision_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_WARPMarkCollision", "file": "src/warp/hard_gate_producers_test.go", "line": 124, "assertion": "second session pins owned mark -> ApplyRoute err && counter > 0"},
    ],
    "warp_route_without_liveness_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_WARPRouteWithoutLiveness", "file": "src/warp/hard_gate_producers_test.go", "line": 154, "assertion": "promotion without liveness proof -> ApplyRoute err && counter > 0"},
    ],
    "warp_destination_set_partial_apply_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_WARPDestinationSetPartialApply", "file": "src/warp/hard_gate_producers_test.go", "line": 175, "assertion": "partially applied destination set -> ApplyRoute err && counter > 0"},
    ],
    "warp_unbounded_restart_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_WARPUnboundedRestart", "file": "src/warp/hard_gate_producers_test.go", "line": 197, "assertion": "restart beyond MaxRestarts -> err && counter > 0"},
    ],
    "warp_unbounded_registration_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_WARPUnboundedRegistration", "file": "src/warp/hard_gate_producers_test.go", "line": 219, "assertion": "enrollment beyond policy MaxAttempts -> err && counter > 0"},
    ],
    "warp_unrelated_control_action_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_WARPUnrelatedControlAction", "file": "src/warp/hard_gate_producers_test.go", "line": 239, "assertion": "control action on flow outside authorization -> err && counter > 0"},
    ],
    "warp_rollback_failure_total": [
        {"kind": "negative_fixture", "name": "TestHardGateProducer_WARPRollbackFailure", "file": "src/warp/hard_gate_producers_test.go", "line": 263, "assertion": "rollback without previous state -> err && counter > 0"},
    ],
    # --- FB-29 / FB-30 fixtures (mon + abd): resolution-erasure and
    # multi-vantage NO_OPINION fixtures in src/detector. ---
    "monitor_first_success_erased_address_failures_total": [
        {"kind": "positive_fixture", "name": "TestResolutionExperimentFirstSuccessDoesNotMaskSibling", "file": "src/detector/resolution_experiment_test.go", "line": 77, "assertion": "sibling failure surfaced in MaskedSiblings; ErasedByFirstSuccess == 1"},
        {"kind": "negative_fixture", "name": "TestResolutionExperimentErasureCounterSync", "file": "src/detector/resolution_experiment_test.go", "line": 132, "assertion": "MaskedSiblings aligns with ErasedByFirstSuccess; clean window keeps count 0"},
    ],
    "monitor_http_hypothesis_from_tcp_tls_only_observer_total": [
        {"kind": "positive_fixture", "name": "TestVantageTCPTLSOnlyObserverCannotSupportHTTPHypothesis", "file": "src/detector/abd_path_test.go", "line": 41, "assertion": "tcp/tls-only capability covers tcp/tls, never http/body; CompareVantage returns NO_OPINION"},
    ],
    "monitor_observer_unavailable_as_target_failure_total": [
        {"kind": "positive_fixture", "name": "TestVantageUnavailableIsNoOpinion", "file": "src/detector/abd_path_test.go", "line": 27, "assertion": "unavailable observer yields NO_OPINION; never a target-failure claim"},
    ],
    "monitor_exact_endpoint_service_resolution_conflated_total": [
        {"kind": "positive_fixture", "name": "TestVantageExactModeIdentityConflationNoOpinion", "file": "src/detector/abd_path_test.go", "line": 79, "assertion": "mismatched exact/independent mode yields NO_OPINION"},
    ],
    "monitor_observer_capability_unproven_total": [
        {"kind": "positive_fixture", "name": "TestVantageCapabilityUnprovenIsNoOpinion", "file": "src/detector/abd_path_test.go", "line": 65, "assertion": "stale/unproven observer capability yields NO_OPINION"},
    ],
    "detector_first_success_erased_address_failures_total": [
        {"kind": "positive_fixture", "name": "TestResolutionExperimentFirstSuccessDoesNotMaskSibling", "file": "src/detector/resolution_experiment_test.go", "line": 77, "assertion": "sibling failure surfaced in MaskedSiblings; ErasedByFirstSuccess == 1"},
    ],
    "detector_multivantage_stage_mismatch_total": [
        {"kind": "positive_fixture", "name": "TestVantageStageMismatchNoOpinion", "file": "src/detector/abd_path_test.go", "line": 97, "assertion": "stage-mismatched observer yields NO_OPINION"},
    ],
    "detector_http_hypothesis_from_tcp_tls_only_observer_total": [
        {"kind": "positive_fixture", "name": "TestVantageTCPTLSOnlyObserverCannotSupportHTTPHypothesis", "file": "src/detector/abd_path_test.go", "line": 41, "assertion": "tcp/tls-only capability never covers http/body; CompareVantage returns NO_OPINION"},
    ],
    "detector_observer_unavailable_as_target_failure_total": [
        {"kind": "positive_fixture", "name": "TestVantageUnavailableIsNoOpinion", "file": "src/detector/abd_path_test.go", "line": 27, "assertion": "unavailable observer yields NO_OPINION; never a target-failure claim"},
    ],
    "detector_exact_endpoint_service_resolution_conflated_total": [
        {"kind": "positive_fixture", "name": "TestVantageExactModeIdentityConflationNoOpinion", "file": "src/detector/abd_path_test.go", "line": 79, "assertion": "mismatched exact/independent mode or target yields NO_OPINION"},
    ],
    "detector_observer_capability_unproven_total": [
        {"kind": "positive_fixture", "name": "TestVantageCapabilityUnprovenIsNoOpinion", "file": "src/detector/abd_path_test.go", "line": 65, "assertion": "stale/unproven observer capability yields NO_OPINION"},
    ],
    # --- SP WARP-recommendation negative fixtures (addendum v1.6 28A.11):
    # each test drives the violating branch of the production guard and
    # asserts the zero-tolerance counter moved. ---
    "profile_warp_recommended_without_ip_path_evidence_total": [
        {"kind": "negative_fixture", "name": "TestSPRecommendedWithoutIPPathEvidence", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 82, "assertion": "no IP-path evidence -> denied && counter > 0"},
    ],
    "profile_warp_recommended_from_destination_ip_only_total": [
        {"kind": "negative_fixture", "name": "TestSPRecommendedFromDestinationIPOnly", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 90, "assertion": "empty ClientScopeHash -> denied && counter > 0"},
    ],
    "profile_warp_recommended_for_origin_dead_total": [
        {"kind": "negative_fixture", "name": "TestSPRecommendedForOriginDead", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 100, "assertion": "dead origin -> denied && counter > 0"},
    ],
    "profile_warp_recommended_with_unhealthy_controls_total": [
        {"kind": "negative_fixture", "name": "TestSPRecommendedWithUnhealthyControls", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 108, "assertion": "unhealthy controls -> denied && counter > 0"},
    ],
    "profile_warp_recommendation_cross_service_total": [
        {"kind": "negative_fixture", "name": "TestSPCrossServiceRecommendation", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 116, "assertion": "consumer service mismatch -> denied && counter > 0"},
    ],
    "profile_warp_recommendation_stale_profile_total": [
        {"kind": "negative_fixture", "name": "TestSPStaleProfileRecommendation", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 124, "assertion": "expired eligible recommendation -> denied && counter > 0"},
    ],
    "profile_warp_recommendation_without_causal_trace_gate_total": [
        {"kind": "negative_fixture", "name": "TestSPWithoutCausalTraceGate", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 134, "assertion": "CausalTraceReady=false -> denied && counter > 0"},
    ],
    "profile_warp_enabled_without_target_canary_total": [
        {"kind": "negative_fixture", "name": "TestSPEnabledWithoutTargetCanary", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 144, "assertion": "TargetCanarySupported=false -> denied && counter > 0"},
    ],
    "profile_warp_test_token_reused_as_production_authorization_total": [
        {"kind": "negative_fixture", "name": "TestSPTestTokenReusedAsProductionAuthorization", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 154, "assertion": "live TestToken with ProductionAuthorized -> denied && counter > 0"},
    ],
    "profile_warp_recommendation_ignored_control_regression_total": [
        {"kind": "negative_fixture", "name": "TestSPIgnoredControlRegression", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 163, "assertion": "regression reported healthy -> denied && counter > 0"},
    ],
    "profile_warp_recommendation_hidden_fail_policy_total": [
        {"kind": "negative_fixture", "name": "TestSPHiddenFailPolicy", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 171, "assertion": "empty failure policy preview -> denied && counter > 0"},
    ],
    "profile_nonru_suggested_without_geo_requirement_total": [
        {"kind": "negative_fixture", "name": "TestSPNonRUSuggestedWithoutGeoRequirement", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 179, "assertion": "strict non-ru without geo requirement -> denied && counter > 0"},
    ],
    "profile_warp_camouflage_suggested_for_target_ip_block_total": [
        {"kind": "negative_fixture", "name": "TestSPCamouflageSuggestedForTargetIPBlock", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 188, "assertion": "camouflage for ip-blocked target -> denied && counter > 0"},
    ],
    "profile_warp_recommendation_cleanup_failure_total": [
        {"kind": "negative_fixture", "name": "TestSPRecommendationCleanupFailure", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 197, "assertion": "CleanedUp=false -> denied && counter > 0"},
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
        {
            "kind": "removed_delta",
            "name": "TestEvaluateHardGatesWindowDelta (window-delta aggregation)",
            "file": "src/validation/gates_test.go",
            "line": 224,
            "status": "executed",
        },
    ],
    "nfqueue_gso_truncated_total": [
        {"kind": "removed_inc", "name": "TestHardGateProducer_GSOOffloadMetadata (producer removed)", "file": "src/nfq/hard_gate_producers_test.go", "line": 37, "status": "executed"},
        {"kind": "removed_delta", "name": "TestEvaluateHardGatesReadinessInputsNeverBlock (readiness never blocks)", "file": "src/validation/gates_test.go", "line": 275, "status": "executed"},
    ],
    "nfqueue_gso_csum_not_ready_total": [
        {"kind": "removed_inc", "name": "TestHardGateProducer_GSOOffloadMetadata (producer removed)", "file": "src/nfq/hard_gate_producers_test.go", "line": 37, "status": "executed"},
        {"kind": "removed_delta", "name": "TestEvaluateHardGatesReadinessInputsNeverBlock (readiness never blocks)", "file": "src/validation/gates_test.go", "line": 275, "status": "executed"},
    ],
    "nfqueue_gso_token_miss_total": [
        {"kind": "removed_inc", "name": "TestHardGateProducer_GSOTokenMiss (producer removed)", "file": "src/nfq/hard_gate_producers_test.go", "line": 90, "status": "executed"},
        {"kind": "removed_delta", "name": "TestEvaluateHardGatesReadinessInputsNeverBlock (readiness never blocks)", "file": "src/validation/gates_test.go", "line": 275, "status": "executed"},
    ],
    "classifier_layout_parity_fail_total": [
        {"kind": "removed_inc", "name": "TestHardGateProducer_ClassifierLayoutParity (producer removed)", "file": "src/nfq/hard_gate_producers_test.go", "line": 175, "status": "executed"},
        {"kind": "removed_delta", "name": "TestEvaluateHardGatesWindowDelta (window-delta aggregation)", "file": "src/validation/gates_test.go", "line": 224, "status": "executed"},
    ],
    "passive_rst_fail_open_total": [
        {"kind": "removed_inc", "name": "TestHardGateProducer_PassiveRSTMetrics (producer removed)", "file": "src/nfq/hard_gate_producers_test.go", "line": 102, "status": "executed"},
        {"kind": "removed_delta", "name": "TestEvaluateHardGatesReadinessInputsNeverBlock (safe-degradation telemetry)", "file": "src/validation/gates_test.go", "line": 275, "status": "executed"},
    ],
    "passive_rst_reconnect_regression_total": [
        {"kind": "removed_inc", "name": "TestHardGateProducer_PassiveRSTRollback (producer removed)", "file": "src/nfq/hard_gate_producers_test.go", "line": 141, "status": "executed"},
        {"kind": "removed_delta", "name": "TestEvaluateHardGatesWindowDelta (window-delta aggregation)", "file": "src/validation/gates_test.go", "line": 224, "status": "executed"},
    ],
    "b4_capture_visibility_degrade_total": [
        {"kind": "removed_inc", "name": "TestHardGateProducer_CaptureVisibilityDegrade (producer removed)", "file": "src/capture/ppe/hard_gate_producers_test.go", "line": 31, "status": "executed"},
        {"kind": "removed_delta", "name": "TestEvaluateHardGatesReadinessInputsNeverBlock (readiness never blocks)", "file": "src/validation/gates_test.go", "line": 275, "status": "executed"},
    ],
    "b4_hold_disabled_visibility_total": [
        {"kind": "removed_inc", "name": "TestHardGateProducer_CaptureVisibilityDegrade (producer removed)", "file": "src/capture/ppe/hard_gate_producers_test.go", "line": 31, "status": "executed"},
        {"kind": "removed_delta", "name": "TestEvaluateHardGatesReadinessInputsNeverBlock (safety-guard telemetry)", "file": "src/validation/gates_test.go", "line": 275, "status": "executed"},
    ],
    # --- FB-29 / FB-30 mutation runs (mon + abd) ---
    "monitor_first_success_erased_address_failures_total": [
        {"kind": "collapse_to_first_success", "name": "TestResolutionExperimentFirstSuccessDoesNotMaskSibling (erasure regression)", "file": "src/detector/resolution_experiment_test.go", "line": 77, "status": "executed"},
    ],
    "monitor_http_hypothesis_from_tcp_tls_only_observer_total": [
        {"kind": "remove_stage_capability_gate", "name": "TestVantageTCPTLSOnlyObserverCannotSupportHTTPHypothesis (no-opinion regression)", "file": "src/detector/abd_path_test.go", "line": 41, "status": "executed"},
    ],
    "monitor_observer_unavailable_as_target_failure_total": [
        {"kind": "treat_unavailable_as_failure", "name": "TestVantageUnavailableIsNoOpinion (no-opinion regression)", "file": "src/detector/abd_path_test.go", "line": 27, "status": "executed"},
    ],
    "monitor_exact_endpoint_service_resolution_conflated_total": [
        {"kind": "remove_mode_gate", "name": "TestVantageExactModeIdentityConflationNoOpinion (regression)", "file": "src/detector/abd_path_test.go", "line": 79, "status": "executed"},
    ],
    "monitor_observer_capability_unproven_total": [
        {"kind": "remove_capability_fresh_gate", "name": "TestVantageCapabilityUnprovenIsNoOpinion (regression)", "file": "src/detector/abd_path_test.go", "line": 65, "status": "executed"},
    ],
    "detector_first_success_erased_address_failures_total": [
        {"kind": "collapse_to_first_success", "name": "TestResolutionExperimentFirstSuccessDoesNotMaskSibling (erasure regression)", "file": "src/detector/resolution_experiment_test.go", "line": 77, "status": "executed"},
    ],
    "detector_multivantage_stage_mismatch_total": [
        {"kind": "remove_stage_alignment", "name": "TestVantageStageMismatchNoOpinion (regression)", "file": "src/detector/abd_path_test.go", "line": 97, "status": "executed"},
    ],
    "detector_http_hypothesis_from_tcp_tls_only_observer_total": [
        {"kind": "remove_stage_capability_gate", "name": "TestVantageTCPTLSOnlyObserverCannotSupportHTTPHypothesis (no-opinion regression)", "file": "src/detector/abd_path_test.go", "line": 41, "status": "executed"},
    ],
    "detector_observer_unavailable_as_target_failure_total": [
        {"kind": "treat_unavailable_as_failure", "name": "TestVantageUnavailableIsNoOpinion (no-opinion regression)", "file": "src/detector/abd_path_test.go", "line": 27, "status": "executed"},
    ],
    "detector_exact_endpoint_service_resolution_conflated_total": [
        {"kind": "remove_mode_gate", "name": "TestVantageExactModeIdentityConflationNoOpinion (regression)", "file": "src/detector/abd_path_test.go", "line": 79, "status": "executed"},
    ],
    "detector_observer_capability_unproven_total": [
        {"kind": "remove_capability_fresh_gate", "name": "TestVantageCapabilityUnprovenIsNoOpinion (regression)", "file": "src/detector/abd_path_test.go", "line": 65, "status": "executed"},
    ],
    # --- FB-02 sp section mutation run (b4x-61d): every removed spInc call
    # kills its pinning negative fixture (14/14 killed) ---
    "profile_warp_recommended_without_ip_path_evidence_total": [
        {"kind": "removed_inc", "name": "TestSPRecommendedWithoutIPPathEvidence (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 82, "status": "executed"},
    ],
    "profile_warp_recommended_from_destination_ip_only_total": [
        {"kind": "removed_inc", "name": "TestSPRecommendedFromDestinationIPOnly (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 90, "status": "executed"},
    ],
    "profile_warp_recommended_for_origin_dead_total": [
        {"kind": "removed_inc", "name": "TestSPRecommendedForOriginDead (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 100, "status": "executed"},
    ],
    "profile_warp_recommended_with_unhealthy_controls_total": [
        {"kind": "removed_inc", "name": "TestSPRecommendedWithUnhealthyControls (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 108, "status": "executed"},
    ],
    "profile_warp_recommendation_cross_service_total": [
        {"kind": "removed_inc", "name": "TestSPCrossServiceRecommendation (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 116, "status": "executed"},
    ],
    "profile_warp_recommendation_stale_profile_total": [
        {"kind": "removed_inc", "name": "TestSPStaleProfileRecommendation (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 124, "status": "executed"},
    ],
    "profile_warp_recommendation_without_causal_trace_gate_total": [
        {"kind": "removed_inc", "name": "TestSPWithoutCausalTraceGate (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 134, "status": "executed"},
    ],
    "profile_warp_enabled_without_target_canary_total": [
        {"kind": "removed_inc", "name": "TestSPEnabledWithoutTargetCanary (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 144, "status": "executed"},
    ],
    "profile_warp_test_token_reused_as_production_authorization_total": [
        {"kind": "removed_inc", "name": "TestSPTestTokenReusedAsProductionAuthorization (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 154, "status": "executed"},
    ],
    "profile_warp_recommendation_ignored_control_regression_total": [
        {"kind": "removed_inc", "name": "TestSPIgnoredControlRegression (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 163, "status": "executed"},
    ],
    "profile_warp_recommendation_hidden_fail_policy_total": [
        {"kind": "removed_inc", "name": "TestSPHiddenFailPolicy (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 171, "status": "executed"},
    ],
    "profile_nonru_suggested_without_geo_requirement_total": [
        {"kind": "removed_inc", "name": "TestSPNonRUSuggestedWithoutGeoRequirement (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 179, "status": "executed"},
    ],
    "profile_warp_camouflage_suggested_for_target_ip_block_total": [
        {"kind": "removed_inc", "name": "TestSPCamouflageSuggestedForTargetIPBlock (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 188, "status": "executed"},
    ],
    "profile_warp_recommendation_cleanup_failure_total": [
        {"kind": "removed_inc", "name": "TestSPRecommendationCleanupFailure (producer removed)", "file": "src/serviceprofile/hard_gate_producers_test.go", "line": 197, "status": "executed"},
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
_EVIDENCE_RSTGSO = [
    "artifacts/audit/hard_gates_audit.md",
    "artifacts/audit/csi_ppe_rstgso_audit.md",
    "artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md",
    "src/nfq/hard_gate_producers_test.go",
]
_EVIDENCE_PPE = [
    "artifacts/audit/hard_gates_audit.md",
    "artifacts/audit/csi_ppe_rstgso_audit.md",
    "artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md",
    "src/capture/ppe/hard_gate_producers_test.go",
]
for _name in [
    "classifier_reassembled_sni_total", "classifier_layout_parity_fail_total",
    "nfqueue_gso_packets_total", "nfqueue_gso_bytes_total",
    "nfqueue_gso_truncated_total", "nfqueue_gso_csum_not_ready_total",
    "nfqueue_gso_decision_total", "nfqueue_gso_normalized_total",
    "nfqueue_gso_action_suppressed_total", "nfqueue_gso_token_miss_total",
    "passive_rst_observed_total", "passive_rst_decision_total",
    "passive_rst_suppressed_total", "passive_rst_fail_open_total",
    "passive_rst_baseline_quality_total", "passive_rst_budget_exhausted_total",
    "passive_rst_rollback_total", "passive_rst_reconnect_regression_total",
]:
    EVIDENCE_ARTIFACTS[_name] = list(_EVIDENCE_RSTGSO)
for _name in [
    "b4_ppe_rule_reapply_total", "b4_ppe_self_test_total",
    "b4_capture_visibility_degrade_total", "b4_hold_disabled_visibility_total",
]:
    EVIDENCE_ARTIFACTS[_name] = list(_EVIDENCE_PPE)
EVIDENCE_ARTIFACTS["nfqueue_gso_transition_total"] = [
    "artifacts/audit/hard_gates_audit.md",
    "artifacts/audit/csi_ppe_rstgso_audit.md",
    "artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md",
    "src/http/handler/hard_gate_producers_test.go",
]
_EVIDENCE_WARP = [
    "B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md",
    "artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md",
    "src/warp/hard_gate_producers_test.go",
    "src/warp/runtime.go",
]
for _name in [
    "warp_secret_leak_total", "warp_foreign_interface_modified_total",
    "warp_recursive_control_route_total", "warp_mark_collision_total",
    "warp_route_without_liveness_total",
    "warp_destination_set_partial_apply_total", "warp_unbounded_restart_total",
    "warp_unbounded_registration_total", "warp_unrelated_control_action_total",
    "warp_rollback_failure_total",
]:
    EVIDENCE_ARTIFACTS[_name] = list(_EVIDENCE_WARP)
_EVIDENCE_SPF = [
    "B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md",
    "artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md",
    "src/silentpath/hard_gate_producers_test.go",
    "src/silentpath/hard_gate_producers.go",
]
for _name in [
    "silent_failure_action_without_authorization_total",
    "silent_failure_action_with_incomplete_visibility_total",
    "silent_failure_destination_only_state_total",
    "silent_failure_cross_client_action_total",
    "silent_failure_cross_service_action_total",
    "silent_failure_cross_component_action_total",
    "silent_failure_cross_generation_action_total",
    "silent_failure_single_signal_auto_fallback_total",
    "silent_failure_non_independent_evidence_auto_fallback_total",
    "silent_failure_suppressor_ignored_total",
    "silent_failure_fast_parallel_false_positive_total",
    "silent_failure_recent_success_false_positive_total",
    "silent_failure_explicit_server_error_misclassified_total",
    "silent_failure_gso_mss_progress_mismatch_total",
    "silent_failure_ppe_visibility_violation_total",
    "silent_failure_unbounded_probe_total",
    "silent_failure_unbounded_rotation_total",
    "silent_failure_recursive_transport_fallback_total",
    "silent_failure_recovery_without_rollback_target_total",
    "silent_failure_control_regression_promoted_total",
    "silent_failure_false_positive_budget_ignored_total",
    "silent_failure_user_revert_not_rolled_back_total",
]:
    EVIDENCE_ARTIFACTS[_name] = list(_EVIDENCE_SPF)
_EVIDENCE_DDI = [
    "B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md",
    "artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md",
    "src/discovery/hard_gate_producers_test.go",
    "src/discovery/hard_gate_producers.go",
]
for _name in [
    "discovery_profile_without_context_validation_total",
    "discovery_profile_stale_without_revalidation_total",
    "discovery_profile_cross_wan_use_total",
    "discovery_profile_mutable_runtime_pointer_total",
    "discovery_profile_hint_without_provenance_total",
    "discovery_profile_hint_overrode_current_baseline_total",
    "discovery_profile_skipped_target_validation_total",
    "discovery_profile_disabled_exhaustive_fallback_total",
    "discovery_profile_direct_production_write_total",
    "discovery_profile_allowed_sni_direct_promotion_total",
    "discovery_profile_threshold_out_of_budget_total",
    "discovery_profile_capture_gate_bypass_total",
    "discovery_profile_cross_service_action_total",
    "discovery_profile_false_pass_total",
]:
    EVIDENCE_ARTIFACTS[_name] = list(_EVIDENCE_DDI)
_EVIDENCE_TGB = [
    "B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md",
    "artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md",
    "src/mtproto/hard_gate_producers_test.go",
    "src/mtproto/hard_gate_producers.go",
]
for _name in [
    "mtproto_bridge_zero_byte_handled_drop_total",
    "mtproto_bridge_fixed_5s_destructive_timeout_total",
    "mtproto_bridge_unbounded_pending_total",
    "mtproto_bridge_pending_per_client_limit_bypass_total",
    "mtproto_bridge_prefix_loss_total",
    "mtproto_bridge_prefix_duplicate_total",
    "mtproto_bridge_route_recursion_total",
    "mtproto_bridge_primary_failure_silent_drop_total",
    "mtproto_bridge_overflow_without_reason_total",
    "mtproto_bridge_shutdown_leak_total",
]:
    EVIDENCE_ARTIFACTS[_name] = list(_EVIDENCE_TGB)
_EVIDENCE_ABD = [
    "B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md",
    "artifacts/remediation/FB02_ABD_PRODUCERS.json",
    "src/detector/hard_gate_producers_test.go",
    "src/detector/hard_gate_producers.go",
]
for _name in [
    "detector_single_probe_confirmed_total",
    "detector_exception_string_only_confirmed_total",
    "detector_static_target_only_high_confidence_total",
    "detector_self_interference_total",
    "detector_native_path_unproven_total",
    "detector_capture_invalid_packet_verdict_total",
    "detector_control_failure_ignored_total",
    "detector_duplicate_evidence_confidence_increase_total",
    "detector_cross_component_evidence_merge_total",
    "detector_cross_generation_evidence_merge_total",
    "detector_unbounded_dynamic_scan_total",
    "detector_resource_budget_bypass_total",
    "detector_sensitive_export_total",
    "detector_host_dead_from_single_reference_failure_total",
    "detector_reference_path_unhealthy_used_total",
    "detector_reference_path_used_as_action_authorization_total",
    "detector_partial_run_profile_compiled_total",
    "detector_resume_cross_network_context_total",
    "detector_capacity_self_interference_total",
    "detector_dns_single_resolver_spoof_confirmed_total",
    "detector_dns_cdn_variance_misclassified_total",
    "detector_unverified_mitm_verdict_total",
    "detector_tls_availability_integrity_conflation_total",
    "detector_tls_fingerprint_unlabeled_total",
    "detector_quic_single_target_global_udp_verdict_total",
    "detector_quic_tcp_evidence_conflation_total",
    "detector_valid_application_error_dpi_total",
    "detector_head_only_available_verdict_total",
    "detector_partial_progress_discarded_total",
    "detector_small_object_classified_throttled_total",
    "detector_fixed_16kb_window_confirmed_without_profile_total",
    "detector_packet_threshold_reported_as_byte_threshold_total",
    "detector_byte_threshold_reported_as_packet_threshold_total",
    "detector_gso_skb_count_as_wire_packet_total",
    "detector_single_origin_l4_budget_confirmed_total",
    "detector_server_header_limit_dpi_total",
    "detector_retransmission_counted_as_progress_total",
    "detector_l4_threshold_without_controls_total",
    "blocking_profile_without_target_plan_total",
    "blocking_profile_without_network_context_total",
    "blocking_profile_without_provenance_total",
    "blocking_profile_mutated_after_compile_total",
    "blocking_profile_high_confidence_with_contradiction_total",
    "blocking_profile_direct_action_authorization_total",
    "blocking_profile_direct_production_write_total",
    "guided_search_skipped_baseline_total",
    "guided_search_disabled_full_fallback_total",
    "guided_search_profile_overrode_current_baseline_total",
    "guided_search_target_unvalidated_promotion_total",
    "guided_search_cross_service_action_total",
    "guided_search_white_sni_direct_promotion_total",
    "guided_search_false_savings_report_total",
    "guided_search_required_component_uncovered_total",
    "guided_search_coverage_ignored_control_regression_total",
    "guided_search_cross_service_set_cover_total",
    "guided_search_excluded_target_hidden_total",
    "guided_search_more_complex_candidate_preferred_without_gain_total",
    "guided_search_unverified_shortlist_promotion_total",
    "detector_monitor_request_direct_action_total",
    "detector_monitor_request_without_target_plan_overlay_total",
    "detector_monitor_request_without_network_context_total",
    "detector_monitor_request_without_config_generation_total",
    "detector_monitor_request_without_budget_token_total",
    "detector_monitor_request_expired_accepted_total",
    "detector_provisional_monitor_evidence_profile_compiled_total",
    "detector_passive_observation_counted_as_independent_probe_total",
    "detector_monitor_recurrence_counted_as_evidence_independence_total",
    "detector_client_resolution_replaced_silently_total",
    "detector_probe_without_resolution_binding_total",
    "detector_cname_terminal_ip_misattributed_total",
    "detector_multi_ip_partial_failure_hidden_total",
    "detector_stale_client_resolution_used_total",
    "detector_result_without_monitor_assessment_link_total",
    "detector_result_cross_network_context_total",
    "detector_result_cross_config_generation_total",
    "detector_result_cross_monitoring_epoch_total",
    "detector_incomplete_run_final_profile_total",
    "detector_monitor_result_action_authorization_total",
    "detector_monitor_result_delivery_identity_mismatch_total",
]:
    EVIDENCE_ARTIFACTS[_name] = list(_EVIDENCE_ABD)
_EVIDENCE_SP = [
    "B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md",
    "artifacts/remediation/FB02_SP_PRODUCERS.json",
    "src/serviceprofile/hard_gate_producers_test.go",
    "src/serviceprofile/hard_gate_producers.go",
]
for _name in [
    "profile_warp_recommended_without_ip_path_evidence_total",
    "profile_warp_recommended_from_destination_ip_only_total",
    "profile_warp_recommended_for_origin_dead_total",
    "profile_warp_recommended_with_unhealthy_controls_total",
    "profile_warp_recommendation_cross_service_total",
    "profile_warp_recommendation_stale_profile_total",
    "profile_warp_recommendation_without_causal_trace_gate_total",
    "profile_warp_enabled_without_target_canary_total",
    "profile_warp_test_token_reused_as_production_authorization_total",
    "profile_warp_recommendation_ignored_control_regression_total",
    "profile_warp_recommendation_hidden_fail_policy_total",
    "profile_nonru_suggested_without_geo_requirement_total",
    "profile_warp_camouflage_suggested_for_target_ip_block_total",
    "profile_warp_recommendation_cleanup_failure_total",
]:
    EVIDENCE_ARTIFACTS[_name] = list(_EVIDENCE_SP)
_EVIDENCE_MON = [
    "B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md",
    "artifacts/remediation/FB02_MON_PRODUCERS.json",
    "src/monitoring/hard_gate_producers_test.go",
    "src/monitoring/hard_gate_producers.go",
]
for _name in [
    "monitor_observation_direct_action_total",
    "monitor_provisional_profile_compiled_total",
    "monitor_passive_discovery_start_total",
    "monitor_passive_warp_enable_total",
    "monitor_fast_lane_action_total",
    "monitor_fast_lane_promoted_as_authoritative_total",
    "monitor_destination_only_deep_trigger_total",
    "monitor_cross_client_merge_total",
    "monitor_cross_service_merge_total",
    "monitor_cross_component_merge_total",
    "monitor_cross_wan_evidence_merge_total",
    "monitor_cross_generation_evidence_merge_total",
    "monitor_router_origin_as_forwarded_proof_total",
    "monitor_duplicate_evidence_independence_total",
    "monitor_temporal_persistence_without_time_separation_total",
    "monitor_success_suppressor_ignored_total",
    "monitor_recovered_subject_not_demoted_total",
    "monitor_expired_evidence_used_total",
    "monitor_decay_disabled_without_policy_total",
    "monitor_probe_without_resolution_binding_total",
    "monitor_client_dns_answer_replaced_silently_total",
    "monitor_cname_terminal_ip_misattributed_total",
    "monitor_multi_ip_partial_failure_hidden_total",
    "monitor_stale_resolution_used_as_exact_proof_total",
    "monitor_trigger_without_visibility_total",
    "monitor_trigger_without_budget_total",
    "monitor_trigger_during_global_wan_failure_total",
    "monitor_trigger_with_stale_source_heartbeat_total",
    "monitor_duplicate_concurrent_abd_run_total",
    "monitor_unbounded_target_intake_total",
    "monitor_unbounded_probe_parallelism_total",
    "monitor_self_interference_total",
    "monitor_reference_result_as_action_authorization_total",
    "monitor_abd_request_without_target_plan_total",
    "monitor_abd_partial_result_profile_ready_total",
    "monitor_abd_result_bypassed_ddi_total",
    "monitor_discovery_without_authoritative_profile_total",
    "monitor_discovery_skipped_mandatory_baseline_total",
    "monitor_recommendation_without_scope_total",
    "monitor_warp_recommendation_without_ip_path_evidence_total",
    "monitor_legacy_watchdog_direct_apply_total",
    "monitor_legacy_watchdog_created_unvalidated_set_total",
    "monitor_legacy_watchdog_overwrote_set_without_canary_total",
    "monitor_legacy_api_projection_mutation_total",
    "monitor_shadow_and_active_writer_overlap_total",
    "monitor_required_event_drop_hidden_total",
    "monitor_source_heartbeat_stale_auto_diagnose_total",
    "monitor_checkpoint_corruption_false_ready_total",
    "monitor_restart_reused_expired_lease_total",
    "monitor_sensitive_dns_history_export_total",
    "monitor_secret_trace_leak_total",
    "monitor_high_cardinality_metric_label_total",
]:
    EVIDENCE_ARTIFACTS[_name] = list(_EVIDENCE_MON)
_EVIDENCE_MONABD = [
    "artifacts/audit/hard_gates_audit.md",
    "artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md",
]
for _name in [
    "monitor_first_success_erased_address_failures_total",
    "monitor_http_hypothesis_from_tcp_tls_only_observer_total",
    "monitor_observer_unavailable_as_target_failure_total",
    "monitor_exact_endpoint_service_resolution_conflated_total",
    "monitor_observer_capability_unproven_total",
    "detector_first_success_erased_address_failures_total",
    "detector_multivantage_stage_mismatch_total",
    "detector_http_hypothesis_from_tcp_tls_only_observer_total",
    "detector_observer_unavailable_as_target_failure_total",
    "detector_exact_endpoint_service_resolution_conflated_total",
    "detector_observer_capability_unproven_total",
]:
    EVIDENCE_ARTIFACTS[_name] = list(_EVIDENCE_MONABD)

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
                    "reset_semantics": ("increment-only; window-delta == 0" if kind == "zero_tolerance_violation_counter"
                                        else ("increment-only; readiness input (window delta + owner state)" if kind == "current_generation_readiness_input"
                                              else "telemetry; not a blocker")),
                    "expiry_generation_binding": None,
                    "applicability": f"family:{family}",
                    "test_producer": TEST_PRODUCERS.get(name),
                    "mutation_test": MUTATION_TESTS.get(name),
                    "evidence_artifact": EVIDENCE_ARTIFACTS.get(name),
                }
                entries.append(entry)
        if entries:
            families[family] = entries
    # Extra canonical gates (not extractable from the addenda; see
    # EXTRA_GATES): added to the declared family and indexed, so --check
    # never flags them as orphans and regeneration never drops them.
    for name, entry in EXTRA_GATES.items():
        fam = entry["owner_family"]
        if name in index:
            print(f"WARN: extra gate {name!r} already owned by {index[name]}", file=sys.stderr)
            continue
        index[name] = fam
        e = dict(entry)
        # Verified extra gates follow the same commitment rule as the
        # addendum-extracted producers (verified_commit = REGISTER_VERIFIED_COMMIT).
        if e.get("producer_status") == "verified" and not e.get("verified_commit"):
            e["verified_commit"] = REGISTER_VERIFIED_COMMIT
        families.setdefault(fam, []).append(e)
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
                # Telemetry / readiness-input counters must not block promotion.
                if g.get("kind") in ("telemetry_counter", "current_generation_readiness_input") and g.get("promotion_blocker"):
                    errors.append(f"KIND: {gid!r} is {g.get('kind')!r} but blocks promotion")
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
