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
        "producer_status": "missing",
        "runtime_producer": None,
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
        "evidence_artifact": None,
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
REGISTER_VERIFIED_COMMIT = "fed07a5d"  # FB-02 SPF: 22 silent-path failure producers verified (2026-08-04); 67 applicable

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
        families.setdefault(fam, []).append(dict(entry))
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
