#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FB-33 (b4x-yzt): Canonical Exact Source-Stage Registry generator.

Builds the single machine-readable source-stage registry
(specs/registries/source_stage_registry.yaml) that supersedes the manual
totals in B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md (§23.1/§45/§58,
FB-14 решения 6/7):

    criteria_total = count(valid canonical registry entries)

Each entry carries the normative schema (B4X_AUDIT_FIX_TASKS v2.md §FB-33):

    RequirementID, SourceDocument, SourceVersion, SourceSHA256, Section,
    Stage, Category, Dependencies, Suites, Gates, Verdicts, Applicability

Requirement ranges are declared per normative document section (verified
2026-08-05 against the documents listed in DOCUMENTS). The source SHA-256
is computed from the actual document file, so any edit of a normative
document without regenerating the registry fails --check (stale refs
detected; FB-14 решение 7: CI fail on duplicate/orphan/missing hash/stage/
dependency/verdict).

Usage:
  python tools/gen_source_stage_registry.py          # write yaml
  python tools/gen_source_stage_registry.py --check  # validate existing yaml
"""

import argparse
import hashlib
import os
import re
import sys
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_PATH = os.path.join(REPO_ROOT, "specs", "registries", "source_stage_registry.yaml")

SCHEMA_VERSION = "1.0"
GENERATED_AT = "2026-08-05"
STATUS = "canonical (FB-33, owner decision 2026-08-05; FB-14 решения 6/7)"

# ---------------------------------------------------------------------------
# Normative documents (all must exist; SHA-256 is computed at build time).
# ---------------------------------------------------------------------------

# name -> (version, category)
DOCUMENTS = {
    "B4_FORK_ARCHITECTURE_v2.4.md": ("2.4", "architecture"),
    "B4_FORK_PATCH_PLAN.md": ("2.3", "patch-plan"),
    "B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md": ("1.5", "implementation"),
    "B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md": ("1.5", "field-test"),
    "B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md": ("1.6", "service-profiles"),
    "B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md": ("1.2", "warp"),
    "B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md": ("1.0", "silent-path"),
    "B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md": ("1.0", "ppe"),
    "B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md": ("1.0", "csi"),
    "B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md": ("1.0", "rst-gso"),
    "B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md": ("1.2", "abd"),
    "B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md": ("1.0", "ddi-tgb"),
    "B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md": ("1.0", "mon"),
}

IV_DOC = "B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md"
PLAN_DOC = "B4_FORK_PATCH_PLAN.md"
ARCH_DOC = "B4_FORK_ARCHITECTURE_v2.4.md"
FT_DOC = "B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md"
SP_DOC = "B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md"
MON_DOC = "B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md"
ABD_DOC = "B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md"
DDI_DOC = "B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md"

# Principal-verdict family names (ReleaseScope families in gates.go; FB-34
# will attach alias/dependency expressions — empty now, never invented).
VERDICT_FAMILIES = {
    "CSI": "csi", "RST_GSO": "rst-gso", "PPE": "ppe", "SPF": "silent-path",
    "MON": "mon", "ABD": "abd", "DDI": "ddi", "TGB": "ddi-tgb",
    "WARP": "warp", "SP": "service-profiles", "FT": "field-test",
}

# ---------------------------------------------------------------------------
# Requirement ranges per document section.  Each entry:
#   (first_id, last_id, doc, section, stage, category, applicability)
# Ranges are closed (inclusive on both ends); single IDs use equal bounds.
# ---------------------------------------------------------------------------

def _seq(first, last):
    """Expand a range of requirement IDs (int suffix, optional letter prefix)."""
    m = re.match(r"^(.*?)(\d+)$", first)
    prefix, n0 = m.group(1), int(m.group(2))
    n1 = int(re.match(r"^.*?(\d+)$", last).group(1))
    return ["%s%d" % (prefix, n) for n in range(n0, n1 + 1)]


def _letters(first, last):
    """Expand a range of letter-suffixed IDs (FT-A..FT-L, WARP-C1..C10)."""
    if re.match(r"^.*\d$", first):
        return _seq(first, last)
    m = re.match(r"^(.*?)([A-Z]+)$", first)
    prefix, a = m.group(1), m.group(2)
    b = re.match(r"^.*?([A-Z]+)$", last).group(1)
    out = []
    cur = a
    while True:
        out.append("%s%s" % (prefix, cur))
        if cur == b:
            break
        # next letter sequence (A..Z, AA..AB)
        carry = True
        chars = list(cur)
        i = len(chars) - 1
        while carry and i >= 0:
            if chars[i] == "Z":
                chars[i] = "A"
                carry = i == 0
                i -= 1
            else:
                chars[i] = chr(ord(chars[i]) + 1)
                carry = False
        if carry:
            chars = ["A"] * (len(cur) + 1)
        cur = "".join(chars)
    return out


def _with_verdicts(ids, verdict):
    return [(i, verdict) for i in ids]


# companion ranges from IV §41 (verified 2026-08-05)
COMPANION_RANGES = [
    # (ids, doc, section, stage, category, applicability)
    (_seq("CSI-1", "CSI-10"), IV_DOC, "41.1", "companion", "csi", "family:csi"),
    (_seq("H1", "H10"), IV_DOC, "41.2", "companion", "rst-gso", "family:rst_gso"),
    (_seq("PPE-1", "PPE-8"), IV_DOC, "41.3", "companion", "ppe", "family:ppe"),
    (_letters("FT-A", "FT-L"), IV_DOC, "41.4", "companion", "field-test", "family:field_test"),
    (_seq("SP-1", "SP-15"), IV_DOC, "41.5", "companion", "service-profiles", "family:sp"),
    (_seq("WARP-1", "WARP-12"), IV_DOC, "41.6", "companion", "warp", "family:warp"),
    (_seq("WARP-C1", "WARP-C10"), IV_DOC, "41.6", "companion", "warp", "family:warp_camouflage"),
    (_letters("FT-M", "FT-Q"), IV_DOC, "41.7", "companion", "field-test", "family:field_test"),
    (_letters("FT-AC", "FT-AE"), IV_DOC, "41.7", "companion", "field-test", "family:field_test"),
    (_seq("SP-16", "SP-19"), IV_DOC, "41.8", "companion", "service-profiles", "family:sp"),
    (_seq("SPF-1", "SPF-10"), IV_DOC, "41.9", "companion", "silent-path", "family:spf"),
    (_letters("FT-R", "FT-V"), IV_DOC, "41.9", "companion", "field-test", "family:field_test"),
    (_seq("SP-20", "SP-23"), IV_DOC, "41.9", "companion", "service-profiles", "family:sp"),
    # FT v1.5 field additions (FT-W..FT-AB live in the FT addendum; §54 maps
    # ABD/DDI/TGB source stages onto them)
    (_letters("FT-W", "FT-AB"), FT_DOC, "field-additions", "field-test", "field-test", "family:field_test"),
    # SP v1.6 recommendation stages (FB-32; §54 profile coverage)
    (_seq("SP-24", "SP-29"), SP_DOC, "recommendation", "service-profiles", "service-profiles", "family:sp"),
    (_seq("SP-30", "SP-32"), SP_DOC, "recommendation", "service-profiles", "service-profiles", "family:sp"),
    # MON addendum (FB-28 IV-18 registration; §84-92)
    (_seq("MON-1", "MON-12"), MON_DOC, "84-92", "monitoring", "mon", "family:mon"),
    (_letters("FT-MON-A", "FT-MON-J"), MON_DOC, "84-92", "monitoring", "mon", "family:mon"),
    # ABD/DDI/TGB source stages (ABD/DDI addenda; §58 registry subset)
    (_seq("ABD-1", "ABD-12"), ABD_DOC, "39-42", "source-stage", "abd", "family:abd"),
    (_seq("DDI-1", "DDI-10"), DDI_DOC, "discovery", "source-stage", "ddi", "family:ddi"),
    (_seq("TGB-1", "TGB-10"), DDI_DOC, "bridge", "source-stage", "ddi-tgb", "family:tgb"),
]

# implementation stages of the addendum itself (IV §44/§55; umbrella suites)
IV_RANGES = [
    (_seq("IV-1", "IV-13"), IV_DOC, "44", "implementation", "implementation", "all"),
    (_seq("IV-14", "IV-17"), IV_DOC, "55", "implementation", "implementation", "all"),
]

# Patch Plan stages (B4_FORK_PATCH_PLAN.md, Stage 1..36)
PLAN_RANGES = [
    (_seq("PLAN-S1", "PLAN-S36"), PLAN_DOC, "stage", "patch-plan", "patch-plan", "all"),
]

# ARCH v2.4 clauses/invariants/hold-replay (verified against fb18b.go
# FB18BEntries; ARCH-106..145 clauses, 5.1..5.17 invariants, HR-42..45)
ARCH_RANGES = [
    (_seq("ARCH-106", "ARCH-145"), ARCH_DOC, "106-145", "architecture", "architecture", "all"),
    (["INV-5.%d" % n for n in range(1, 18)], ARCH_DOC, "5.1-5.17", "architecture", "architecture", "all"),
    (_seq("HR-42", "HR-45"), ARCH_DOC, "42-45", "architecture", "architecture", "all"),
]

# Suites/dependencies from §54 companion coverage matrix (verified 2026-08-05)
SUITES_BY_PREFIX = {
    "ABD-1": ["IV-14"], "ABD-2": ["IV-14"], "ABD-3": ["IV-14"],
    "ABD-4": ["IV-14"], "ABD-5": ["IV-14"], "ABD-6": ["IV-14"],
    "ABD-7": ["IV-14"], "ABD-8": ["IV-14"],
    "ABD-9": ["IV-14"], "ABD-10": ["IV-14"],
    "ABD-11": ["IV-15"], "ABD-12": ["IV-15"],
    "DDI-1": ["IV-15"], "DDI-2": ["IV-15"], "DDI-3": ["IV-15"],
    "DDI-4": ["IV-15"], "DDI-5": ["IV-15"], "DDI-6": ["IV-15"],
    "DDI-7": ["IV-15"], "DDI-8": ["IV-15"], "DDI-9": ["IV-15"], "DDI-10": ["IV-15"],
    "TGB-1": ["IV-16"], "TGB-2": ["IV-16"], "TGB-3": ["IV-16"],
    "TGB-4": ["IV-16"], "TGB-5": ["IV-16"], "TGB-6": ["IV-16"],
    "TGB-7": ["IV-16"], "TGB-8": ["IV-16"], "TGB-9": ["IV-16"], "TGB-10": ["IV-16"],
    "WARP-1": ["IV-6", "IV-17"], "WARP-2": ["IV-6", "IV-17"],
    "WARP-3": ["IV-6", "IV-17"], "WARP-4": ["IV-6", "IV-17"],
    "WARP-5": ["IV-6", "IV-17"], "WARP-6": ["IV-6", "IV-17"],
    "WARP-7": ["IV-6", "IV-17"], "WARP-8": ["IV-6", "IV-17"],
    "WARP-9": ["IV-8", "IV-17"], "WARP-10": ["IV-8", "IV-17"],
    "WARP-C1": ["IV-8", "IV-12", "IV-17"], "WARP-C2": ["IV-8", "IV-12", "IV-17"],
    "WARP-C3": ["IV-8", "IV-12", "IV-17"], "WARP-C4": ["IV-8", "IV-12", "IV-17"],
    "WARP-C5": ["IV-8", "IV-12", "IV-17"], "WARP-C6": ["IV-8", "IV-12", "IV-17"],
    "WARP-C7": ["IV-8", "IV-12", "IV-17"], "WARP-C8": ["IV-8", "IV-12", "IV-17"],
    "WARP-C9": ["IV-8", "IV-12", "IV-17"], "WARP-C10": ["IV-8", "IV-12", "IV-17"],
}

DEPS_BY_PREFIX = {
    "ABD-1": ["FT-W", "SP-24", "SP-25"], "ABD-2": ["FT-W", "SP-24", "SP-25"],
    "ABD-3": ["FT-W", "SP-24", "SP-25"],
    "ABD-4": ["FT-X", "FT-Y", "SP-25", "SP-26"], "ABD-5": ["FT-X", "FT-Y", "SP-25", "SP-26"],
    "ABD-6": ["FT-X", "FT-Y", "SP-25", "SP-26"], "ABD-7": ["FT-X", "FT-Y", "SP-25", "SP-26"],
    "ABD-8": ["FT-X", "FT-Y", "SP-25", "SP-26"],
    "ABD-9": ["FT-Y", "SP-26"], "ABD-10": ["FT-Y", "SP-26"],
    "ABD-11": ["FT-Z", "FT-AA", "FT-AB", "SP-27", "SP-28", "SP-29"],
    "ABD-12": ["FT-Z", "FT-AA", "FT-AB", "SP-27", "SP-28", "SP-29"],
    "DDI-1": ["FT-Z", "SP-27"], "DDI-2": ["FT-Z", "SP-27"], "DDI-3": ["FT-Z", "SP-27"],
    "DDI-4": ["FT-Z", "SP-27"], "DDI-5": ["FT-Z", "SP-27"],
    "DDI-6": ["FT-Z", "FT-AA", "FT-AB", "SP-27", "SP-28", "SP-29"],
    "DDI-7": ["FT-Z", "FT-AA", "FT-AB", "SP-27", "SP-28", "SP-29"],
    "DDI-8": ["FT-Z", "FT-AA", "FT-AB", "SP-27", "SP-28", "SP-29"],
    "DDI-9": ["FT-Z", "FT-AA", "FT-AB", "SP-27", "SP-28", "SP-29"],
    "DDI-10": ["FT-Z", "FT-AA", "FT-AB", "SP-27", "SP-28", "SP-29"],
    "TGB-1": ["FT-AA", "SP-28"], "TGB-2": ["FT-AA", "SP-28"], "TGB-3": ["FT-AA", "SP-28"],
    "TGB-4": ["FT-AA", "SP-28"], "TGB-5": ["FT-AA", "SP-28"], "TGB-6": ["FT-AA", "SP-28"],
    "TGB-7": ["FT-AA", "FT-AB", "SP-28", "SP-29"], "TGB-8": ["FT-AA", "FT-AB", "SP-28", "SP-29"],
    "TGB-9": ["FT-AA", "FT-AB", "SP-28", "SP-29"], "TGB-10": ["FT-AA", "FT-AB", "SP-28", "SP-29"],
    "WARP-1": ["FT-M", "FT-AC", "FT-AD", "SP-16", "SP-17", "SP-18", "SP-19"],
    "WARP-2": ["FT-M", "FT-AC", "FT-AD", "SP-16", "SP-17", "SP-18", "SP-19"],
    "WARP-3": ["FT-M", "FT-AC", "FT-AD", "SP-16", "SP-17", "SP-18", "SP-19"],
    "WARP-4": ["FT-M", "FT-AC", "FT-AD", "SP-16", "SP-17", "SP-18", "SP-19"],
    "WARP-5": ["FT-M", "FT-AC", "FT-AD", "SP-16", "SP-17", "SP-18", "SP-19"],
    "WARP-6": ["FT-M", "FT-AC", "FT-AD", "SP-16", "SP-17", "SP-18", "SP-19"],
    "WARP-7": ["FT-M", "FT-AC", "FT-AD", "SP-16", "SP-17", "SP-18", "SP-19"],
    "WARP-8": ["FT-M", "FT-AC", "FT-AD", "SP-16", "SP-17", "SP-18", "SP-19"],
    "WARP-9": ["FT-O", "FT-AE", "SP-18", "SP-19"],
    "WARP-10": ["FT-O", "FT-AE", "SP-18", "SP-19"],
    "WARP-C1": ["FT-N", "FT-O", "FT-P", "FT-Q", "FT-AC", "FT-AD", "FT-AE", "SP-18", "SP-19"],
    "WARP-C2": ["FT-N", "FT-O", "FT-P", "FT-Q", "FT-AC", "FT-AD", "FT-AE", "SP-18", "SP-19"],
    "WARP-C3": ["FT-N", "FT-O", "FT-P", "FT-Q", "FT-AC", "FT-AD", "FT-AE", "SP-18", "SP-19"],
    "WARP-C4": ["FT-N", "FT-O", "FT-P", "FT-Q", "FT-AC", "FT-AD", "FT-AE", "SP-18", "SP-19"],
    "WARP-C5": ["FT-N", "FT-O", "FT-P", "FT-Q", "FT-AC", "FT-AD", "FT-AE", "SP-18", "SP-19"],
    "WARP-C6": ["FT-N", "FT-O", "FT-P", "FT-Q", "FT-AC", "FT-AD", "FT-AE", "SP-18", "SP-19"],
    "WARP-C7": ["FT-N", "FT-O", "FT-P", "FT-Q", "FT-AC", "FT-AD", "FT-AE", "SP-18", "SP-19"],
    "WARP-C8": ["FT-N", "FT-O", "FT-P", "FT-Q", "FT-AC", "FT-AD", "FT-AE", "SP-18", "SP-19"],
    "WARP-C9": ["FT-N", "FT-O", "FT-P", "FT-Q", "FT-AC", "FT-AD", "FT-AE", "SP-18", "SP-19"],
    "WARP-C10": ["FT-N", "FT-O", "FT-P", "FT-Q", "FT-AC", "FT-AD", "FT-AE", "SP-18", "SP-19"],
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _doc_hash(name):
    return sha256_of(os.path.join(REPO_ROOT, name))


def _verdict_for(rid):
    """Principal-verdict family for requirement IDs that carry one."""
    if rid.startswith("CSI-"):
        return ["CSI"]
    if rid.startswith("H"):
        return ["RST_GSO"]
    if rid.startswith("PPE-"):
        return ["PPE"]
    if rid.startswith("SPF-"):
        return ["SPF"]
    if rid.startswith("MON-") or rid.startswith("FT-MON-"):
        return ["MON"]
    if rid.startswith("ABD-"):
        return ["ABD"]
    if rid.startswith("DDI-"):
        return ["DDI"]
    if rid.startswith("TGB-"):
        return ["TGB"]
    if rid.startswith("WARP-"):
        return ["WARP"]
    if rid.startswith("SP-"):
        return ["SP"]
    if rid.startswith("FT-"):
        return ["FT"]
    return []


def build_entries():
    entries = []
    seen = set()

    def add(rid, doc, section, stage, category, applicability, verdicts=None, suites=None, deps=None):
        if rid in seen:
            raise SystemExit("ERROR: duplicate requirement id %s" % rid)
        seen.add(rid)
        entries.append({
            "requirement_id": rid,
            "source_document": doc,
            "source_version": DOCUMENTS[doc][0],
            "source_sha256": _doc_hash(doc),
            "section": section,
            "stage": stage,
            "category": category,
            "dependencies": deps or [],
            "suites": suites or [],
            "gates": [],
            "verdicts": verdicts or [],
            "applicability": applicability,
        })

    for ids, doc, section, stage, category, appl in COMPANION_RANGES:
        for rid in ids:
            v = _verdict_for(rid)
            add(rid, doc, section, stage, category, appl,
                verdicts=v, suites=SUITES_BY_PREFIX.get(rid, []),
                deps=DEPS_BY_PREFIX.get(rid, []))
    for ids, doc, section, stage, category, appl in IV_RANGES:
        for rid in ids:
            add(rid, doc, section, stage, category, appl)
    for ids, doc, section, stage, category, appl in PLAN_RANGES:
        for rid in ids:
            add(rid, doc, section, stage, category, appl)
    for ids, doc, section, stage, category, appl in ARCH_RANGES:
        for rid in ids:
            add(rid, doc, section, stage, category, appl)

    return entries


# ---------------------------------------------------------------------------
# Validation (shared by build and --check)
# ---------------------------------------------------------------------------

def validate(entries, documents, strict_docs=True, doc_hashes=None):
    """Return list of error strings; empty list == valid.

    documents: list of document names.  doc_hashes: optional map name ->
    (version, category, sha256) as read from an existing registry file; when
    given, the on-disk SHA-256 of every document is compared against it so a
    stale registry (normative document edited without regeneration) fails
    --check (FB-14 решение 7: stale refs detected).
    """
    errors = []

    if doc_hashes:
        for name, (version, category, sha) in doc_hashes.items():
            path = os.path.join(REPO_ROOT, name)
            if not os.path.exists(path):
                errors.append("missing normative document %s" % name)
                continue
            if sha256_of(path) != sha:
                errors.append("stale document hash %s (document edited; regenerate registry)" % name)

    ids = [e["requirement_id"] for e in entries]
    if len(ids) != len(set(ids)):
        dup = {i for i in ids if ids.count(i) > 1}
        errors.append("duplicate requirement_id: %s" % sorted(dup))

    docset = set(documents)
    for e in entries:
        if e["source_document"] not in docset:
            errors.append("orphan source_document %s (req %s)" % (e["source_document"], e["requirement_id"]))
        if not e["source_version"]:
            errors.append("missing source_version (req %s)" % e["requirement_id"])
        if len(e["source_sha256"]) != 64:
            errors.append("missing source_sha256 (req %s)" % e["requirement_id"])
        if not e["section"]:
            errors.append("missing section (req %s)" % e["requirement_id"])
        if not e["stage"]:
            errors.append("missing stage (req %s)" % e["requirement_id"])
        if not e["category"]:
            errors.append("missing category (req %s)" % e["requirement_id"])
        if not e["applicability"]:
            errors.append("missing applicability (req %s)" % e["requirement_id"])

    known_verdicts = set(VERDICT_FAMILIES)
    for e in entries:
        for v in e.get("verdicts", []):
            if v not in known_verdicts:
                errors.append("unknown verdict %s (req %s)" % (v, e["requirement_id"]))
        for d in e.get("dependencies", []):
            if d not in ids:
                errors.append("missing dependency %s (req %s)" % (d, e["requirement_id"]))
        for s in e.get("suites", []):
            if s not in ids:
                errors.append("missing suite %s (req %s)" % (s, e["requirement_id"]))

    if strict_docs:
        for name in documents:
            if not os.path.exists(os.path.join(REPO_ROOT, name)):
                errors.append("missing normative document %s" % name)

    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="validate existing registry")
    args = ap.parse_args()

    if args.check:
        with open(REGISTRY_PATH, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        entries = doc["requirements"]
        declared = doc.get("declared_total")
        computed = len(entries)
        doc_names = [d["name"] for d in doc["documents"]]
        doc_hashes = {d["name"]: (d["version"], d["category"], d["sha256"]) for d in doc["documents"]}
        errors = validate(entries, doc_names, strict_docs=False, doc_hashes=doc_hashes)
        if declared is not None and declared != computed:
            errors.append("declared_total %d != computed_total %d" % (declared, computed))
        if errors:
            for e in errors:
                print("ERROR: " + e, file=sys.stderr)
            print("FAIL: source-stage registry invalid (%d errors)" % len(errors), file=sys.stderr)
            return 1
        print("OK: source-stage registry %d entries, %d documents, declared_total == computed_total == %d"
              % (computed, len(doc["documents"]), declared))
        return 0

    entries = build_entries()
    errors = validate(entries, DOCUMENTS)
    if errors:
        for e in errors:
            print("ERROR: " + e, file=sys.stderr)
        return 1

    docs_block = []
    for name, (version, category) in DOCUMENTS.items():
        docs_block.append({"name": name, "version": version, "category": category, "sha256": _doc_hash(name)})

    out = {
        "schema_version": SCHEMA_VERSION,
        "generator": "tools/gen_source_stage_registry.py",
        "generated_at": GENERATED_AT,
        "status": STATUS,
        "declared_total": len(entries),
        "computed_total": len(entries),
        "documents": docs_block,
        "requirements": entries,
    }
    os.makedirs(os.path.dirname(REGISTRY_PATH), exist_ok=True)
    with open(REGISTRY_PATH, "w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump(out, f, sort_keys=False, allow_unicode=True, width=1000)
    fams = {}
    for e in entries:
        fams.setdefault(e["category"], 0)
        fams[e["category"]] += 1
    print("WROTE %s: %d requirements, %d documents" % (REGISTRY_PATH, len(entries), len(docs_block)))
    for cat, n in sorted(fams.items()):
        print("  %-20s %d" % (cat, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
