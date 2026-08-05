#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FB-34 (b4x-xgc): Principal verdict registry validator.

Validates the canonical principal verdict registry
(specs/registries/principal_verdicts.yaml) that unifies ARCH §142 principal
verdicts, IV §52/§52.1 release and blocked verdicts, §83 behavioral
fingerprinting / constrained synthesis verdicts and §88 adaptive DNS
verdicts into a single machine-readable source of truth with alias mapping.

FB-34 acceptance criteria covered here (CI fail on any violation):

  * duplicate canonical names / aliases / alias-canonical collisions
  * empty owner_stage / dependency_expression
  * dependency references to unknown canonical names
  * cyclic dependency graph (aggregation must follow the ARCH graph)
  * blocked_variants referencing entries that are not kind=blocked
  * gate references (family:xxx) that do not exist in hard_gates.yaml
  * source_stage_category references that do not exist in
    source_stage_registry.yaml
  * missing expiry/invalidation rules (stale/missing-evidence invalidation)
  * declared_total mismatch

Usage:
  python tools/validate_principal_verdicts.py --check   # validate registry
  python tools/validate_principal_verdicts.py           # same (default)
"""

import argparse
import os
import sys

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_PATH = os.path.join(REPO_ROOT, "specs", "registries", "principal_verdicts.yaml")
HARD_GATES_PATH = os.path.join(REPO_ROOT, "specs", "registries", "hard_gates.yaml")
SOURCE_STAGE_PATH = os.path.join(REPO_ROOT, "specs", "registries", "source_stage_registry.yaml")

ALLOWED_KINDS = {"ready", "blocked"}
# Invalidation rule required on every entry (stale/missing-evidence rule).
REQUIRED_EXPIRY = "evidence-generation-bound"


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def known_gate_families():
    doc = load_yaml(HARD_GATES_PATH)
    fams = set()
    for fam, gates in (doc.get("families") or {}).items():
        fams.add(fam)
    for g in _iter_flat_gates(doc.get("families") or {}):
        for ref in g.get("applicability") or []:
            if ref.startswith("family:"):
                fams.add(ref[len("family:"):])
        for ref in g.get("owner_family") or []:
            if isinstance(ref, str) and ref:
                fams.add(ref)
    return fams


def _iter_flat_gates(families):
    for fam, gates in families.items():
        if isinstance(gates, list):
            for g in gates:
                if isinstance(g, dict):
                    yield g
        elif isinstance(gates, dict):
            for g in gates.values():
                if isinstance(g, dict):
                    yield g


def known_stage_categories():
    doc = load_yaml(SOURCE_STAGE_PATH)
    cats = set()
    for r in doc.get("requirements", []):
        c = r.get("category")
        if c:
            cats.add(c)
    return cats


def validate(registry):
    """Return list of error strings; empty list == valid."""
    errors = []
    verdicts = registry.get("verdicts", [])
    declared = registry.get("declared_total")
    computed = len(verdicts)
    if declared is not None and declared != computed:
        errors.append("declared_total %d != computed_total %d" % (declared, computed))

    canon = [v.get("canonical") for v in verdicts]
    if len(canon) != len(set(canon)):
        dup = {c for c in canon if canon.count(c) > 1}
        errors.append("duplicate canonical: %s" % sorted(dup))

    all_names = set(canon)
    seen_aliases = set()
    for v in verdicts:
        name = v.get("canonical", "<missing>")
        if not v.get("canonical"):
            errors.append("missing canonical")
        if not v.get("kind"):
            errors.append("missing kind (%s)" % name)
        elif v["kind"] not in ALLOWED_KINDS:
            errors.append("unknown kind %s (%s)" % (v["kind"], name))
        if not v.get("owner_family"):
            errors.append("missing owner_family (%s)" % name)
        if not v.get("source_doc"):
            errors.append("missing source_doc (%s)" % name)
        if not v.get("source_section"):
            errors.append("missing source_section (%s)" % name)
        if not v.get("dependency_expression"):
            errors.append("missing dependency_expression (%s)" % name)
        if not v.get("expiry"):
            errors.append("missing expiry (invalidation rules) (%s)" % name)
        elif REQUIRED_EXPIRY not in v["expiry"]:
            errors.append("expiry must include %r (%s)" % (REQUIRED_EXPIRY, name))

        for a in v.get("aliases", []):
            if not a:
                errors.append("empty alias (%s)" % name)
            if a in all_names:
                errors.append("alias collides with canonical name %s (%s)" % (a, name))
            if a in seen_aliases:
                errors.append("duplicate alias %s (%s)" % (a, name))
            seen_aliases.add(a)

        for d in v.get("dependencies", []):
            if d not in all_names:
                errors.append("unknown dependency %s (%s)" % (d, name))
        for b in v.get("blocked_variants", []):
            if b not in all_names:
                errors.append("unknown blocked_variant %s (%s)" % (b, name))
        for g in v.get("required_gates", []):
            if not g.startswith("family:"):
                errors.append("required_gates must use family:<name> form, got %r (%s)" % (g, name))

        cat = v.get("source_stage_category")
        if cat:
            known = known_stage_categories()
            if cat not in known:
                errors.append("unknown source_stage_category %s (%s)" % (cat, name))

        for e in v.get("required_target_evidence", []):
            if not e:
                errors.append("empty required_target_evidence entry (%s)" % name)

    # blocked_variants must reference kind=blocked entries
    by_name = {v["canonical"]: v for v in verdicts if v.get("canonical")}
    for v in verdicts:
        name = v["canonical"]
        for b in v.get("blocked_variants", []):
            tgt = by_name.get(b)
            if tgt and tgt.get("kind") != "blocked":
                errors.append("blocked_variant %s does not reference kind=blocked entry (%s)" % (b, name))

    # dependency graph must be acyclic (ARCH graph aggregation)
    graph = {v["canonical"]: v.get("dependencies", []) for v in verdicts if v.get("canonical")}
    cycle = _find_cycle(graph)
    if cycle:
        errors.append("cyclic dependency graph: %s" % " -> ".join(cycle + [cycle[0]]))

    # gate family references must exist in hard_gates.yaml
    fams = known_gate_families()
    for v in verdicts:
        name = v["canonical"]
        for g in v.get("required_gates", []):
            fam = g[len("family:"):]
            if fam not in fams:
                errors.append("unknown gate family %r (%s)" % (fam, name))

    # normative documents must exist
    for v in verdicts:
        name = v["canonical"]
        doc = v.get("source_doc")
        if doc and not os.path.exists(os.path.join(REPO_ROOT, doc)):
            errors.append("missing normative document %s (%s)" % (doc, name))

    return errors


def _find_cycle(graph):
    """Return a cycle as a list of nodes, or None if the graph is acyclic."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in graph}
    stack = []

    def dfs(n):
        color[n] = GRAY
        stack.append(n)
        for m in graph.get(n, []):
            if color.get(m, BLACK) == GRAY:
                # found cycle: from m to end of stack
                idx = stack.index(m)
                return stack[idx:] + [m]
            if color.get(m, BLACK) == WHITE:
                r = dfs(m)
                if r:
                    return r
        stack.pop()
        color[n] = BLACK
        return None

    for n in graph:
        if color[n] == WHITE:
            r = dfs(n)
            if r:
                return r
    return None


def main():
    ap = argparse.ArgumentParser(description="Validate the principal verdict registry (FB-34)")
    ap.add_argument("--check", action="store_true", help="validate existing registry")
    args = ap.parse_args()
    _ = args

    if not os.path.exists(REGISTRY_PATH):
        print("FAIL: registry not found: %s" % REGISTRY_PATH, file=sys.stderr)
        return 1

    registry = load_yaml(REGISTRY_PATH)
    errors = validate(registry)
    computed = len(registry.get("verdicts", []))
    declared = registry.get("declared_total")
    if errors:
        for e in errors:
            print("ERROR: " + e, file=sys.stderr)
        print("FAIL: principal verdict registry invalid (%d errors)" % len(errors), file=sys.stderr)
        return 1
    print("OK: principal verdict registry %d verdicts, declared_total == computed_total == %d"
          % (computed, declared))
    return 0


if __name__ == "__main__":
    sys.exit(main())
