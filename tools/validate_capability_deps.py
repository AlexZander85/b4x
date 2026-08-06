#!/usr/bin/env python3
"""B4X FB-36: validate the canonical capability dependency graph.

Checks on specs/registries/capability_dependencies.yaml (run when the
registry changes; CI runs `--check`):
  - schema:      required fields present per capability;
  - duplicate:   no duplicate capability ids;
  - dependency:  every requires entry resolves to a registered capability
    (no orphan refs);
  - acyclic:      the dependency graph is acyclic (topological sort);
  - layer:        requires always carry a strictly smaller layer (monotone
    graph depth; parallel wave grouping stays consistent);
  - parallel:     a parallel capability may not appear later in the strict
    chain (its layer stays at the wave of its requires);
  - totals:       declared_total == computed_total == len(capabilities).

Usage: python tools/validate_capability_deps.py [--check]
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

REPO = Path(__file__).resolve().parent.parent
REGISTRY = REPO / "specs" / "registries" / "capability_dependencies.yaml"


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="CI mode: same checks, exit non-zero on any violation")
    args = ap.parse_args(argv)

    with REGISTRY.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    caps = data.get("capabilities") or []
    errors: list[str] = []

    # declared vs computed total
    declared = data.get("declared_total")
    computed = len(caps)
    if declared != computed:
        errors.append(f"declared_total={declared} != computed_total={computed}")

    by_id: dict[str, dict] = {}
    for c in caps:
        cid = c.get("id")
        if not cid:
            errors.append("capability without id")
            continue
        if cid in by_id:
            errors.append(f"duplicate capability id {cid}")
        by_id[cid] = c
        for field in ("name", "layer"):
            if field not in c:
                errors.append(f"{cid}: missing {field}")

    # --- requires resolve + layer monotonicity
    for cid, c in by_id.items():
        for dep in c.get("requires") or []:
            if dep not in by_id:
                errors.append(f"{cid}: requires unknown capability {dep}")
            elif by_id[dep].get("layer", 0) >= c.get("layer", 0):
                errors.append(
                    f"{cid}: requires {dep} with layer "
                    f"{by_id[dep].get('layer', 0)} >= own layer {c.get('layer', 0)}"
                )

    # --- acyclicity (Kahn topological sort)
    indeg = {cid: len(c.get("requires") or []) for cid, c in by_id.items()}
    adj = {cid: [] for cid in by_id}
    for cid, c in by_id.items():
        for dep in c.get("requires") or []:
            adj[dep].append(cid)
    queue = [cid for cid, d in indeg.items() if d == 0]
    order: list[str] = []
    while queue:
        n = queue.pop(0)
        order.append(n)
        for m in adj[n]:
            indeg[m] -= 1
            if indeg[m] == 0:
                queue.append(m)
    if len(order) != len(by_id):
        cyclic = [cid for cid, d in indeg.items() if d > 0]
        errors.append(f"cyclic dependency graph involving: {sorted(cyclic)}")

    # --- parallel capability layer consistency (optional capabilities
    # declare a parallel wave; they must not be placed below a strictly
    # ordered capability deeper than their requires)
    for cid, c in by_id.items():
        if c.get("parallel") and c.get("layer", 0) > 0:
            max_require_layer = max(
                (by_id[d].get("layer", 0) for d in (c.get("requires") or [])),
                default=-1,
            )
            if c.get("layer", 0) != max_require_layer + 1:
                errors.append(
                    f"{cid}: parallel capability layer must be exactly "
                    f"max(requires)+1 ({max_require_layer + 1}), got {c.get('layer', 0)}"
                )

    # --- normative ordering sanity: strict chain anchors must exist
    anchors = ["classifier", "visibility", "progress", "mon", "abd", "ddi",
               "canary", "warp", "service_profile"]
    for a in anchors:
        if a not in by_id:
            errors.append(f"normative chain anchor missing: {a}")

    if errors:
        for e in errors:
            print(f"ERROR: {e}")
        return 1
    if args.check:
        print(f"OK {REGISTRY.name}: {computed} capabilities, acyclic, "
              f"declared_total={declared}")
    return 0


if __name__ == "__main__":
    sys.exit(main())