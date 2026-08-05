#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FB-31 (b4x-cka): Causal eligibility matrix validator.

Validates the canonical causal eligibility matrix
(specs/registries/causal_eligibility_matrix.yaml) that maps every failure
family (hypothesis/evidence family) to its eligible/forbidden candidate
families, mandatory narrower families, prerequisites, controls, target
validation and scoped transport authorization rules.

FB-31 acceptance criteria covered here (CI fail on any violation):

  * declared_total mismatch
  * duplicate failure families / candidate families
  * eligible/forbidden/mandatory references to unknown candidate families
  * forbidden candidate families listed as eligible (never selectable)
  * shadow candidate families listed as eligible (probe-only)
  * forbidden/kind=forbidden candidate family in any eligible list
  * transport_authorization not in {none, scoped-eligible-to-test}
  * scoped-eligible-to-test without required_evidence_authority
  * transport candidate families (WARP/SOCKS/TUN) eligible only with
    scoped-eligible-to-test and required evidence authority >=
    authoritative-abd (FB-31: provisional hint never authorizes transport;
    broad WARP escalation by DNS-only/QUIC-only/single timeout blocked)
  * required_evidence_authority not in FB-30 authority levels
  * missing normative source document
  * empty required fields (title/source_doc/source_section)

Usage:
  python tools/validate_causal_matrix.py --check   # validate registry
  python tools/validate_causal_matrix.py           # same (default)
"""

import argparse
import os
import sys

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_PATH = os.path.join(REPO_ROOT, "specs", "registries", "causal_eligibility_matrix.yaml")

# FB-30 evidence authority levels, weakest first. Only authority at or above
# authoritative-abd may authorize scoped transport.
AUTHORITY_LEVELS = ["passive-monitoring", "provisional-fast", "authoritative-abd", "android-canary"]
MIN_TRANSPORT_AUTHORITY = "authoritative-abd"
TRANSPORT_MODES = {"none", "scoped-eligible-to-test"}


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def validate(registry):
    """Return list of error strings; empty list == valid."""
    errors = []
    fams = registry.get("failure_families", [])
    cands = registry.get("candidate_families", [])
    declared = registry.get("declared_total")
    computed = len(fams)
    if declared is not None and declared != computed:
        errors.append("declared_total %d != computed_total %d" % (declared, computed))

    by_family = {}
    for f in fams:
        name = f.get("family", "<missing>")
        if not f.get("family"):
            errors.append("missing failure family name")
        elif name in by_family:
            errors.append("duplicate failure family %s" % name)
        by_family[name] = f
        if not f.get("title"):
            errors.append("missing title (%s)" % name)
        if not f.get("source_doc"):
            errors.append("missing source_doc (%s)" % name)
        elif not os.path.exists(os.path.join(REPO_ROOT, f["source_doc"])):
            errors.append("missing normative document %s (%s)" % (f["source_doc"], name))
        if not f.get("source_section"):
            errors.append("missing source_section (%s)" % name)

    cand_by_name = {}
    for c in cands:
        cname = c.get("family", "<missing>")
        if not c.get("family"):
            errors.append("missing candidate family name")
        elif cname in cand_by_name:
            errors.append("duplicate candidate family %s" % cname)
        cand_by_name[cname] = c
        if c.get("kind") not in {"eligible", "shadow", "forbidden"}:
            errors.append("unknown candidate family kind %r (%s)" % (c.get("kind"), cname))

    for f in fams:
        name = f["family"]
        eligible = f.get("eligible_candidate_families", [])
        forbidden = f.get("forbidden_candidate_families", [])
        mandatory = f.get("mandatory_narrower_families", [])
        shadow = f.get("shadow_candidate_families", [])
        for c in eligible + forbidden + mandatory + shadow:
            if c not in cand_by_name:
                errors.append("unknown candidate family %s (%s)" % (c, name))
        for c in eligible:
            if c in forbidden:
                errors.append("candidate family %s both eligible and forbidden (%s)" % (c, name))
            if c in cand_by_name and cand_by_name[c].get("kind") in {"forbidden", "shadow"}:
                errors.append("candidate family %s has kind %s but is eligible (%s)"
                              % (c, cand_by_name[c].get("kind"), name))
        for c in shadow:
            if c in cand_by_name and cand_by_name[c].get("kind") != "shadow":
                errors.append("candidate family %s has kind %s but is shadow (%s)"
                              % (c, cand_by_name[c].get("kind"), name))
        for c in mandatory:
            if c not in eligible:
                errors.append("mandatory narrower family %s is not eligible (%s)" % (c, name))

        mode = f.get("transport_authorization")
        if mode not in TRANSPORT_MODES:
            errors.append("unknown transport_authorization %r (%s)" % (mode, name))
            continue
        authority = f.get("required_evidence_authority") or ""
        if mode == "scoped-eligible-to-test":
            if authority not in AUTHORITY_LEVELS:
                errors.append("scoped-eligible-to-test requires a valid evidence authority, got %r (%s)"
                              % (authority, name))
            elif AUTHORITY_LEVELS.index(authority) < AUTHORITY_LEVELS.index(MIN_TRANSPORT_AUTHORITY):
                errors.append("scoped transport requires evidence authority >= %s, got %s (%s)"
                              % (MIN_TRANSPORT_AUTHORITY, authority, name))
        elif authority:
            errors.append("transport_authorization none must not set required_evidence_authority (%s)" % name)

        # WARP/SOCKS/TUN (transport candidate families) may be eligible only
        # with scoped-eligible-to-test (FB-31 acceptance: broad WARP
        # escalation by DNS-only/QUIC-only/single timeout blocked).
        if "scoped_transport" in eligible and mode != "scoped-eligible-to-test":
            errors.append("scoped_transport eligible but transport_authorization is %r (%s)"
                          % (mode, name))

        for h in f.get("hypotheses", []):
            if not h:
                errors.append("empty hypothesis entry (%s)" % name)
    return errors


def main():
    ap = argparse.ArgumentParser(description="Validate the causal eligibility matrix (FB-31)")
    ap.add_argument("--check", action="store_true", help="validate existing registry")
    args = ap.parse_args()
    _ = args

    if not os.path.exists(REGISTRY_PATH):
        print("FAIL: registry not found: %s" % REGISTRY_PATH, file=sys.stderr)
        return 1

    registry = load_yaml(REGISTRY_PATH)
    errors = validate(registry)
    computed = len(registry.get("failure_families", []))
    declared = registry.get("declared_total")
    if errors:
        for e in errors:
            print("ERROR: " + e, file=sys.stderr)
        print("FAIL: causal eligibility matrix invalid (%d errors)" % len(errors), file=sys.stderr)
        return 1
    print("OK: causal eligibility matrix %d failure families, declared_total == computed_total == %d"
          % (computed, declared))
    return 0


if __name__ == "__main__":
    sys.exit(main())
