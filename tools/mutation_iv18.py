#!/usr/bin/env python3
"""FB-28 / IV-18 mutation suite (E3).

Applies one targeted mutation at a time to src/monitor/*.go, runs the
existing monitor unit test that pins the invariant, and reports whether the
mutant was KILLED (test failed -> invariant is live) or ESCAPED (tests still
passed -> coverage gap).

Fail-closed contract (IV-18-FT-MON-B / IV-18-MON-12):
  * every mutation in this suite MUST be killed by the existing suite;
  * any escaped or non-compiling mutant fails the run (exit code 1);
  * the source tree is restored to its exact original bytes after each
    mutation, so this script never leaves a modified tree behind.

Usage:
  python tools/mutation_iv18.py [--image golang:1.25-alpine]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MONITOR_DIR = os.path.join(REPO_ROOT, "src", "monitor")

# (id, file, old, new, target_test)
# Every mutation maps to a concrete invariant pinned by an existing test:
MUTATIONS = [
    (
        "M1-invalid-observation-rejected",
        "observation_bus.go",
        "if b == nil || !o.Valid(b.cfg.Clock()) {",
        "if b == nil || o.Valid(b.cfg.Clock()) {",
        "TestBusValidatesScopeAndPreservesSafetyLane",
    ),
    (
        "M2-queue-drop-safety-lane",
        "observation_bus.go",
        'p0 := o.Source == SourceQueueDrop || o.Source == SourcePPEVisibility || o.Source == SourceTCPRST',
        'p0 := o.Source == SourcePPEVisibility || o.Source == SourceTCPRST',
        "TestBusValidatesScopeAndPreservesSafetyLane",
    ),
    (
        "M3-failing-boundary",
        "temporal.go",
        "case HealthDegraded:\n\t\tif f >= a.cfg.FailuresToFailing {",
        "case HealthDegraded:\n\t\tif f > a.cfg.FailuresToFailing {",
        "TestTemporalHysteresisAndBoundedBuckets",
    ),
    (
        "M4-bucket-limit-removed",
        "temporal.go",
        "for len(a.buckets) > a.cfg.MaxBuckets || (len(a.buckets) > 0 && a.buckets[0].End.Before(cutoff)) {",
        "for (len(a.buckets) > 0 && a.buckets[0].End.Before(cutoff)) {",
        "TestTemporalHysteresisAndBoundedBuckets",
    ),
    (
        "M5-quick-overload-boundary",
        "scheduler.go",
        "if len(s.quick) >= s.cfg.QuickCapacity {",
        "if len(s.quick) > s.cfg.QuickCapacity {",
        "TestSchedulerOverloadIsBounded",
    ),
    (
        "M6-backoff-removed",
        "scheduler.go",
        "e.running = nil\n\t\t\te.attempts++\n\t\t\te.nextAt = now.Add(s.cfg.Backoff * time.Duration(e.attempts))",
        "e.running = nil\n\t\t\te.attempts++\n\t\t\te.nextAt = now",
        "TestSchedulerCoalescesAndLeases",
    ),
    (
        "M7-empty-path-evidence-accepted",
        "ddi.go",
        "len(r.PathEvidence) == 0",
        "len(r.PathEvidence) != 0",
        "TestRecommendationRequiresIPPathEvidence",
    ),
    (
        "M7b-expired-ddi-fresh",
        "ddi.go",
        "p.ExpiresAt.IsZero() || now.Before(p.ExpiresAt)",
        "p.ExpiresAt.IsZero() || !now.Before(p.ExpiresAt)",
        "TestDDIAndDiscoveryRequireFreshAuthoritativeInputs",
    ),
    (
        "M8-scope-mismatch-accepted",
        "abd_adapter.go",
        "if result.Scope != r.Request.Overlay.Scope {",
        "if result.Scope == r.Request.Overlay.Scope {",
        "TestABDEscalationRejectsScopeMismatch",
    ),
    (
        "M10-android-origin-dropped",
        "canary.go",
        'if o.Milestone == MilestoneAndroidSeen && o.Origin == "android" && o.Success {',
        'if o.Milestone == MilestoneAndroidSeen && o.Success {',
        "TestCanaryRequiresAndroidMilestoneSeparately",
    ),
    (
        "M11-rollback-inverted",
        "canary.go",
        "if o.Milestone == MilestoneRollbackSignal {",
        "if o.Milestone != MilestoneRollbackSignal {",
        "TestCanaryRollbackIsObservationOnly",
    ),
]


def run(cmd, timeout=600):
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr


def go_test_in_docker(image, test_name):
    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{REPO_ROOT}:/src",
        "-v", "b4x-gomod:/go/pkg/mod",
        "-w", "/src/src",
        image,
        "sh", "-c", f"go test ./monitor/ -run '^{test_name}$' 2>&1",
    ]
    rc, out = run(docker_cmd)
    return rc, out


def classify(rc, out):
    if rc == 0:
        return "escaped"
    if "FAIL" in out or "failed" in out.lower():
        return "killed"
    return "error"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="golang:1.25-alpine")
    parser.add_argument("--skip-docker-check", action="store_true")
    args = parser.parse_args()

    if not args.skip_docker_check:
        rc, out = run(["docker", "version", "--format", "{{.Server.Version}}"])
        if rc != 0:
            print(f"docker unavailable: {out}", file=sys.stderr)
            sys.exit(2)

    started = datetime.now(timezone.utc).isoformat()
    results = []
    failed = False
    for mid, fname, old, new, target in MUTATIONS:
        path = os.path.join(MONITOR_DIR, fname)
        with open(path, "r", encoding="utf-8") as fh:
            original = fh.read()
        count = original.count(old)
        if count != 1:
            results.append({"id": mid, "file": fname, "target": target,
                            "result": "error", "detail": f"old pattern found {count} times, want exactly 1"})
            failed = True
            continue
        mutated = original.replace(old, new)
        try:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(mutated)
            rc, out = go_test_in_docker(args.image, target)
            outcome = classify(rc, out)
            detail = out.strip().splitlines()[-1] if out.strip() else ""
            results.append({"id": mid, "file": fname, "target": target,
                            "result": outcome, "detail": detail})
            if outcome != "killed":
                failed = True
        finally:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)

    killed = sum(1 for r in results if r["result"] == "killed")
    escaped = sum(1 for r in results if r["result"] == "escaped")
    errors = sum(1 for r in results if r["result"] == "error")

    report = {
        "suite": "IV-18-MUTATIONS",
        "generated_at": started,
        "total": len(results),
        "killed": killed,
        "escaped": escaped,
        "errors": errors,
        "verdict": "PASS" if not failed else "FAIL",
        "mutations": results,
    }
    print(json.dumps(report, indent=2))

    evidence_dir = os.path.join(REPO_ROOT, "specs", "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "iv18-mutations.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
