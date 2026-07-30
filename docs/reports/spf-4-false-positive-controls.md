# SPF-4 — False-positive controls

Status: IMPLEMENTED_NOT_TARGET_VALIDATED

Added pre-classification suppression primitives with bounded fresh same-scope
and compatible-path success windows. Explicit server/application responses are
non-expiring suppressors for the assessed flow. Any active suppressor wins over
positive evidence; stale success cannot suppress a new assessment.
