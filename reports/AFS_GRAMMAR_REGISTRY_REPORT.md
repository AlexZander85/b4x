# AFS Grammar Registry Report

Grammar version: `afs-grammar-v1`
Engine version: `afs-synth-v1`
Status: `LAB_VALIDATED`

## Automatic operator registry

| Operator family | Automatic status | Existing compiler bridge | Bounded parameters |
|---|---|---|---|
| `tcp_split` | enabled | `PlanStrategy` | registered logical marker domain |
| `tls_record_split` | enabled | `PlanTLSRecordSplit` validation + existing multi-split plan | registered TLS/SNI marker domain |
| `bounded_disorder` | enabled by policy | `PlanStrategy` multi-disorder | marker + `swap_adjacent_once` |
| `safe_duplicate_original` | enabled | existing ActionPlan write transform | `count=1` |
| `per_flow_jitter` | enabled by policy | existing ActionPlan delay transform | `0,1,2,4,8 ms` |
| `safe_fake_profile` | enabled only when policy permits and validated template is supplied | `PlanFakeMix` | finite mode; profile ID comes from existing validated registry |
| `pre_padding` | registered but **not automatic** | unavailable | finite byte domain |
| `post_padding` | registered but **not automatic** | unavailable | finite byte domain |

## Global bounds

- max candidates: `24` by default;
- max generations: `3`;
- max actions: `4`;
- max branches: `1`;
- max amplification: `1.5`;
- runtime/probe use remains inside the existing Discovery budget;
- synthesis search concurrency is constrained by the existing Discovery policy and AFS preflight resource gate.

## Emission hard gate

Before a synthesized candidate enters Discovery, the emission guard re-checks:

1. exact grammar version;
2. registered trigger domain;
3. registered operator family;
4. automatic-safe status and available existing compiler bridge;
5. every parameter against its finite domain.

Grammar escape and unsafe emission raise dedicated zero-tolerance counters. Focused CI run `35085703795` passed after fault-injection coverage was added.
