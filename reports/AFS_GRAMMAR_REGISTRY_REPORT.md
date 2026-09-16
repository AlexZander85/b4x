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
| `safe_duplicate_original` | enabled | existing `ActionPlan` write transform | `count=1` |
| `pre_padding` | enabled | existing `action.ApplyClientHelloPadding` pure `ActionPlan` transform | `1,4,8,16,32` bytes |
| `post_padding` | enabled | existing `action.ApplyClientHelloPadding` pure `ActionPlan` transform | `1,4,8,16,32` bytes |
| `per_flow_jitter` | enabled by policy | existing `ActionPlan` delay transform | `0,1,2,4,8 ms` |
| `safe_fake_profile` | enabled only when policy permits and an existing validated endpoint-safe `FakeMixRequest` template is supplied | `PlanFakeMix` | finite mode; profile ID is sourced from the existing validated action template/registry |

All eight grammar-v1 operator families are automatic-safe only through existing Action-layer primitives. The synthesis layer does not create a second packet engine or raw-packet execution path.

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

Grammar escape and unsafe emission raise dedicated zero-tolerance counters. Current focused CI run `35098015343` (`AFS Addendum CI` #93) passed the Action, config, detector, Discovery, Monitoring, observability, runtimecontrol, validation and UI checks on branch commit `fa8a7c8da3fc6563d2349697e76933a89f85583a`.
