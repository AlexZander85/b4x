# PPE Stage 3 Implementation Report

## Scope

Implemented transactional apply, remove, exact verification, rollback, and cleanup for B4-owned PPE chains and jumps.

## Delivered

- `TransactionManager` serializes PPE mutations and tracks the active desired generation.
- Every address family is snapshotted before the first mutation.
- A candidate generation is installed only through `iptables -w` / `ip6tables -w` after lock support was proven by PPE-1.
- B4 removes only jumps carrying B4 provenance comments and only the owned `B4_PPE_PRE` / `B4_PPE_FWD` chains.
- Duplicate owned jumps and rules are reconciled to one canonical generation.
- Owned jumps are inserted at position 1 in `mangle/PREROUTING` and `mangle/FORWARD`.
- Exact verification rereads `iptables -S`, checks chain presence, jump count and position, and compares ordered chain rules with the compiled plan.
- Apply/remove failures restore all family snapshots in reverse order.
- Rollback uses a separate bounded context, so cancellation of the mutating request cannot cancel cleanup.
- Foreign references to B4-owned chains fail before any mutation.

## Failure semantics

- Missing proven xtables lock support rejects mutation.
- Verification failure is treated the same as apply failure and restores the previous generation.
- Remove is transactional and restores previous state when any family fails.
- Rollback errors are returned together with the original stage error; they are never hidden.
