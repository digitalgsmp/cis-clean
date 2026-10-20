# Unit 8A session-identity correction — architecture review card

## Review boundary

Review only this proposed correction to the unaccepted Unit 8A worker-session
slice. Return a structured verdict. Do not propose a parallel execution,
verification, review, or promotion system.

## Current defect

Migration `0013_worker_sessions.sql` says the session content address excludes
the supervision route, but `WorkerSessionAuthority.open_session` includes
`supervision_id`, `route_index`, and `adapter_id` in both `session_id` and
`session_hash`. The current `worker_sessions` row is therefore one route-bound
provider session leg, not a durable provider-neutral logical session.

The current schema also intentionally allows exactly one
`worker_model_requests` row per supervision route and exactly one request per
route-bound session. A regression test proves a second disagreeing session
cannot alias or reuse that request; it fails closed.

## Required invariants

1. A durable logical session represents conversation/work continuity and is
   provider-neutral. Its identity must not include a supervision plan, route,
   authorization, adapter, provider, or external provider session reference.
2. Every model request remains independently bound to exactly one verified
   supervisor route, one distinct `ALLOW` authorization, one adapter, exact
   positive budgets, and prompt/context/response-schema digests.
3. Provider fallback or a later authorized request may continue the same
   logical session without reusing a spent authorization.
4. Existing migration-0013 rows are immutable and must remain verifiable.
5. No external provider session reference or checkpoint becomes authority.
6. The correction must not create another gateway, verifier, reviewer,
   evidence store, or promotion path.

## Proposed versioned correction

Add migration `0014_worker_logical_sessions.sql`; do not rewrite 0013.

Add append-only table `worker_logical_sessions` with:

- `logical_session_id` primary key
- `objective_id`, `transaction_id`, `target_module_id`, `operation`,
  `logical_role`
- a closed v1 hash domain, content hash, timestamp, sequence

Its content address is derived only from those semantic fields. It contains no
route, authorization, adapter, provider, or external-session identity.

Add append-only association table `worker_session_legs` with:

- content-addressed `leg_id`
- `logical_session_id` foreign key
- existing route-bound `session_id` foreign key
- positive `leg_ordinal`
- hash domain, content hash, timestamp, sequence
- uniqueness on `(logical_session_id, leg_ordinal)` and on `session_id`

Keep migration-0013 `worker_sessions` and its current API as immutable
route-bound session legs for compatibility. Correct its misleading migration,
module, contract, and README language so it no longer claims route-independent
identity or durable logical continuity.

Extend `WorkerSessionAuthority` with:

- `open_logical_session(objective_id, transaction_id, target_module_id,
  operation, logical_role)`
- `attach_route_session(logical_session_id, session_id, leg_ordinal)`
- read/verify methods for logical sessions and legs

`attach_route_session` must independently verify both records, require all
shared objective/transaction/target/operation/role fields to match, and refuse
duplicate, disagreeing, reordered, or cross-objective attachment. The route
session continues to enforce request-to-route authorization and budgets.

Legacy 0013 rows remain valid route legs. They acquire durable continuity only
when explicitly attached to a verified logical session; there is no inferred
or automatic backfill.

## Focused acceptance tests

- identical logical-session open is idempotent
- logical identity is unchanged across distinct authorized routes/adapters
- two route sessions can attach to one logical session in ordered legs
- each leg's request remains bound to its own route and authorization
- cross-objective/transaction/target/operation/role attachment refuses
- duplicate session attachment and disagreeing ordinal refuse
- tampered logical-session and leg digests refuse
- append-only update/delete triggers protect both new tables
- existing 0013 tests, including cross-session alias refusal, remain green

## Requested verdict format

Return JSON only:

```json
{
  "verdict": "PASS|OBJECTIONS|INVALID_REVIEW",
  "summary": "...",
  "objections": [
    {"severity": "HIGH|MEDIUM|LOW", "issue": "...", "required_change": "..."}
  ],
  "accepted_invariants": ["..."],
  "model_assessment": "architecture review, not implementation verification"
}
```
