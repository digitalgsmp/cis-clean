# Queue 4.37 controller invariant — continuity revision 43

Projection generated for Git-visible recovery on 2026-10-20. This file is not
an independent authority. The authoritative record is
`dev_continuity_events(task='4.37', revision=43)` in the CIS spine, request ID
`codex-20261020-registered-role-controller-invariant-v1`.

Status: `AUTHORITATIVE_REGISTERED_ROLE_CONTROLLER_INVARIANT`

## Governing invariant

No model execution may occur outside a registered, role-specific CIS-owned
controller. This applies to Brain/Codex, Menter/Claude, Qwen, DeepSeek, Kimi,
and future models, regardless of provider, lineage, harness, or whether they
run on the host or inside a container. Raw model, CLI, harness, and provider
invocations are not valid normal pipeline routes.

Each controller must bind:

- the logical role and exact model, provider, harness, and execution identity;
- the authorized task contract;
- filesystem, network, tool, credential, time, token, and cost boundaries;
- mandatory structured input and output;
- durable session, attempt, checkpoint, and failure facts;
- fail-closed handling for missing reports, timeouts, permission waits,
  provider failures, malformed artifacts, and exhausted budgets; and
- evidence to the exact authorization, candidate, and route.

No model may verify, review, authorize, admit evidence, mutate the queue,
expand permissions, promote, or accept its own work. A separately authorized
role-specific controller must own each operation, and independence constraints
still apply.

## Role boundaries

- **Brain:** reads authority, continuity, dependencies, and evidence and
  produces recommendations, cards, and reconciliation. It does not implement,
  act as deterministic verifier, admit evidence, mutate authority without an
  authorized interface, or promote.
- **Menter:** makes only authorized candidate changes in a bounded workspace,
  runs developer tests, and returns a candidate and structured report. It does
  not perform independent acceptance or promotion.
- **Reviewer:** reads the exact candidate and bound evidence, satisfies the
  independent-lineage policy, and cannot edit, accept, or promote.
- **Deterministic Verifier:** is trusted CIS software, not a model. It runs
  required acceptance checks independently behind its own narrow execution
  boundary.
- **CIS authority:** alone records acceptance and controls promotion.

Separately authorized break-glass execution must be recorded as recovery and
must never be represented as ordinary governed execution. A model route that
does not yet have a registered and verified controller is unavailable rather
than informally substituted.

## Build consequence

Complete and register the common `CodingAgentController` boundary, the Claude
and Hermes/provider-neutral process controllers, supervisor routing and budget
profiles, deterministic-verifier handoff, independent-review receipts,
promotion gates, durable continuity, and Workbench observability. The
`cis-clean` container image must reproduce these boundaries.

The pre-existing revision 42 contradiction remains open: the Qwen reviewer
route is not accepted as deterministically enforced until actual route
execution and its receipt are proven.

## Recorded evidence

- `tests.test_claude_process:8:PASS`
- Qwen implementation review:
  `gen-1792541011-7oqXWT8JOYPgnEWbDnvE` — PASS
- Qwen Hermes-controller architecture review:
  `gen-1792540130-dwZTPWxMzMpoI7yTcGXl` — PASS

## Snapshot verification status

At the time this recovery projection was committed, the accumulated working
tree was intentionally preserved as WIP. The full deterministic suite ran 662
tests with three failures: two README count assertions and one Layer-2 backend
name leak assertion covering the newly introduced reviewer/controller modules.
This projection does not convert that implementation into accepted evidence.
