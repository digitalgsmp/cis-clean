# CIS clean-room reconstruction — vertical slices 1–6B2

A runnable, offline, deterministic slice of the durable CIS: **one human
instruction becomes a bounded ALLOW or HOLD, an ALLOW becomes one governed
backend run, and that immutable submission can pass through deterministic
verification, independent review, bounded objections, and a record-only
promotion decision.**

Slice 3 adds a fail-closed regeneration proof: every declared derived surface
is rebuilt twice through fresh projection instances, its canonical hash must
match, authority must remain byte-identical, and a file-backed cold start must
produce the same combined surface hash.

Slice 4 adds a real nonroot networkless container worker bound to a frozen task
contract plus a separate host gate that applies only a promotion-authorized,
evidence-matching candidate and can restore prior bytes from append-only
authority alone.

Slice 5 adds production issuance for `verify_authored_source.v1`: the exact
candidate, canonical vector contract, entrypoint, immutable worker image and
trusted apparatus digests are bound before dispatch. The real contained run is
then admitted through the existing verifier, independently reviewed against
the same bindings, and may produce only a record-only autonomous promotion
decision.

Slice 6 begins bounded recovery with operational self-assessment. A recorded
objection is independently rechecked against its review, verification and
execution-input authority, then translated into an immutable specification of
what failed, what must remain unchanged, and what a later recovery may alter.
This assessment deliberately grants no execution authority.

Slice 6B1 adds `cis.assurance.recovery_attempt`, the sole owner of
`recovery_attempts`. It records the lineage from a verified
replacement-required assessment to the fresh child task contract and
execution-input binding issued for its replacement attempt. This records
lineage only; it neither claims execution nor grants authority to authorize,
execute, verify, review or promote anything.

Slice 6B2 adds `cis.assurance.recovery_execution`. It requires a separate,
pre-existing child authorization and carries that replacement through the
existing issuer, recovery-attempt ledger, gateway, Verifier, Reviewer and
record-only promotion authority. The assessment cannot authorize its own
recommendation, and a failed replacement cannot become promotion-authorized.
The production proof records a rejected parent and a successful replacement
through the real sealed non-root worker.

Slice 8A adds `cis.execution.worker_session`. Migration 0013's
`worker_sessions` row is one route-bound provider session leg — its content
address includes the governing supervision route and adapter — not a
durable, provider-neutral session; it keeps its existing API unchanged.
Migration 0014 adds the durable logical session that was missing:
`worker_logical_sessions`, content-addressed only from
objective/transaction/target-module/operation/role and naming no route,
authorization, adapter, provider or external session reference, plus
`worker_session_legs`, the append-only association that attaches an existing
route-bound session to a logical session at a strictly positive sequential
ordinal. A route-bound session gains durable continuity only through
explicit attachment — there is no inferred or automatic backfill — so a
provider fallback or a later authorized request can continue the same
logical session without reusing a spent authorization or aliasing a new one.
`tests.test_worker_session` is 25/25 deterministic PASS, independently
confirmed by a Qwen final PASS against
`runtime/review-cards/unit-8a-session-architecture-v1.md`.

`/mnt/projects/cis` is read-only evidence for this work. Nothing here reads,
writes, migrates, restarts or deploys anything in it; the authority store
refuses to open a database under that path at all, and every ALLOW carries
`write:/mnt/projects/cis` in its forbidden actions.

---

## Operator commands

```sh
cd /mnt/projects/cis-clean

# validate the blueprint and all 38 module contracts, print the derived order
PYTHONPATH=src python3 -m cis verify

# run the whole slice end to end, in memory, offline
PYTHONPATH=src python3 -m cis demo

# the full test suite (stdlib unittest, no dependencies, no network)
python3 -m unittest discover -s tests -t . -v

# real Slice 5 proof (requires the sealed contained-worker image)
PYTHONPATH=src python3 tools/prove_authored_source_pipeline.py \
    --authority runtime/worker-proof/authored-source-unit-5.db \
    --output runtime/worker-proof/authored-source-unit-5.json

# real Slice 6B2 bounded-recovery proof (requires the sealed worker image)
PYTHONPATH=src python3 tools/prove_recovery_pipeline.py \
    --authority runtime/worker-proof/recovery-unit-6b2-attempt2.db \
    --output runtime/worker-proof/recovery-unit-6b2-attempt2.json

# one test module
python3 -m unittest tests.test_execution -v

# the Workbench JSON interface on loopback (optional; nothing needs it)
PYTHONPATH=src python3 -m cis serve --port 8077 \
    --objective "Reconstruct the CIS Workbench trajectory projection"
```

Exercising it over HTTP — these eleven routes are the whole surface:

```sh
curl -s localhost:8077/health            # also prints the route list
curl -s localhost:8077/blueprint
curl -s localhost:8077/contracts
curl -s localhost:8077/objective
curl -s -X POST localhost:8077/instruction \
  -d '{"verbatim":"Reconstruct cis.workbench.projection in the clean environment"}'
curl -s localhost:8077/authorization/auth-tx-...
curl -s -X POST localhost:8077/execute -d '{"authorization_id":"auth-tx-..."}'
curl -s localhost:8077/trajectory
curl -s localhost:8077/trajectory/tx-...
curl -s localhost:8077/assurance
curl -s localhost:8077/assurance/task/tc-...
```

There is deliberately **no** `POST /evidence` and no route that mutates the
objective. Trusted evidence admission is a privileged in-process seam
(`Workbench.import_authoritative_evidence`, which requires an
`admission_basis` naming the import path) and is absent from the HTTP surface.
Even if it were present it would unlock nothing: evidence records are
continuity material, and **token overlap confers no execution authority** —
permission comes from the validated architecture for the target module and
from nowhere else. `POST /instruction` accepts the single field `verbatim` and nothing
else: a body carrying `actor` or `declared_classification` is refused with
`INVALID_INPUT`, because classification is derived from the exact operator
words. `POST /execute` accepts the single field `authorization_id`; the
operation is derived from the recorded authority and is not a dispatch
argument.

**Honest statement about this listener.** It has no caller identity, no
authentication and no authorization of its own. It binds loopback for a single
trusted local operator, and it is single-threaded on purpose — the authority
store owns one SQLite connection and one logical sequence counter, so
`HTTPServer` is the correct choice and `ThreadingHTTPServer` would be a
correctness bug, not a performance win. This is an operator console, **not an
external-agent endpoint**; granting a remote agent access would need an
identity seam that does not exist in this slice.

---

## What is here

```
blueprint/reconstruction_manifest.json   operational input: stages, selected modules,
                                         reconstruction status, evidence basis
contracts/*.contract.json                38 module contracts, exactly 16 fields each
src/cis/contracts/                       registry + field-level validator
src/cis/blueprint/                       manifest loader; baseline hash
src/cis/authority/                       clean SQLite authority + 14 migrations
policy/                                  cumulative closed-schema operational policy sources
src/cis/policy/                          automatic source admission + closed MASTER/TASK compiler
src/cis/assurance/                       frozen contracts, verifier, independent reviewer,
                                         promotion gate and derived projection
src/cis/projection/                      exhaustive regeneration and cold-start proof gate
src/cis/continuity/                      classifier + antecedent retrieval
src/cis/workbench/                       application service + trajectory projection
src/cis/execution/                       Layer-2 port, gateway, and L3 adapters
src/cis/worker/                          real nonroot contained execution adapter
src/cis/host/                            decision-enforcing apply and rollback gate
src/cis/interface/                       L1 JSON control surface (+ stdlib HTTP)
tests/                                   554 tests, stdlib unittest only
```

---

## The rules this slice implements, and where

| Recorded authority | Where it is enforced |
|---|---|
| ADR-ARCH-001 cl. 3 — exactly 16 semantic fields | `contracts/registry.py :: REQUIRED_FIELDS`, refused before recording |
| ADR-ARCH-001 cl. 4 — fields do not collapse | `parse_contract` refuses `recovery_behavior == failure_boundary` and `evidence_produced == [verification]` |
| ADR-ARCH-001 cl. 5 — one owner per authority | `ContractRegistry.add` / `validate`; 26 owned authorities, 15 owner modules |
| ADR-ARCH-001 cl. 2 — planes are properties | `trust_domain`, `execution_location`, `failure_boundary` are contract fields; there is no second hierarchy and no second store |
| ADR-ARCH-002 — record once, derive everywhere | dependency order, active objective, module progress and "you are here" are all derived; the manifest is refused if it carries a literal dependency order |
| ADR-ARCH-002 — derive from fields, not prose | every decision the code makes reads a structured field; no module parses narrative text for a status |
| ADR-ARCH-003 cl. 1 — one sole call path | `execution/gateway.py`; a leak test asserts no backend name, port, path or config file appears above it |
| ADR-ARCH-003 cl. 3 — declared liveness | `ExecutionPort.liveness()`; nothing reads a backend's private files or logs |
| ADR-ARCH-004 cl. 1 — verbatim is immutable source evidence | `authority/intent.py`; byte-exact storage, hashed, with the interpretation in a separately labeled source-linked column, append-only by trigger |
| ADR-ARCH-004 cl. 2 — work must already be inside authority | `Workbench._verdict`; ALLOW derives only from canonical authority — the validated manifest's selected-module entry and its `evidence_basis`, the module's contract and reconstruction status, and an independently established objective |
| ADR-ARCH-002 — evidence is not authority | retrieval ranks evidence for continuity and is not an input to the verdict; `required_evidence` names canonical accepted authority, never a retrieved antecedent id |
| ADR-ARCH-004 cl. 3 — a contract cannot widen scope | scope is derived from the target module's own contract and is inside the binding hash |
| ADR-ARCH-004 cl. 5 — author is not verifier | `assurance/verifier.py` and `assurance/reviewer.py` use separate input ports and are registry-forbidden from depending on one another |
| Frozen task contract | `assurance/task_contract.py`; independent hash domain, template envelope, narrowing allowed and widening refused |
| MASTER/TASK policy enforcement | `policy/operational_sources.json`, `policy/source_catalog.py`, `policy/sources.py`, `policy/resolver.py`, `policy/compiler.py`, `policy/authority.py`, `execution/gateway.py`, `worker/policy_obligations.py`, `worker/contained_nonroot.py`; every governed dispatch admits and compiles current policy, while each required check/evidence label maps to independently verified facts and only `label=verified` satisfies the gateway |
| Bounded objection recovery | `assurance/reviewer.py` plus migration `0004`; three cycles maximum, then `ESCALATED`, with a fourth blocked by API, ledger and SQL |
| Promotion conjunction | `assurance/promotion.py`; `PROMOTION_AUTHORIZED` requires recorded `VERIFIED_PASS` and review `PASS`, and records `NONE_RECORD_ONLY` as the host action |
| Contained nonroot execution | `worker/contained_nonroot.py`; recomputed frozen contract, token-covered policy envelope, no network, read-only root, dropped capabilities, nonroot identity, resource and wall-time bounds, host-verified teardown, and closed semantic evidence mapping |
| Sanctioned host action and rollback | `host/promotion_gate.py` plus migration `0005`; the decision and action remain separate, exact prior and candidate bytes are planned before mutation, and state is derived from append-only completion events |
| Projection regeneration | `projection/regeneration.py`; exhaustive manifest inventory, two fresh builds, per-surface hashes, unchanged complete-authority digest, and cold-start surface-set equivalence |
| ADR-SEED-018 — L1 / L2 / L3 ownership | `layer` field plus three registry rules: nothing depends on L1, L1 never depends directly on L3, and L3 never depends on an authority owner |
| `dev_continuity_events` rev 178 — continuity of perspective | `continuity/classifier.py` + `continuity/retrieval.py`: questions and fragments are retrieval cues that recover prior intent in its original language; only an explicit redirection supersedes the objective; the superseded objective is retained |
| Handoff A21 — sanctioned mutation path | one `AuthorityStore.insert`; append-only enforced by SQLite trigger, not by convention |
| Handoff A26 — clean-room principle | modules were selected from positively identified capabilities and each carries its `evidence_basis`; nothing was copied from the reference tree |

---

## Architectural rationale, briefly

**Why the manifest does not list the dependency order.** The order is a fact the
contracts already own through `depends_on`. Writing it again in the manifest
would create the second writable record ADR-ARCH-002 forbids, and the two would
drift. The manifest instead names the authority and the derivation, and the
loader *refuses* a manifest that tries to carry the order itself.

**Why "you are here" has no column.** A stored position is a second copy of a
fact the event log already holds, and a stored copy is exactly what goes stale.
The marker is computed from the single highest-`seq` trajectory event, and it
reports its own provenance (`trajectory_events:seq=30`). A test asserts the
schema contains no position column.

**Why the binding is one hash over six things, and what that does not prove.** Instruction, continuity
decision, authorization identity and verdict, scope, baseline and objective are
bound together, and the gateway recomputes that hash from authority immediately
before dispatch. A forged row with a wider scope and a copied hash does not
verify; an authorization issued under an objective that was later superseded
does not verify; an authorization issued against a different blueprint or
contract set does not verify. All four refusals happen before any backend work.
It is an integrity hash and not a MAC, so it proves consistency, not issuance —
see the limitation named under "What this slice does not do".

**Why the default verdict is HOLD.** Nothing in this slice can reach execution
by accident. A question, a memory fragment, an unresolved target, a module
outside this slice's reconstruction scope, a module with no canonical evidence
basis, a recorded evidence conflict, an absent objective, or an objective this
very request established each produce HOLD with a reason code from a closed
vocabulary. ALLOW requires that the work name exactly one module the validated
manifest selects, that the module be in reconstruction scope, that it carry a
non-empty canonical `evidence_basis`, that an objective established
independently of the request govern, and that no evidence conflict stand
recorded.

**Why continuity and authorization are two separate concerns.** Retrieval
recovers prior human exchanges and admitted knowledge so meaning survives a
question or a vague memory fragment. That is continuity, and it is the whole
of what retrieval is for. It is **not** an authorization basis: a request must
never be able to manufacture the authority that permits it, and token overlap
against conversation history is exactly such a manufacture — submit a request,
be held, submit it again, and the held request becomes "evidence". So the two
channels are separate in the data and in the code. `required_evidence` on an
ALLOW names the target module's canonical accepted `evidence_basis` from the
validated manifest, labeled `canonical_evidence_basis:<module>:<ref>`, and
never an `intent:tx-*` or `evi-run-*` id. Retrieved antecedents travel beside
the authorization as `antecedents`, each tagged
`CONTEXTUAL_CONTINUITY_EVIDENCE_NOT_AUTHORIZATION_BASIS`. `Workbench._verdict`
does not take the antecedents as a parameter at all, which is the structural
reason overlap cannot leak back into permission, and a test pins that
signature.

**Why the manifest may be the authorization basis, and what that assumes.**
The manifest is operational input, it is validated before use, and its exact
bytes are inside `baseline_hash`, so a selected-module entry cannot drift from
an authorization that cites it without every prior authorization going stale.
That is what makes it canonical here rather than merely convenient. The
assumption this slice carries openly: the manifest is accepted architecture
because a human wrote and reviewed it, and nothing in the slice *proves* that
acceptance. Accepted ADR / KB / queue authority as a second, independently
recorded basis is a later slice.

**Why a repeated request gains nothing.** The target module is either already
selected by the validated architecture with a canonical evidence basis or it
is not. If it is, the *first* request is allowed and the second is a distinct
transaction bounded byte-identically — same operation, same scope, same
required evidence. If it is not, no number of repetitions changes that: each
repeat appends one more immutable record of the request and zero canonical
authority. The one HOLD that a later request legitimately clears is an absent
objective, and clearing it requires an *earlier exchange that said something
else*, or the bootstrap seam. An instruction that establishes the first
objective is not authorized under the objective it just created, and neither
is a verbatim repetition of it — the independence check compares the objective's
originating verbatim hash, not just its transaction id, precisely so the retry
loophole cannot survive one level up.

**Why one ALLOW authorizes exactly one attempt.** Immediately before adapter
entry the gateway appends a claim whose authorization id is UNIQUE in SQLite.
That atomic claim survives failure and closes concurrent dispatch as well as
ordinary replay. Re-dispatch is refused even when the first container attempt
did not return a run row. New work needs a new instruction and authorization.

**Why there are two mock backends.** Replaceability has to be demonstrated, not
asserted: "a contract above a backend that cannot actually be swapped is
documentation, not a proven boundary" (handoff A6). Both adapters satisfy the
same port, the switch happens entirely inside the Layer-2 gateway, and the test
proves different backends really ran by comparing artifact digests while the
calling code stays byte-identical.

**Why evidence conflicts fail closed.** When the blueprint and the contracts
disagree, the loader raises `EvidenceConflict` and the Workbench holds. No
resolution is invented, and a recorded conflict in the authority is itself
enough to force HOLD.

**Why no LLM, no network, no third-party package.** Determinism is a hard
requirement of the slice: the same words must classify the same way and the same
request must hash the same way, forever. `tests/test_offline.py` runs the whole
end-to-end path with `socket.socket` replaced by a trap that raises, and asserts
the trap was never touched.

---

## What this slice does not do

* Objection cycles still only record a bounded recovery decision; they do not
  execute a replacement themselves. `cis.assurance.recovery_execution` carries
  a replacement candidate end to end, but only for one already-assessed,
  already-authorized child — it has no retry policy, no failure
  classification and no way to select or produce a candidate on its own.
* The deterministic mock backend remains for offline boundary tests. The real
  contained worker can execute source bound by `verify_authored_source.v1` and
  its closed vector contract. It cannot choose its inputs, verify itself,
  review itself, promote its own output, or perform a host action.
* Retrieval is deterministic token overlap, not semantic search. It is honest
  about what it matched and it is reproducible; it is not a recall claim, and
  it is not a permission channel — nothing it returns can authorize work.
  Ranking prefers the human's original words over records CIS generated about
  its own execution, which is an explicit ordering rule, not a quality claim.
* No adapter for any external harness exists, by decision: ADR-ARCH-003 adopts,
  evaluates and records no backend, and absence is the status of an unadopted
  one.
* `STEP_6_PROVE_THE_BOUNDARIES` is complete for the declared A–O inventory.
  The proof includes frozen contract integrity, a real container boundary,
  deterministic verification, independent review, bounded objections,
  promotion conjunction, sanctioned apply, authority-only rollback, timeout
  cleanup, and repeated fresh-container execution. Nothing listens by default and there is no credential to
  protect; `cis serve` is the one exception, and it is an unauthenticated
  loopback console rather than a secured surface.
* The authorization binding is an integrity hash, not a proof of issuance.
  `binding_hash` is an unkeyed sha256 over public fields, so it catches an
  edited row, a copied hash over a widened scope, and a verbatim or decision
  digest that no longer recomputes from its source — all of which the tests
  exercise. It does not catch a self-consistent row appended by something that
  already holds `AuthorityStore.insert`, which `tests/test_authorization.py ::
  BindingIsIntegrityNotProvenanceTests` states explicitly rather than hiding.
  What stands in the way there is architectural: exactly one writer of
  `execution_authorizations`, and no route that reaches the append primitive.
  An unforgeable issuance proof needs a key and a key owner, which this slice
  does not have.
* The logical clock is per-store-instance. `created_at` is a deterministic
  counter so every hash reproduces; re-opening a file-backed authority restarts
  it, so ordering everywhere comes from `seq`, which *is* resumed from
  `MAX(seq)`. No module compares two `created_at` values.
* `cis demo` narrates a first conversation and refuses an authority that
  already holds intent transactions, because on a replay its step labels would
  be false even though the slice still fails closed.

## Next slice boundary

The A–O foundation, deterministic operational self-assessment and the bounded
replacement coordinator now exist. The next development boundary is a real
replacement-recovery proof through the sealed contained worker, followed by
the deferred deterministic worker supervisor for per-attempt budgets, closed
failure classification, progress checkpoints, circuit breaking and bounded
fallback routing. Neither step may let an assessment authorize itself, treat a
worker report as evidence, or move privileged host control into the worker
trust domain.
