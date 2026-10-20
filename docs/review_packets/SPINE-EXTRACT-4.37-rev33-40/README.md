# Spine extract — dev_continuity_events task 4.37, revisions 33-40

Read-only projection of the authority record, extracted 2026-10-20 so an
external reviewer can read it. `data/*` is gitignored, so this content is
otherwise invisible from GitHub. THE DATABASE REMAINS THE AUTHORITY: if this
file and the spine disagree, the spine is right and this file is stale
(ADR-ARCH-002).


---

## Revision 33 — `reconciliation` — superseded_in_part

*2026-10-19 21:02:02 · actor: codex* · against revision 32

**Summary:** reconciled against revision 32: superseded_in_part


**Body:**

AUTHORITATIVE RECONCILIATION. Preserve queue 4.37's trusted host control plane, containment, evidence, independent review, verification, and fail-closed requirements. Supersede only the interpretation that external developers retire to recovery-only use. The retirement gate now means retirement and dormancy of the unsupervised manual host-development path once the contained pipeline is readiness-proven. External Claude, Codex, and other model developers remain available for ongoing capability re-evaluation and implementation as replaceable governed workers invoked through frozen task contracts, bounded execution, worker supervision, and the contained assurance path. They hold no planning, authorization, queue-mutation, acceptance, promotion, permission-expansion, or policy authority by model lineage or location. CIS control-plane authorities assess verified state, reconcile it against the unified authoritative build record, dependency-order bounded recommendations, authorize dispatch, and bind returned artifacts and evidence to the exact task and candidate. Recommendations never self-authorize; every worker result returns through independent review, deterministic verification, evidence admission, and promotion authority. OSA-BR handles bounded operational recovery; /opt/cis-control remains the quiet host trust root and operator break-glass plane. The manual external-host workflow may reactivate only for explicit recovery or trust-boundary repair, while governed external workers may participate routinely without becoming authority. Queue 4.39 is the destination capability and is interpreted with 4.10, 4.20, 4.35, 4.36, and 4.37. Historical queue bodies remain unchanged; this reconciliation is the later authority.


**Evidence refs:** queue_items:4.39; owner_instruction:2026-10-19


**Source refs:** queue_items:4.10; queue_items:4.20; queue_items:4.35; queue_items:4.36; queue_items:4.37; queue_items:4.39


---

## Revision 34 — `verified_result` — RECOVERY_EXECUTION_PROOF_VERIFIED_INDEPENDENT_CODE_ACCEPTANCE_PENDING

*2026-10-19 21:51:01 · actor: codex_with_claude_code*

**Summary:** Bounded replacement recovery completed through the real sealed contained worker


**Body:**

Clean reconstruction Slice 6B2 now carries a replacement-required operational assessment through a separately recorded child ALLOW, immutable production issuance, recovery-attempt lineage, the existing contained-worker gateway, deterministic Verifier, independent Reviewer, and record-only PromotionRecorder. The assessment cannot create its own authorization. Wrong target, wrong operation, missing child authorization, parent-authorization reuse, non-replacement assessment, failed replacement, exact lineage, and idempotent resume are covered. Real sealed-worker proof: the intentionally wrong parent produced VERIFIED_FAIL, OBJECTIONS, and PROMOTION_DENIED; operational assessment produced REPLACEMENT_CANDIDATE_REQUIRED; the distinct child run completed with VERIFIED_PASS, review PASS, PROMOTION_AUTHORIZED, and host action NONE_RECORD_ONLY. Deterministic repository verification: 441 tests pass; cis verify reports 35 contracted/35 selected modules and 24 authorities with exactly one owner; git diff check passes; proof DB quick_check is ok. Claude authored the core bounded unit; Codex independently inspected it and corrected pre-issuance assessment refusal, missing-authorization normalization, claim-without-run refusal, exact run linkage, and the real proof harness. Because Codex modified the final delta, final independent code acceptance remains pending and is not claimed here. Nothing was deployed or host-applied.


**Evidence refs:** /mnt/projects/cis-clean/runtime/worker-proof/recovery-unit-6b2-attempt2.json; /mnt/projects/cis-clean/runtime/worker-proof/recovery-unit-6b2-attempt2.db; tests:441:PASS; cis-verify:35-selected:24-authorities:PASS


**Source refs:** dev_continuity_events:4.37:33; queue_items:4.36; queue_items:4.39


---

## Revision 35 — `verified_result` — RECOVERY_EXECUTION_FINAL_PROOF_GREEN_EXTERNAL_ACCEPTANCE_PENDING

*2026-10-19 22:03:03 · actor: codex_with_claude_code*

**Summary:** Recovery execution finalized; authority wording corrected to distinguish issued attempt from proven execution


**Body:**

Final Slice 6B2 state after review correction: recovery_attempts records immutable issued-attempt lineage and does not by itself claim execution; the separate recovery-execution result and backend run prove execution. The coordinator refuses a non-replacement assessment before child issuance, normalizes missing child authorization to a recovery refusal, refuses a spent claim with no run, returns exact run linkage, and preserves the existing gateway/Verifier/Reviewer/PromotionRecorder path. The real sealed-worker proof remains green: parent VERIFIED_FAIL/OBJECTIONS/PROMOTION_DENIED; assessment REPLACEMENT_CANDIDATE_REQUIRED; separate child completed with VERIFIED_PASS/PASS/PROMOTION_AUTHORIZED/NONE_RECORD_ONLY. Final deterministic verification is 441/441 tests, cis verify 35/35 modules and 24 single-owner authorities, JSON valid, proof DB quick_check ok, git diff check clean. A read-only Claude Opus review executed but its final verdict was not captured, so external acceptance remains pending rather than inferred.


**Evidence refs:** /mnt/projects/cis-clean/runtime/worker-proof/recovery-unit-6b2-attempt2.json; tests:441:PASS; cis-verify:35-selected:24-authorities:PASS


**Source refs:** dev_continuity_events:4.37:34


---

## Revision 36 — `verified_result` — WORKER_SUPERVISOR_UNIT_7A_VERIFIED_GATEWAY_EXECUTION_PENDING

*2026-10-20 00:21:31 · actor: codex*

**Summary:** Append-only worker-supervision plan and attempt-event state machine implemented and verified; runtime dispatch enforcement remains pending Unit 7B


**Body:**

Unit 7A is complete in the recovered cis-clean working tree. cis.execution.worker_supervisor now solely owns immutable worker_supervision_plans and worker_attempt_events. A plan binds an ordered list of distinct existing ALLOW authorizations that independently verify and share objective, transaction, target module and operation; each route fixes positive wall-time, token and cost budgets plus an opaque adapter id. Events enforce ordered STARTED, active-only CHECKPOINT, run-and-evidence-bound SUCCEEDED, closed-taxonomy FAILED, and deterministic CIRCUIT_OPEN transitions. The closed failure set is timeout, budget_exhausted, permission_wait, network_or_provider_failure, empty_or_incomplete_output and invalid_artifacts. Success requires an exact existing completed gateway run and matching admitted evidence, so worker self-report is insufficient. SQL triggers enforce append-only storage and content-addressed identical retries are idempotent while disagreements refuse. This unit records supervision authority only: it does not yet dispatch, terminate a process, retry a route, or claim runtime timeout enforcement. Claude Code was assigned the atomic card but returned a session-limit failure before editing; Codex implemented the unit and independently ran all verification. Evidence: 447/447 tests pass; cis verify reports 36/36 selected contracts and 26 authorities with exactly one owner; git diff check passes. Next bounded unit is gateway-controlled execution over these separately authorized routes with typed failure mapping and enforceable adapter budgets.


**Evidence refs:** tests:447:PASS; cis-verify:36-selected:26-authorities:PASS; dev_continuity_events:4.39:1


**Source refs:** owner_instruction:worker_supervisor; /mnt/projects/cis-clean/src/cis/execution/worker_supervisor.py; /mnt/projects/cis-clean/src/cis/authority/migrations/0012_worker_supervision.sql


---

## Revision 37 — `verified_result` — WORKER_SUPERVISOR_UNIT_7B_VERIFIED_REAL_ADAPTER_PROOF_PENDING

*2026-10-20 01:39:06 · actor: codex_with_claude_code*

**Summary:** Gateway-bound budgets, typed failures, deterministic fallback and interruption-safe recovery implemented and independently verified


**Body:**

Unit 7B is complete in the cis-clean working tree. Claude Code implemented two bounded cards: provider-neutral ExecutionBudget and typed failure vocabulary, then authoritative gateway route binding, measured ExecutionUsage, deterministic fallback, and restart recovery. Codex independently inspected each delta and corrected unbudgeted request-hash compatibility, strict route-budget typing, evidence hash/provenance verification, exact failed-run/evidence binding, and malformed in-memory usage refusal. The gateway derives authorization, adapter and budget only through the verified supervision-route resolver; the caller cannot supply or widen them. A supervised adapter must declare enforcement of wall time, token and cost dimensions, the exact budget is token-covered, missing usage fails closed, and exceeded usage becomes the corresponding typed failure. The coordinator uses distinct preauthorized routes only, never reuses a spent ALLOW, maps the six typed failures to the closed taxonomy, advances only after FAILED, stops on success/circuit/exhaustion, and resumes from terminal events or exact durable gateway run/evidence. A claim without a run becomes empty_or_incomplete_output and is never replayed. Ordinary unbudgeted request and unmetered evidence identities remain byte-compatible. Verification: focused supervisor/execution suites 82 tests pass; full suite 494/494 passes; cis verify reports 36/36 modules and 26 single-owner authorities; git diff check passes. No real external-model adapter is declared budget-enforcing yet and no claim of actual process termination is made. Unit 7C must implement or bind a real terminating adapter, inject timeout/provider/budget/empty-output failures, and produce a real end-to-end supervision proof.


**Evidence refs:** tests:494:PASS; cis-verify:36-selected:26-authorities:PASS; dev_continuity_events:4.37:36


**Source refs:** /mnt/projects/cis-clean/src/cis/execution/worker_supervisor.py; /mnt/projects/cis-clean/src/cis/execution/gateway.py; /mnt/projects/cis-clean/src/cis/execution/port.py


---

## Revision 38 — `verified_result` — WORKER_SUPERVISOR_UNIT_7C_REAL_TERMINATION_AND_FALLBACK_VERIFIED

*2026-10-20 03:24:01 · actor: codex_with_claude_code*

**Summary:** Real contained-worker timeout termination, distinct-authorization fallback, assurance and idempotent replay verified


**Body:**

Unit 7C is complete for the adopted sealed contained-worker adapter. Claude Code implemented bounded production cards; Codex independently inspected, hardened and executed them. contained_worker now declares and enforces the exact supervised budget dimensions: authority-derived wall time is the subprocess bound up to the fixed adapter backstop, while tokens and provider cost are measured as zero because this adapter makes no model/provider call. A timed-out container has a deterministic request-derived name; fixed removal and absence inspection must succeed before the failure may be classified as timeout. Failed removal or inability to prove absence becomes invalid_artifacts. The six-argument frozen invocation, no-network sandbox and ordinary unbudgeted result identity remain intact. The live proof used two distinct ALLOW authorizations for the same work: route 0 started a real sealed nonroot container with an infinite candidate, exceeded its 1000 ms budget, was removed and proven absent, and recorded FAILED/timeout with no fabricated run; route 1 ran the valid candidate in 326 ms, recorded exact usage/run/evidence, passed deterministic Verifier and independent Reviewer, and produced PROMOTION_AUTHORIZED with NONE_RECORD_ONLY. Replaying the coordinator left four events and one backend run unchanged. The live proof exposed and corrected two legitimate compatibility defects: Verifier and Reviewer independently rejected the gateway optional usage envelope; both now accept only the legacy three-field evidence content or that exact envelope plus a closed nonnegative three-field usage mapping, with malformed and extra fields failing closed. Typed provider/network, permission, budget, empty/incomplete and invalid-artifact paths remain covered by deterministic injected tests; no unadopted provider backend or authority was invented. Final verification: 518/518 tests pass, cis verify reports 36/36 selected contracts and 26 authorities with exactly one owner, git diff and JSON checks pass, current baseline 7499e0b816c674a49a0272e187557254f9ae4492836eacaa7c34b3995ce914e2. Nothing was deployed or host-applied.


**Evidence refs:** /mnt/projects/cis-clean/runtime/worker-proof/worker-supervision-unit-7c.json; /mnt/projects/cis-clean/runtime/worker-proof/worker-supervision-unit-7c-authority.sqlite3; tests:518:PASS; cis-verify:36-selected:26-authorities:PASS


**Source refs:** dev_continuity_events:4.37:37; /mnt/projects/cis-clean/tools/prove_worker_supervision.py; /mnt/projects/cis-clean/src/cis/execution/adapters/contained_worker.py


---

## Revision 39 — `verified_result` — WORKER_SESSION_UNIT_8A_SUPERVISOR_BINDING_VERIFIED

*2026-10-20 12:21:16 · actor: codex_with_claude_code*

**Summary:** Governed external-worker sessions and exact model requests are durably bound to verified supervisor routes


**Body:**

Slice 8A is complete in the cis-clean working tree. Claude Code implemented the provider-neutral worker-session authority in bounded cards; Codex independently reviewed each delta, ran the denied compile/test commands, and corrected terminal retry semantics plus reconstruction-status integration. Migration 0013 and cis.execution.worker_session now distinguish immutable session headers, one model request per governed supervision route, and closed lifecycle events. Session opening independently verifies the supervision plan, exact route and ALLOW; request issuance copies the route authorization, adapter and exact wall/token/cost budgets and binds prompt, context and response-schema digests. Lifecycle records external-session continuity, request start, checkpoints, success/failure, suspension and closure, but grants no authority: start requires the supervisor STARTED fact, success requires the exact supervisor SUCCEEDED event plus matching completed backend run/evidence, and failure requires the identical supervisor FAILED classification. External session references and checkpoints remain opaque continuity evidence, never permission. Events are append-only, content-addressed and idempotent; disagreement, forged run/evidence, invalid digest, changed failure class, post-close mutation and request/session mismatch fail closed. The module is contracted and selected as RECONSTRUCTED_IN_SLICE_008A, exported through cis.execution, and README counts were reconciled. Verification: focused worker-session tests 13/13 pass; focused contract/blueprint/surface tests 74/74 pass; full suite 531/531 passes; cis verify reports 37/37 selected contracts and 29 authorities with exactly one owner. Baseline hash f802a350ebddd6db65ef22170ee8729f5bb800bdbd072ea46d529af3487921f4. Nothing was committed, deployed or host-applied.


**Evidence refs:** /mnt/projects/cis-clean/tests/test_worker_session.py; tests:531:PASS; cis-verify:37-selected:29-authorities:PASS


**Source refs:** dev_continuity_events:4.37:38; /mnt/projects/cis-clean/src/cis/execution/worker_session.py; /mnt/projects/cis-clean/src/cis/authority/migrations/0013_worker_sessions.sql


---

## Revision 40 — `contradiction` — WORKER_SESSION_UNIT_8A_EXTERNAL_REVIEW_OBJECTIONS

*2026-10-20 13:18:51 · actor: openrouter_qwen3.7_max_reviewed_by_codex*

**Summary:** Hosted Qwen adversarial review blocks Unit 8A acceptance on session identity contradiction


**Body:**

A true different-lineage read-only adversarial review was run through OpenRouter model qwen/qwen3.7-max against the frozen Unit 8A migration, implementation, tests, contract, integration diff and deterministic evidence. Generation gen-1792502227-jGkrXEPHS14LCRiHDMxA returned OBJECTIONS at cost $0.038805775 with 23,432 prompt and 959 completion tokens and zero reasoning tokens. Material finding 1 is valid: migration 0013 states that a session content address excludes supervision/route so a retry under a disagreeing route fails closed, but open_session currently includes supervision_id and route_index in the semantic input used for session_id. A disagreeing route therefore creates a distinct valid session instead of colliding and refusing as documented. Required reconciliation: separate stable session identity from the full route-binding session hash, or explicitly supersede the documented invariant; architecture intent favors the former. Material finding 2 alleges cross-session request aliasing under the global one-request-per-route constraint. Initial Codex assessment finds the exact alias described unlikely because deterministic session_id and request_id include the session identity: same semantic session returns the same session, while a different role/session changes request_id and is refused. This objection is not dismissed; add a direct two-role/same-route test and require re-review. Unit 8A revision 39 remains historical evidence of deterministic tests but its acceptance status is superseded pending bounded correction, full deterministic verification and re-review by the same external lineage. The earlier Qwen call that returned empty content is not substantive review.


**Evidence refs:** openrouter:generation:gen-1792502227-jGkrXEPHS14LCRiHDMxA; openrouter:model:qwen/qwen3.7-max; openrouter:cost:0.038805775


**Source refs:** dev_continuity_events:4.37:39; /mnt/projects/cis-clean/src/cis/execution/worker_session.py; /mnt/projects/cis-clean/src/cis/authority/migrations/0013_worker_sessions.sql
