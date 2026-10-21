I'll begin by researching the primary sources cited in the packet and verifying the claims about Codex app-server capabilities.

Now let me research specific aspects critical to the architecture review: authentication, sandboxing, approval policies, and usage/budget controls.

Now I have sufficient primary source material to produce the independent architecture review. Let me compile my findings.

---

# CIS 4.37 — Independent Architecture Review: Codex App-Server as Brain Integration Boundary

**Reviewer:** Qwen (Independent Architecture Review)
**Date:** 2026-10-21
**Method:** Primary-source internet research against official OpenAI documentation, open-source repository artifacts, and engineering blog posts.

---

## 1. Verdict: **PROCEED WITH CONDITIONS**

The Codex app-server is a viable, well-documented integration surface for the CIS Brain role. Its protocol is mature enough for production use (backward compatibility is enforced via CI checks), its thread/goal primitives map naturally to CIS deliberation and card-factory workflows, and its sandbox/approval model provides the technical controls needed to prevent tool bypass. However, five conditions must be met before any implementation commitment:

1. The stdio transport must be the only assumed transport; WebSocket is explicitly unsupported for production.
2. CIS must own all authority state; app-server thread state is evidence, not governance.
3. The Brain adapter must be a narrow, replaceable module behind a role/controller abstraction—never a direct dependency in CIS schemas.
4. Budget enforcement must use wall-time, turn-count, and token-count limits; `cost_micros` must become provider-optional in the gateway contract.
5. The smallest experimental slice must prove structured deliberation output, governance rejection, and correction flow before any broader adoption.

---

## 2. Most Important Compatibility Finding

**The app-server's thread/goal primitive is a near-exact match for CIS Brain deliberation tracking.** The `thread/goal/set` API accepts an `objective` (≤4000 chars), a `tokenBudget`, and tracks `tokensUsed`, `timeUsedSeconds`, and a status lifecycle (`active`, `paused`, `blocked`, `usageLimited`, `budgetLimited`, `complete`). This maps directly to CIS's need for bounded Brain deliberation with observable resource consumption. The goal mechanism is a core runtime concern in the Codex harness—it owns turn lifecycle, tool completion boundaries, interruptions, resume behavior, and token accounting (verified in commit `4167628`).

This is the single most important compatibility finding: CIS does not need to build its own deliberation-budget tracker. It can use the app-server's native goal mechanism as an *observation channel* while retaining CIS's own governance authority over whether deliberation output is accepted.

**Source:** [codex-rs/app-server-protocol/src/protocol/v2/thread.rs](https://github.com/openai/codex/blob/main/codex-rs/app-server-protocol/src/protocol/v2/thread.rs), [commit 4167628](https://github.com/openai/codex/commit/4167628622a0af70374a7a6c44a547a99b5075eb)

---

## 3. Fatal or High-Risk Conflicts

### 3a. No fatal conflicts identified.

### 3b. High-risk conflicts:

**H1: Pre-authorization circularity (Question 1).** The existing CIS worker gateway requires an ALLOW decision before model dispatch, but the Brain must deliberate *before* it can produce a meaningful work card. This is a real architectural tension. The app-server does not solve it—CIS must introduce a separate, narrow **Brain-deliberation boundary** that is distinct from the worker-execution gateway. The deliberation boundary should:
- Allow a single `turn/start` with a constrained `outputSchema` (the deliberation schema)
- Enforce wall-time and turn-count limits at the CIS level (not relying on app-server alone)
- Produce a structured deliberation output that the Card Factory can accept, reject, or request correction on
- Never grant the Brain access to CIS execution tools, file writes, or network

**H2: Authentication session management.** ChatGPT login requires either a browser callback flow or device-code authentication. Tokens are cached in `~/.codex/auth.json` and refreshed automatically during use. However, token expiry, revocation, or workspace policy changes can invalidate sessions. CIS must treat authentication as a **failure boundary** (see §12 below) and must not assume persistent login across container restarts or long idle periods. The device-code flow (PR #15525) is the appropriate path for headless CIS environments.

**H3: Required MCP server failure creates a hard block.** When a `required` MCP server fails to initialize, `thread/start` and `thread/resume` fail entirely (verified in PR #10902, issue #36296). There is currently no recovery mode—Codex Desktop users have been locked out of tasks for ~1 hour due to a single MCP server bug. CIS must either:
- Never mark MCP servers as `required` (accept degraded operation), or
- Implement explicit retry and diagnostic logic at the CIS level, or
- Use the `required` flag deliberately as a fail-closed gate and accept the recovery cost

**H4: Protocol version coupling.** The app-server protocol is backward-compatible (older clients work with newer servers), and a CI check (PR #29509) rejects breaking changes to the stable surface. However, CIS must pin its app-server binary version and generate its TypeScript/JSON schemas from that exact version (`codex app-server generate-ts`, `codex app-server generate-json-schema`). Schema drift between JSON and TypeScript artifacts has been observed (issue #17554). CIS must treat generated schemas as build artifacts, not hand-maintained types.

---

## 4. Recommended Smallest Safe Experimental Slice

The minimum viable experiment should prove **five properties** without committing CIS to the full app-server model:

### Slice definition:

1. **One stdio-connected app-server process** spawned by CIS as a child process, using `--listen stdio://` (the default, stable transport).

2. **One Brain deliberation thread** created via `thread/start` with:
   - `sandboxPolicy: { type: "workspaceWrite", networkAccess: false, writableRoots: [] }` (no file writes, no network)
   - `approvalPolicy: "on-request"` (CIS intercepts and denies all approval requests)
   - `web_search: "disabled"` in config (no web search tool)
   - No MCP servers configured (eliminate MCP failure surface for the experiment)

3. **One structured deliberation turn** via `turn/start` with an `outputSchema` that constrains the Brain's output to a CIS-defined deliberation schema (e.g., `{ obstacle, explanation, proposedResponse, workCards[] }`).

4. **One governance decision** where CIS evaluates the structured output and either:
   - Accepts it (producing work cards for downstream execution), or
   - Rejects it with a structured rejection that triggers a `turn/steer` with correction instructions

5. **One failure boundary test** where the app-server process is killed mid-turn, and CIS demonstrates graceful recovery (thread resume via `thread/resume`, turn interruption via `turn/interrupt`, or clean error reporting).

### What this slice proves:
- Brain deliberation produces structured, schema-constrained output ✓
- CIS governance can accept or reject Brain output ✓
- Correction flow works via `turn/steer` ✓
- Tool bypass is prevented (no network, no file writes, no MCP, all approvals denied) ✓
- Failure recovery is possible ✓

### What this slice does NOT commit CIS to:
- Using app-server for implementation workers (Hermes remains unchanged)
- Using app-server for Qwen review (OpenRouter path remains unchanged)
- Making app-server a permanent dependency (the Brain adapter is a replaceable module)

---

## 5. Required CIS Contract/Schema Changes

### 5a. Gateway contract revision:

The existing worker gateway contract must be split into two boundaries:

| Boundary | Purpose | Pre-authorization | Budget contract |
|----------|---------|-------------------|-----------------|
| **Brain-deliberation boundary** | Brain investigates, explains, proposes | CIS allows a single deliberation turn without a pre-existing work card | Wall-time, turn-count, token-count (from goal tracking). `cost_micros` is **not required**. |
| **Worker-execution boundary** | Claude/Hermes implements, Qwen reviews | Existing ALLOW-before-dispatch contract unchanged | Wall-time, token, cost limits unchanged. `cost_micros` remains required for API-key-backed workers. |

### 5b. `cost_micros` becomes provider-optional:

The gateway budget contract should change from:
```
budget: { wall_time_ms, max_tokens, cost_micros }
```
to:
```
budget: { wall_time_ms, max_tokens, cost_micros?: number, provider_budget?: { token_budget, time_seconds } }
```

For subscription-backed Brain turns, `cost_micros` is absent and `provider_budget` carries the goal-level `tokenBudget` and wall-time limit. For API-key-backed workers (Claude, Qwen via OpenRouter), `cost_micros` remains required.

### 5c. Brain deliberation schema:

A new CIS-internal schema for Brain deliberation output, enforced via `outputSchema` on `turn/start`:

```json
{
  "type": "object",
  "properties": {
    "obstacle": { "type": "string" },
    "explanation": { "type": "string" },
    "proposedResponse": {
      "enum": ["robust_fix", "temporary_workaround", "escalate_to_human"]
    },
    "workCards": {
      "type": "array",
      "items": { "$ref": "#/definitions/WorkCardDraft" }
    },
    "justification": { "type": "string", "description": "Required when proposedResponse is temporary_workaround" }
  },
  "required": ["obstacle", "explanation", "proposedResponse"],
  "additionalProperties": false
}
```

### 5d. Governance rejection schema:

A structured rejection that CIS sends back to the Brain via `turn/steer`:

```json
{
  "type": "object",
  "properties": {
    "rejectionReason": { "enum": ["insufficient_investigation", "unjustified_workaround", "scope_violation", "policy_violation"] },
    "requiredAction": { "type": "string" },
    "resubmissionDeadline": { "type": "string", "format": "date-time" }
  }
}
```

### 5e. Provider abstraction schema:

All CIS-internal schemas must use role-based naming, not provider-specific naming:

| ❌ Do not use | ✅ Use instead |
|---------------|---------------|
| `codex_thread_id` | `brain_session_ref` |
| `openrouter_request_id` | `reviewer_request_ref` |
| `hermes_process_id` | `worker_process_ref` |
| `claude_api_key` | `implementation_provider_credential` |

Provider-specific evidence (thread IDs, request IDs, token counts) is stored in a `provider_evidence` bag attached to the relevant CIS receipt, keyed by provider name. This preserves auditability without coupling schemas to providers.

---

## 6. Workbench Effects and Compatibility Risks

### 6a. What the Workbench can show:

The app-server streams rich events that the Workbench can render:
- `item/started` / `item/agentMessage/delta` / `item/completed` → streamed Brain deliberation text
- `item/commandExecution/requestApproval` → governance interception points (CIS auto-denies)
- `turn/completed` with `status` → deliberation completion, interruption, or failure
- `thread/goal/updated` → live budget consumption (tokens used, time used)
- `thread/status/changed` → thread lifecycle visibility

### 6b. What must NOT change in the Workbench:

- The Workbench must not render app-server events directly. It should consume CIS-normalized events (deliberation_started, deliberation_delta, deliberation_completed, governance_rejected, correction_requested, card_produced).
- The Workbench must not assume Codex-specific event shapes. The Brain adapter module translates app-server events into CIS events.
- The Workbench's existing card view, receipt view, and policy view remain unchanged.

### 6c. Compatibility risks:

- **Event volume:** Brain deliberation can produce many `item/agentMessage/delta` events. The Workbench must handle high-frequency streaming without coupling to Codex-specific delta formats.
- **Thread identity:** The Workbench currently shows work cards and receipts. Adding Brain thread visibility requires a new "deliberation" panel, not modifications to existing card/receipt panels.
- **Offline/disconnected state:** If the app-server process dies, the Workbench must show a clear "Brain disconnected" state, not stale deliberation data.

---

## 7. What Must Remain Unchanged in Hermes and Qwen Paths

### 7a. Hermes (implementation worker):

- **Hermes process controller:** The existing (broken) `hermes oneshot` path is unrelated to the Brain adapter. The Brain adapter does not invoke Hermes. Hermes remains the controlled execution path for implementation workers inside the container.
- **Tool hooks:** Hermes tool hooks (file write, command execution, network access) are governed by CIS, not by the app-server. The Brain adapter's sandbox policy (no writes, no network, no MCP) ensures the Brain cannot reach Hermes-controlled resources.
- **Worker gateway:** The existing ALLOW-before-dispatch contract for Hermes workers is unchanged. The Brain-deliberation boundary is a separate, parallel path.

### 7b. Qwen (independent reviewer via OpenRouter):

- **OpenRouter provider path:** Qwen's review route via OpenRouter remains unchanged. The Brain adapter does not route through OpenRouter.
- **Review receipts:** Qwen review receipts (validated in the existing route) remain the authoritative record of review decisions. The Brain adapter does not produce review receipts.
- **Independence:** Qwen's role as independent reviewer must not be compromised by the Brain adapter. The Brain proposes work cards; Qwen reviews implementation. These are separate roles with separate controllers and separate provider paths.

### 7c. What must be built to formalize Qwen's role:

The packet notes that the current Qwen route "validates review receipts but does not yet provide a governed Qwen execution controller." To make Qwen's role formal rather than advisory, CIS needs:
- A **Qwen execution controller** that wraps OpenRouter API calls with the same budget contract (wall-time, token, cost limits)
- A **review request schema** that structures what Qwen is asked to review
- A **review response schema** that structures Qwen's verdict (accept, reject, request_changes)
- A **review receipt** that records the verdict, evidence, and provider metadata

This is independent of the Brain adapter and should be built regardless of whether the Brain adapter proceeds.

---

## 8. Permanent vs. Explicitly Transitional Decisions

### Permanent decisions:

| Decision | Rationale |
|----------|-----------|
| CIS owns all authority state | App-server thread state is evidence, not governance. This is a durable architectural principle. |
| Role/controller abstraction for all model providers | Prevents provider lock-in. Codex, Claude, Qwen, Hermes are all behind role interfaces. |
| Brain-deliberation boundary is separate from worker-execution boundary | Resolves the pre-authorization circularity. This is a structural decision, not a provisional one. |
| `cost_micros` is provider-optional | Subscription-backed providers don't expose per-turn cost. This is a durable reality. |
| Structured output schemas for Brain deliberation | Enforces the "no silent workarounds" principle. |

### Explicitly transitional decisions:

| Decision | Transition trigger | Exit criteria |
|----------|-------------------|---------------|
| Using Codex app-server specifically for the Brain role | If a better Brain provider emerges, or if OpenAI changes subscription terms | Brain adapter is replaceable; CIS schemas don't reference Codex |
| stdio transport for app-server | If WebSocket transport becomes production-supported | Re-evaluate when WebSocket is no longer "experimental and unsupported" |
| Device-code authentication for headless CIS | If OpenAI introduces a service-account or API-key auth path for app-server | Re-evaluate when non-interactive auth is available |
| No MCP servers in the experimental slice | When CIS has a stable MCP server that the Brain needs | Add MCP servers one at a time with explicit failure handling |
| `web_search: "disabled"` for Brain | If the Brain needs web search for investigation | Enable only with explicit CIS network policy and domain allowlist |

---

## 9. Corrections to Factual Claims in the Packet

### 9a. Verified claims (no correction needed):

- ✅ "Codex app-server provides usage/token information, but does not naturally provide a per-turn `cost_micros` equivalent." — **Confirmed.** The `account/rateLimits/read` API provides `used_percent` and window metadata, and `thread/goal` tracks `tokensUsed`, but there is no per-turn cost in currency units for subscription-backed usage.
- ✅ "WebSocket support is experimental and should not be assumed production-ready." — **Confirmed.** Documentation explicitly states: "The app-server command and WebSocket transport are experimental and aren't supported for production workloads."
- ✅ "The repository recognizes a logical BRAIN role." — **Confirmed** by the packet's own assertion; not independently verifiable without repository access.
- ✅ "Existing CIS work and dirty state must be preserved." — **Acknowledged as a constraint.**

### 9b. Claims requiring correction or nuance:

- ⚠️ "Local stdio transport" is listed as a capability. **Correction:** stdio is the *default and stable* transport, not merely "local." It is the recommended production transport. The documentation says: "stdio (`--listen stdio://`, default): newline-delimited JSON (JSONL)." Unix socket is also stable. Only WebSocket is experimental.

- ⚠️ "Subscription-backed Codex provides usage/token information" — **Nuance needed:** The usage data available via `account/rateLimits/read` provides rate-limit window snapshots (percentage used, reset time), not granular per-turn token counts. Per-thread token usage is available via `account/tokenUsage/read` with `thread_id` parameter, and goal-level tracking via `thread/goal/get` provides `tokensUsed` and `timeUsedSeconds`. These are different granularity levels and should not be conflated.

- ⚠️ "The current Hermes process controller calls an unsupported `hermes oneshot` command" — **Not independently verifiable** without repository access. Accepted as stated.

- ⚠️ "At the last inspection, the test suite had 662 tests and 3 known failures" — **Not independently verifiable** without repository access. Accepted as stated.

### 9c. Claims the packet does not make but should:

- The packet does not mention that the Codex MCP server (`codex mcp-server`) has been **deprecated and removed**. The documentation states: "The `codex mcp-server` command and standalone `codex-mcp-server` binary have been removed. Use the Codex app server for existing integrations." This eliminates MCP-as-integration-path as an alternative to app-server.
- The packet does not mention that the app-server protocol has an **automated backward-compatibility CI check** (PR #29509) that rejects breaking changes to the stable surface. This is a significant stability guarantee that strengthens the case for proceeding.
- The packet does not mention `thread/fork` as a mechanism for **speculative deliberation branches**. The Brain could fork a thread to explore alternative approaches without polluting the main deliberation history.

---

## 10. Cited Primary Sources and Statement of Internet-Research Capability

### Internet-research capability statement:

Web research **worked successfully**. I fetched and analyzed 8 primary-source web pages and 12+ search result sets from GitHub, OpenAI developer documentation, and OpenAI engineering blog posts. All URLs returned HTTP 200 with full content. No paywalls, bot-detection blocks, or content truncation were encountered.

### Primary sources cited:

| # | Source | URL | Retrieved |
|---|--------|-----|-----------|
| 1 | Codex App Server documentation | https://learn.chatgpt.com/docs/app-server | 2026-10-21 |
| 2 | Web search documentation | https://learn.chatgpt.com/docs/web-search | 2026-10-21 |
| 3 | Codex as a platform (blog) | https://developers.openai.com/blog/codex-as-a-platform | 2026-10-21 |
| 4 | Unlocking the Codex harness (blog) | https://openai.com/index/unlocking-the-codex-harness/ | 2026-10-21 |
| 5 | Sandbox documentation | https://learn.chatgpt.com/docs/sandboxing | 2026-10-21 |
| 6 | Authentication documentation | https://learn.chatgpt.com/docs/auth | 2026-10-21 |
| 7 | Codex SDK documentation | https://learn.chatgpt.com/docs/codex-sdk | 2026-10-21 |
| 8 | Codex pricing | https://developers.openai.com/codex/pricing/ | 2026-10-21 |
| 9 | PR #15525: Device-code login | https://github.com/openai/codex/pull/15525 | 2026-10-21 |
| 10 | PR #8377: outputSchema support | https://github.com/openai/codex/pull/8377 | 2026-10-21 |
| 11 | PR #10902: Required MCP failure | https://github.com/openai/codex/pull/10902 | 2026-10-21 |
| 12 | PR #29509: Protocol compatibility check | https://github.com/openai/codex/pull/29509 | 2026-10-21 |
| 13 | Commit 4167628: Goal core runtime | https://github.com/openai/codex/commit/4167628622a0af70374a7a6c44a547a99b5075eb | 2026-10-21 |
| 14 | Issue #36296: Required MCP recovery | https://github.com/openai/codex/issues/36296 | 2026-10-21 |
| 15 | Issue #14192: Approval response RPC | https://github.com/openai/codex/issues/14192 | 2026-10-21 |
| 16 | Issue #32707: Rate limit bucket visibility | https://github.com/openai/codex/issues/32707 | 2026-10-21 |
| 17 | v2/thread.rs: Goal and token usage types | https://github.com/openai/codex/blob/main/codex-rs/app-server-protocol/src/protocol/v2/thread.rs | 2026-10-21 |
| 18 | v2/account.rs: Rate limit types | https://github.com/openai/codex/blob/27c05a52/codex-rs/app-server-protocol/src/protocol/v2/account.rs | 2026-10-21 |
| 19 | v2/turn.rs: TurnStartParams | https://github.com/openai/codex/blob/main/codex-rs/app-server-protocol/src/protocol/v2/turn.rs | 2026-10-21 |
| 20 | Agent approvals & security | https://learn.chatgpt.com/docs/agent-approvals-security | 2026-10-21 |

---

## Appendix: Answers to the 12 Central Architecture Questions

### Q1: Pre-authorization circularity
**Recommendation:** Introduce a separate Brain-deliberation boundary. Do not revise the worker gateway contract. The deliberation boundary allows a single constrained turn (structured output schema, no tools, no network, no file writes) without a pre-existing work card. The output of deliberation is a structured proposal that the Card Factory evaluates. If accepted, normal work cards enter the existing worker-execution gateway with its ALLOW-before-dispatch contract intact.

### Q2: Authority
**Recommendation:** CIS must treat all app-server state (threads, goals, approvals, tool results) as **evidence and conversation state**, never as CIS authority. Authority resides in: CIS governance decisions (accept/reject), CIS policy versions, CIS work cards, CIS receipts. The Brain adapter translates app-server events into CIS events; CIS never reads authority from app-server state.

### Q3: Tool bypass prevention
**Exact controls:**
- `sandboxPolicy: { type: "workspaceWrite", networkAccess: false, writableRoots: [] }` — no file writes outside empty root set, no network
- `approvalPolicy: "on-request"` — CIS intercepts all approval requests and denies them
- `web_search: "disabled"` in config.toml — no web search tool
- No MCP servers configured — no external tool surface
- CIS responds to all `item/commandExecution/requestApproval` and `item/permissions/requestApproval` with `decline`
- The Brain cannot use `thread/shellCommand` (that API is for user-initiated commands and runs outside the sandbox; CIS must never invoke it for Brain threads)

### Q4: Budgets
**Enforceable limits for subscription-backed Brain:**
- Wall-time: CIS-enforced via process-level timeout on the deliberation turn
- Turn count: CIS-enforced (typically 1 deliberation turn + N correction turns)
- Token count: Observable via `thread/goal/get` → `tokensUsed`, and `account/tokenUsage/read` with `thread_id`
- `cost_micros`: **Not available** for subscription-backed usage. Must become provider-optional in the gateway contract.
- Rate-limit window: Observable via `account/rateLimits/read` (percentage used, reset time). CIS can check this before starting deliberation.

### Q5: Session binding
**Recommendation:** CIS binds a conversation to work cards via:
- `brain_session_ref`: The app-server thread ID, stored in the CIS deliberation record
- `brain_turn_ref`: The turn ID for each deliberation attempt
- `brain_goal_ref`: The goal objective hash, linking deliberation to a specific investigation scope
- CIS work cards reference the deliberation record, not the app-server thread directly
- Policy version is recorded in the deliberation record at the time of the turn
- Interruptions are recorded as CIS events, not app-server events
- Retries increment a CIS retry counter on the deliberation record

### Q6: Correction flow
**Structured rejection and resubmission contract:**
1. CIS evaluates Brain output against the deliberation schema and governance policy
2. If rejected, CIS sends a `turn/steer` with a structured rejection message (rejection reason, required action, deadline)
3. The Brain must produce a new structured output that addresses the rejection
4. If the Brain produces a `temporary_workaround` without a `justification` field, CIS rejects again
5. After N rejections (configurable, recommend 2), CIS escalates to the human operator
6. All rejections and resubmissions are recorded in the CIS deliberation record

### Q7: Workbench impact
See §6 above. Summary: The Workbench gains a "deliberation" panel showing streamed Brain activity, governance decisions, and correction cycles. Existing card/receipt/policy views are unchanged. The Workbench consumes CIS-normalized events, not app-server events directly.

### Q8: Provider abstraction
See §5e above. Summary: All CIS schemas use role-based naming (`brain_session_ref`, `reviewer_request_ref`, `worker_process_ref`). Provider-specific evidence is stored in a `provider_evidence` bag keyed by provider name.

### Q9: Hermes compatibility
See §7a above. Summary: The Brain adapter creates no conflict with Hermes. They operate on separate boundaries (deliberation vs. execution), use separate transports (app-server stdio vs. Hermes process controller), and have separate tool hooks.

### Q10: Qwen compatibility
See §7b-c above. Summary: OpenRouter/Qwen remains an independent reviewer with its own controller path. To make this formal, CIS needs a Qwen execution controller, review request/response schemas, and review receipts. This is independent of the Brain adapter.

### Q11: Migration (smallest reversible slice)
See §4 above. Summary: One stdio app-server process, one deliberation thread, one structured turn, one governance decision, one failure test. This proves the concept without committing CIS to the full app-server model.

### Q12: Failure boundaries

| Failure mode | Behavior | CIS response |
|-------------|----------|-------------|
| Authentication expires | App-server returns auth error on next API call | CIS records auth failure, alerts human operator, does not retry automatically |
| App-server crashes | stdio pipe closes, process exits | CIS detects process exit, records failure, attempts one restart with `thread/resume`, escalates if restart fails |
| Streaming interrupted | `turn/completed` with `status: "interrupted"` | CIS records interruption, evaluates partial output if available, may retry |
| Required MCP missing | `thread/start` fails | CIS records MCP failure, alerts human operator (in experimental slice, no MCP servers are configured) |
| Usage limits reached | `account/rateLimits/read` shows 100% used, or goal status becomes `usageLimited`/`budgetLimited` | CIS records limit reached, escalates to human operator, does not attempt to purchase credits |
| Output doesn't match schema | App-server enforces `outputSchema`; non-conforming output is a protocol error | CIS records schema violation, treats as governance rejection, may retry once |
| WebSocket unavailable | Not applicable—CIS uses stdio only | N/A |

---

*End of independent architecture review. This review is separate from implementation and should be cross-reviewed by Claude before Codex synthesis and human decision.*
