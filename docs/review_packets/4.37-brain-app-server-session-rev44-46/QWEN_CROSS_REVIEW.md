Now let me search for additional details on specific claims and potential gaps.

Now let me verify one more detail about the `thread/inject_items` method and the Codex SDK for completeness.

---

# Qwen Cross-Review of Claude's Independent Architecture Review

## CIS 4.37 — Codex App-Server as Brain Integration Boundary

---

## 1. Overall Assessment of Claude's Review

Claude's review is **substantively strong** on the primary containment question. The web-search hosted-tool bypass finding is correct, important, and well-sourced. The WebSocket security characterization is accurate. The cost_micros confirmation and goal-enforcement analysis are sound.

However, Claude **missed at least two additional sandbox-bypass vectors** that are documented in the same primary source it fetched, and **understated the MCP stability risk** for long-running operation. These gaps materially affect the safety of the recommended experimental slice.

---

## 2. Agreements — Verified Against Primary Sources

### 2.1 Web search bypasses sandbox network policy ✅
**Claude's claim:** web_search is a hosted tool, separate from sandboxed local command networking, does not use the permission profile's network proxy or domain allowlist, and is enabled by default in cached-index mode.

**Primary source confirmation (learn.chatgpt.com/docs/web-search):**
> "Web search is a hosted tool, separate from sandboxed local command networking. It does not use the permission profile's network proxy or domain allowlist, and it can remain available when command network access is disabled."

> "For local Codex chats, Codex enables cached search by default."

**Additional corroboration (learn.chatgpt.com/docs/agent-approvals-security):**
> "The network proxy filters scripts, programs, and child processes that run inside the local command sandbox. It does not filter web search, app or connector tool calls, MCP server connections, browser or Computer Use activity, Codex cloud tasks, or the client's model and authentication requests."

This last quote is broader than Claude's finding and introduces additional bypass surfaces Claude did not enumerate (see §3.1).

### 2.2 WebSocket non-loopback unauthenticated ✅
**Claude's claim:** "non-loopback WebSocket listeners currently allow unauthenticated connections by default during rollout."

**Primary source confirmation (learn.chatgpt.com/docs/app-server):**
> "Non-loopback WebSocket listeners currently allow unauthenticated connections by default during rollout, so configure WebSocket auth before exposing one remotely."

Claude's recommendation to strengthen the packet's language from "not production-ready" to a security issue is correct.

### 2.3 WebSocket experimental and unsupported ✅
**Primary source:** "The app-server command and WebSocket transport are experimental and aren't supported for production workloads."

Note: the doc uses "unsupported," which is stronger than Claude's "experimental." stdio is the default and stable transport. Unix socket is also production-ready. Claude's stdio-only recommendation is correct.

### 2.4 No per-turn cost_micros ✅
**Primary source confirmation (learn.chatgpt.com/docs/auth):** Subscription access uses ChatGPT workspace permissions and plan credits. API key access uses standard API pricing. No per-turn dollar figure is documented for subscription-backed operation.

The goal object exposes `tokenBudget`, `tokensUsed`, and `timeUsedSeconds` — token and wall-time accounting only, no monetary equivalent.

### 2.5 Goal enforcement is cooperative, not an external enforcement wall ✅
**Primary source confirmation (GitHub commit 4167628622a):**
> "Treats token budget exhaustion as a soft stop by marking the goal `budget_limited` and injecting wrap-up steering instead of aborting the active turn."

**Source code confirmation (budget_limit.md prompt template):**
> "The system has marked the goal as budget_limited, so do not start new substantive work for this goal. Wrap up this turn soon."

This is a steering prompt, not a hard cutoff. Claude correctly identified this as cooperative enforcement that must not substitute for CIS gateway authority.

### 2.6 Required MCP fails closed at thread/start and thread/resume ✅
**Primary source (app-server doc):**
> "If you mark an enabled MCP server as `required` in config and that server fails to initialize, `thread/start` and `thread/resume` fail instead of continuing without it."

**GitHub PR #10902:** "have `codex exec` and `codex app-server` thread start/resume fail fast when required MCPs fail to initialize."

Claude correctly flagged this. However, Claude noted mid-thread MCP failure as "untested" — see §3.3 for documented evidence that this is worse than untested.

### 2.7 outputSchema is per-turn and enforced via structured outputs ✅
**Primary source (GitHub PR #8377):**
> "V2 `turn/start` now accepts `outputSchema` and constrains the final assistant message for that turn (explicitly per-turn only)."

Integration tests confirm the schema is forwarded as `text.format` with `strict: true` to the Responses API and does not leak to subsequent turns. Claude's recommendation to use outputSchema for work-card payloads is technically sound.

### 2.8 Approval policy values ✅
Valid string values confirmed from source code: `untrusted`, `on-failure`, `on-request`, `never`, plus experimental `granular` object form. Note: `untrusted` is **retired** in current clients and can prevent startup (see §3.5).

---

## 3. Critical Gaps — What Claude Missed

### 3.1 `thread/shellCommand` — Full sandbox bypass (HIGH severity)

**This is the most important finding Claude missed.** The app-server documentation Claude fetched contains this explicit statement:

> **`thread/shellCommand`** — run a user-initiated shell command against a thread. **This runs outside the sandbox with full access and doesn't inherit the thread sandbox policy.** Clients should expose it only for explicit user-initiated commands.

This is not a configuration default or a side effect — it is a **by-design full-access escape hatch**. GitHub issue #37076 confirms with source code citations:

> `sandbox: SandboxType::None` — the command never runs under the configured sandbox policy.
> `PermissionProfile::Disabled`.
> Comment: "`/shell` is the explicit full-access escape hatch, so it must not inherit a managed proxy from the surrounding session or turn."

**Impact on Claude's recommended slice:** Claude's slice specifies `sandbox.workspaceWrite` with `networkAccess:false`, `web_search:"disabled"`, and `approvalPolicy:onRequest`. Even with all of these set, if the CIS adapter does not block or filter `thread/shellCommand` at the protocol level, the Brain (or any prompt injection that reaches the model) can invoke arbitrary unsandboxed shell commands with full filesystem and network access.

**Required mitigation:** The CIS adapter must either:
- Refuse to forward `thread/shellCommand` requests from the Brain thread, or
- Treat any `thread/shellCommand` invocation as a governance violation requiring human approval.

This is a **protocol-level filter requirement**, not a configuration setting.

### 3.2 `process/spawn` — Experimental unsandboxed process execution (MEDIUM severity)

The app-server doc states:
> "`process/*` is an experimental, explicit process-control API. It requires `capabilities.experimentalApi = true` and **runs outside Codex's sandbox.** Use it only when your client intentionally exposes local process control without a sandbox."

GitHub PR #19040 confirms: "Made `process/spawn` intentionally unsandboxed and omitted sandbox-selection fields such as `sandboxPolicy` and `permissionProfile`."

**Mitigation:** Do not set `capabilities.experimentalApi = true` in the CIS adapter's `initialize` handshake. This blocks `process/spawn` and several other experimental methods. Claude did not mention this capability gate.

### 3.3 MCP mid-session failure can crash the entire app-server process (HIGH severity for long-running operation)

Claude flagged mid-thread MCP failure as "untested." It is worse than untested — it is a **documented crash vector**:

**GitHub issue #40766:** When an OAuth-backed MCP server returns `401` (expired token) mid-session, "the rmcp transport worker terminates fatally and takes down the **entire `codex` app-server process** — not just that one MCP session." The resulting state corruption leaves the thread permanently stuck with `markedStreaming=true`, blocking all future turns. Recovery requires hand-editing `config.toml`.

**GitHub issue #45379:** A local plugin MCP handshake failure causes the desktop app to enter a restart loop.

**GitHub issue #16271:** "Any Single Engine Crash Leaves Orphaned Threads That Cause a Persistent Crash/Resume Loop." Any unexpected engine exit (MCP failure, OOM, etc.) can trigger an infinite crash/resume cycle requiring manual state database deletion.

**Impact on CIS:** A long-running Brain integration is exactly the use case most exposed to mid-session MCP auth expiry and process crashes. The CIS adapter must:
- Detect app-server process death and initiate clean recovery.
- Never assume a thread is safely resumable after an unexpected process exit without state validation.
- Treat MCP auth tokens as time-bounded resources requiring proactive refresh.

### 3.4 `thread/inject_items` — Model history manipulation without a user turn (MEDIUM severity)

The app-server doc states:
> `thread/inject_items` — append raw Responses API items to a loaded thread's model-visible history without starting a user turn.

This allows injecting arbitrary assistant-role messages into the model's prompt history without going through the normal turn lifecycle. If the CIS adapter does not filter this method, a compromised or confused Brain could inject fabricated "prior reasoning" into its own context, undermining the integrity of the deliberation record.

**Mitigation:** The CIS adapter should either block `thread/inject_items` or log and audit every injection as a governance event.

### 3.5 `untrusted` approval policy is retired (LOW severity, configuration trap)

The approvals doc states:
> "Codex and ChatGPT Work no longer support `approval_policy = "untrusted"`. The retired setting can prevent either client from starting."

If CIS configuration or any code path references `untrusted`, it will fail at startup. The valid values for current deployments are `on-request`, `on-failure`, and `never` (plus `granular` object form). Claude did not flag this.

### 3.6 Network proxy does not filter MCP server connections (MEDIUM severity)

From the approvals doc (quoted in §2.1):
> "It does not filter web search, app or connector tool calls, **MCP server connections**, browser or Computer Use activity..."

Claude identified web_search as a network bypass but did not note that MCP server connections also bypass the network proxy. If CIS relies on the network proxy to restrict which hosts the Brain can reach, MCP server connections to arbitrary hosts are not filtered. This is relevant to question 3 (tool bypass) in the packet.

---

## 4. Corrections to Claude's Review

| # | Claude's Statement | Correction |
|---|---|---|
| 1 | Recommended slice uses `approvalPolicy:onRequest` | The kebab-case form `on-request` is the wire-protocol value. The app-server JSON-RPC layer may accept camelCase, but CIS should use the canonical form to avoid ambiguity. |
| 2 | "Open question, not yet verified: behavior if a required server dies mid-thread" | This is not merely untested — it is a **documented crash vector** that kills the entire app-server process (issue #40766). CIS must plan for this as a known failure mode, not an open question. |
| 3 | Recommended slice does not mention `thread/shellCommand` | The slice must explicitly block or filter `thread/shellCommand` at the protocol level, or the sandbox configuration is meaningless. |
| 4 | Recommended slice does not mention `experimentalApi` capability gate | The `initialize` handshake must explicitly set `experimentalApi: false` (or omit it) to block `process/spawn` and other experimental unsandboxed methods. |
| 5 | "Nothing here touches the Hermes controller" | Correct, but the adapter must also ensure that the app-server process lifecycle (crashes, restarts, auth refresh) does not interfere with concurrent Hermes execution in the same container. |

---

## 5. Corrections to the Original Packet

| # | Packet Claim | Correction |
|---|---|---|
| 1 | "WebSocket support is experimental and should not be assumed production-ready" | Understated. The docs say "experimental and **unsupported**" and "non-loopback WebSocket listeners currently allow **unauthenticated connections** by default." This is a security defect, not a maturity caveat. |
| 2 | "Subscription-backed Codex provides usage/token information, but it does not naturally provide a per-turn `cost_micros` equivalent" | Confirmed, but should be stated more precisely: no dollar cost is exposed at all under OAuth auth. Only token counts and wall-time via `thread/goal`. |
| 3 | Packet does not mention `thread/shellCommand` | This is a documented full-access sandbox bypass that must be in the tool-bypass analysis (Q3). |
| 4 | Packet does not mention `thread/inject_items` | This allows model history manipulation without a user turn — relevant to authority and evidence integrity (Q2). |
| 5 | Packet does not mention MCP mid-session crash risk | Documented failure mode that kills the entire app-server process — relevant to failure boundaries (Q12). |

---

## 6. Revised Verdict

### **PROCEED WITH CONDITIONS** (strengthened)

Claude's verdict is correct but the conditions must be expanded. The integration is technically feasible, and the core protocol (stdio, thread/turn lifecycle, outputSchema, required MCP fail-closed at startup) works as described. However, the containment surface has **more bypass vectors than Claude identified**, and the MCP stability risk for long-running operation is a known defect class, not a theoretical concern.

### Mandatory conditions before the Brain boundary can be trusted:

1. **Protocol-level method filter.** The CIS adapter must maintain an explicit allowlist of app-server methods. At minimum, `thread/shellCommand`, `process/spawn`, `thread/inject_items`, and all `experimentalApi`-gated methods must be blocked or require human approval. This is not optional — without it, sandbox configuration is a suggestion, not a boundary.

2. **Web search disabled.** `web_search = "disabled"` in config, verified at adapter startup.

3. **MCP auth lifecycle management.** Any OAuth-backed MCP server must have proactive token refresh. The adapter must detect app-server process death and implement clean thread recovery (not blind resume).

4. **`experimentalApi` must remain `false`** (or omitted) in the `initialize` handshake.

5. **Goal enforcement is advisory.** CIS must implement its own token and wall-time metering externally. The app-server `thread/goal` mechanism is a cooperative steering tool, not an enforcement boundary.

6. **cost_micros is optional/provider-nullable** in the CIS budget contract. Wall-time and token counts remain the enforceable minimum.

---

## 7. Revised Smallest Safe Experimental Slice

Building on Claude's recommendation with the additional conditions:

- One local **stdio-only** app-server process.
- ChatGPT OAuth login.
- `initialize` with `experimentalApi` omitted (defaults to false).
- Single thread per Brain deliberation.
- `sandbox: "workspace-write"` with `networkAccess: false`.
- `approvalPolicy: "on-request"`.
- `web_search: "disabled"` in config.toml.
- Exactly one CIS-owned **required** MCP server (the only tool surface, wired to Card Factory).
- `outputSchema` enforced for the work-card payload.
- **Protocol-level method allowlist** in the adapter: only `thread/start`, `thread/resume`, `turn/start`, `turn/steer`, `turn/interrupt`, `thread/goal/set`, `thread/goal/get`, `mcpServerStatus/list`, `model/list`, and read-only thread/item listing methods. All other methods rejected at the adapter before reaching app-server.
- **App-server process health monitor** with crash detection and clean recovery (not blind thread resume).
- Every app-server event logged as evidence only — no direct repo-write capability granted to the thread.
- Prove deliberation → structured card → gateway ALLOW → Hermes execution, including interrupt/resume and app-server crash recovery, before widening scope.

---

## 8. Decisions Eric Should Make Next

### Permanent decisions (make now, do not revisit):

1. **Separate DELIBERATE boundary.** Introduce a narrow Brain-deliberation decision distinct from the worker-gateway ALLOW. This resolves Q1 (pre-authorization circularity) without weakening the dispatch contract.

2. **Provider/role abstraction.** No provider names (Codex, Claude, Hermes, Qwen, OpenRouter) in generic schemas. Provider-specific evidence goes in typed extension fields.

3. **cost_micros is optional.** The budget contract makes cost optional/provider-specific. Wall-time and token counts are the enforceable minimum for all providers.

4. **App-server events are evidence, never authority.** Thread state, goals, approvals, and tool results from app-server are conversation state — CIS governance decisions remain authoritative.

### Transitional decisions (explicitly time-bounded, review after experimental slice):

5. **Web search fully disabled** until a reviewed domain allowlist exists and the adapter can enforce it.

6. **stdio-only transport** until WebSocket is officially production-supported with mandatory authentication.

7. **App-server goal/tokenBudget as interim signal** pending CIS's own external token metering.

8. **Single MCP server only** (the Card Factory tool) until the adapter's method filter and MCP stability handling are proven.

### Immediate next actions:

9. **Build the protocol-level method filter** before any Brain thread is started. This is the single highest-priority implementation task — without it, no other containment measure is reliable.

10. **Design the crash recovery path** for app-server process death: what happens to in-flight deliberations, how does CIS detect the failure, and how does it recover without blind thread resume.

11. **Decide whether `thread/inject_items` has any legitimate CIS use case.** If not, block it permanently. If yes, define the governance contract around it.

---

## 9. Research Capability Statement

Web research worked fully this session. I fetched and read four primary documentation pages in full (app-server, web-search, auth, codex-as-a-platform) plus the agent-approvals-security page. I conducted six targeted web searches that returned GitHub issues, pull requests, source code excerpts, and community SDK documentation. All claims in this cross-review are attributed to specific fetched sources. Where I could not verify a claim (e.g., CIS-internal test counts, Hermes process controller state), I said so explicitly.

### Primary sources directly fetched:
- https://learn.chatgpt.com/docs/app-server
- https://learn.chatgpt.com/docs/web-search
- https://learn.chatgpt.com/docs/auth
- https://developers.openai.com/blog/codex-as-a-platform
- https://learn.chatgpt.com/docs/agent-approvals-security

### Secondary sources from web search (GitHub issues, PRs, source code):
- GitHub PR #10902 (required MCP fail-closed)
- GitHub issue #37076 (thread/shellCommand sandbox bypass confirmed in source)
- GitHub issue #40766 (mid-session MCP auth crash kills app-server)
- GitHub issue #45379 (MCP handshake failure restart loop)
- GitHub issue #16271 (orphaned thread crash/resume loop)
- GitHub issue #25569 (approvalPolicy valid values)
- GitHub PR #8377 (outputSchema per-turn enforcement)
- GitHub PR #19040 (process/spawn unsandboxed by design)
- GitHub commit 4167628622a (goal budget_limited soft-stop behavior)
- GitHub source: codex-rs/app-server-protocol/src/protocol/v2/thread.rs (ThreadGoalStatus enum)
- GitHub source: codex-rs/core/src/goals.rs (goal accounting and budget steering)
- GitHub source: codex-rs/prompts/templates/goals/budget_limit.md (budget limit prompt template)
- EMSI codex-app-server-sdk docs (approval_policy and sandbox values)
