## CIS 4.37 Architecture Review — Codex App-Server as Brain Integration Boundary

### 1. Verdict
**PROCEED WITH CONDITIONS.** The integration is technically sound (ChatGPT-OAuth login, structured outputs, fail-closed required MCP, stable stdio transport all exist and work roughly as the packet describes), but two gaps — a hosted tool that bypasses sandbox network policy, and the absence of any per-turn cost figure — must be closed in the adapter contract before the Brain boundary can be trusted with CIS authority.

### 2. Most important compatibility finding
Codex's built-in **web_search tool is a hosted tool, separate from sandboxed local command networking — it does not use the permission profile's network proxy or domain allowlist**, and it is **enabled by default** in cached-index mode ([learn.chatgpt.com/docs/web-search](https://learn.chatgpt.com/docs/web-search)). This means a Brain thread configured with `sandbox.workspaceWrite.networkAccess = false` can still reach the network through web_search unless `web_search = "disabled"` (or a restrictive `allowed_web_search_modes`) is set explicitly. This is the central fact for question 3 (tool bypass) and is more consequential than most other findings — sandbox policy alone is not a network boundary.

### 3. Fatal or high-risk conflicts
- **Tool bypass (high):** as above. Fix: CIS's adapter config must force `web_search = "disabled"` (or an explicit allowlist), and CIS must verify this is enforced centrally rather than left to per-thread defaults.
- **WebSocket exposure (high, if ever used):** "The app-server command and WebSocket transport are experimental and aren't supported for production workloads," and "non-loopback WebSocket listeners currently allow unauthenticated connections by default during rollout" ([learn.chatgpt.com/docs/app-server](https://learn.chatgpt.com/docs/app-server)). This is stronger than the packet's "should not be assumed production-ready" — it's a real auth gap, not just a maturity caveat. CIS must use **stdio only** (stable) or the Unix-socket transport (production-ready); never a non-loopback WebSocket listener.
- **No per-turn cost (confirmed, medium):** OAuth/ChatGPT-managed auth tracks usage against workspace/plan credits with no documented dollar or `cost_micros` figure per turn ([learn.chatgpt.com/docs/auth](https://learn.chatgpt.com/docs/auth)); the app-server's only exposed budget primitive is token-based (`thread/goal` → `tokenBudget`/`tokensUsed`). This confirms the packet's claim.
- **Authority/naming collision (medium):** app-server has its own native `goal` object with states including `budget_limited`. This is **self-reported/cooperative** enforcement inside the model's own loop, not an external enforcement wall equivalent to the CIS gateway's ALLOW decision. It must never be treated as a substitute for gateway enforcement, and CIS's own "Goals" concept should not be conflated with app-server's `thread/goal` in schemas or logs.
- **Open question, not yet verified:** documented behavior covers a required MCP server failing at `thread/start`/`thread/resume` (fails closed); behavior if a required server dies *mid-thread* is not documented in what I could fetch — treat as untested, not assumed safe.

### 4. Recommended smallest safe experimental slice
One local stdio-only app-server process, ChatGPT OAuth login, single thread per Brain deliberation, `sandbox.workspaceWrite` with `networkAccess:false`, `approvalPolicy:onRequest`, `web_search:"disabled"`, exactly one CIS-owned required MCP server (the only tool surface, wired to Card Factory), `outputSchema` enforced for the work-card payload. Treat every app-server event as logged evidence only — no direct repo-write capability granted to the thread. Prove deliberation → structured card → gateway ALLOW → Hermes execution, including interrupt/resume, before widening scope.

### 5. Required CIS contract/schema changes
- A narrow **DELIBERATE** decision distinct from the existing worker-gateway **ALLOW**, so card-creation can proceed without touching the dispatch contract (answers Q1).
- Make `cost_micros` **optional/provider-nullable** in the budget contract; keep wall-time and token counts as the enforceable minimum for subscription-backed providers.
- Add session-binding fields (threadId, turnId, policy version, app-server goalId) to cards/receipts, explicitly as evidence/foreign keys, never as authority.
- A structured rejection/resubmission schema: reason code + required response type (investigate vs. explicitly-justified temporary workaround) the Brain must satisfy before a new card is accepted.

### 6. Workbench effects and compatibility risks
App-server events (`turn/started`, `item/agentMessage/delta`, tool progress) can feed Workbench, but must be normalized at the adapter into CIS's existing generic activity/obstacle/card vocabulary — raw app-server method names should never reach the generic API. Main risk: Workbench currently likely assumes a single Hermes-shaped event stream; it needs a second normalized producer, built once in the adapter, not duplicated in Workbench.

### 7. What must remain unchanged in Hermes/Qwen paths
Nothing here touches the Hermes controller, its tool hooks, or the pre-existing `hermes oneshot` defect — the Brain adapter is a new, separate controller, not a modification of Hermes. Qwen/OpenRouter keeps its independent controller and receipt validation unchanged; no shared code path should force simultaneous edits to either.

### 8. Permanent vs. transitional
**Permanent:** provider/role abstraction with no provider names in generic schemas; a separate Brain-deliberation boundary; cost as optional/provider-specific.
**Transitional:** using app-server's native `goal`/`tokenBudget` as an interim signal pending CIS's own token metering; `web_search` fully disabled until a reviewed allowlist exists; stdio-only transport pending official WebSocket production support (if it ever arrives).

### 9. Corrections to the packet
- The claim about missing `cost_micros` is confirmed, but should be stated more precisely: no dollar cost is exposed at all under OAuth auth — only token counts via `thread/goal`.
- The WebSocket caution should be strengthened from "not production-ready" to "non-loopback listeners are unauthenticated by default during rollout" — a security issue, not merely a maturity one.
- The packet does not mention the web_search hosted-tool network bypass; this is a new, high-priority finding that should be added to the tool-bypass analysis (Q3), as it's arguably the single biggest containment gap.

### 10. Sources and research-capability statement
Web research worked this session via both WebFetch (direct document retrieval with quotes) and WebSearch (secondary corroboration). Primary sources directly fetched:
- [learn.chatgpt.com/docs/app-server](https://learn.chatgpt.com/docs/app-server) — protocol, thread/turn lifecycle, sandbox/approval policy, MCP, transport, goal/budget fields
- [developers.openai.com/blog/codex-as-a-platform](https://developers.openai.com/blog/codex-as-a-platform) — high-level framing (less detailed than expected; confirmed `developers.openai.com/codex/app-server` 308-redirects to the same `learn.chatgpt.com/docs/app-server` page)
- [learn.chatgpt.com/docs/web-search](https://learn.chatgpt.com/docs/web-search) — hosted web_search tool, network-bypass behavior
- [learn.chatgpt.com/docs/auth](https://learn.chatgpt.com/docs/auth) — ChatGPT OAuth vs API-key auth, token storage/refresh, usage-vs-billing distinction

Secondary, lower-confidence sources surfaced via WebSearch snippets (not independently fetched/verified in full): GitHub discussions/issues on Codex goal/token-budget behavior, SSD Nodes, continuumcode.ai, hexdocs.pm (codex_sdk docs), community.openai.com threads. Treat anything attributed only to these as **inference-level**, not verified — recommend Claude/Qwen reviewers independently fetch the primary pages above rather than relying on this summary.
