# CIS 4.37 — Codex App-Server Architecture Review Packet

## Purpose

Independently assess whether Codex app-server should become the integration boundary for the CIS Brain role, using the user's ChatGPT subscription, without weakening CIS control or breaking the existing Hermes/OpenRouter architecture.

This is an architecture review only. Do not implement or modify CIS.

## Mission and authority

CIS is intended to become a controlled environment for multi-model software work. The durable requirement is enforceable control at the system boundary—not preservation of provisional mechanisms that do not serve that goal.

Current intended roles:

- Codex: Brain/coordinator. It investigates obstacles, explains them, proposes robust or deliberately temporary responses, creates work cards, and routes work. It must not silently jump to a workaround.
- Claude/Menter: implementation and developer tests.
- Deterministic CIS Verifier: independent acceptance tests.
- Qwen: independent review of every implementation and material recovery decision.
- Human operator: final authority, especially for scope, policy, and architecture changes.

Models may review one another. The desired review sequence for this decision is independent Claude and Qwen reviews, cross-review, Codex synthesis, then human decision.

## Current pipeline expectation

The working conceptual flow is:

Human conversation -> Brain deliberation -> Card Factory -> governed execution -> implementation -> deterministic verification -> Qwen review -> acceptance or correction/resubmission.

Hermes is the intended controlled worker harness inside the container. OpenRouter is the current provider path for Qwen. Provider-specific components should sit behind role/controller abstractions.

## Current implementation facts

- The existing worker gateway expects an ALLOW decision before model dispatch.
- The existing gateway budget contract requires wall-time, token, and cost limits.
- Subscription-backed Codex provides usage/token information, but it does not naturally provide a per-turn `cost_micros` equivalent.
- The current Hermes process controller calls an unsupported `hermes oneshot` command and is not yet a working controlled execution path.
- The current Qwen route validates review receipts but does not yet provide a governed Qwen execution controller.
- The repository recognizes a logical BRAIN role.
- At the last inspection, the test suite had 662 tests and 3 known failures: two stale README count assertions and one backend-name leakage assertion.
- Existing CIS work and dirty state must be preserved. No review recommendation should assume a rewrite.

## Candidate use of Codex app-server

Use Codex app-server as a narrow integration adapter for the Brain role—not as a replacement for CIS authority and not as a generic coding-worker adapter.

Potential capabilities include:

- ChatGPT account login, including browser/device authentication.
- Thread and turn lifecycle: create, resume, steer, interrupt, and stream events.
- Structured output schemas.
- Sandbox and approval policies.
- MCP tool configuration, including required MCP servers that can fail closed.
- Local stdio transport. WebSocket support is experimental and should not be assumed production-ready.

Official sources:

- App-server: https://learn.chatgpt.com/docs/app-server
- Codex web search: https://learn.chatgpt.com/docs/web-search
- Codex as a platform: https://developers.openai.com/blog/codex-as-a-platform

## Central architecture questions

1. **Pre-authorization circularity:** The Brain must deliberate before it can create a meaningful work card, but the existing worker gateway requires ALLOW before any model dispatch. Should CIS introduce a separate, narrow Brain-deliberation boundary, or revise the gateway contract?
2. **Authority:** How should CIS ensure that app-server thread state, Goals, approvals, and tool results remain evidence or conversation state rather than becoming CIS authority?
3. **Tool bypass:** What exact sandbox, filesystem, network, MCP, and approval policy prevents the Brain from using built-in tools to bypass CIS execution routes?
4. **Budgets:** Which limits are real and enforceable for a subscription-backed Brain? Should `cost_micros` become optional or provider-specific while wall-time, usage, and turn limits remain enforced?
5. **Session binding:** How should CIS bind a conversation/thread to work cards, receipts, policy versions, interruptions, retries, and recovery decisions?
6. **Correction flow:** When governance rejects Brain output, what structured rejection and resubmission contract forces investigation or an explicitly justified temporary workaround?
7. **Workbench impact:** What existing UI/API assumptions would change? Can the Workbench show streamed Brain activity, obstacle reports, governance rejections, corrections, and final cards without becoming coupled to Codex-specific events?
8. **Provider abstraction:** How do we avoid embedding Codex, Claude, Hermes, Qwen, or OpenRouter names in generic schemas while still preserving provider-specific evidence?
9. **Hermes compatibility:** What remains unchanged for controlled implementation workers inside the container? Does the Brain adapter create any conflict with Hermes controllers or their tool hooks?
10. **Qwen compatibility:** Can OpenRouter/Qwen remain an independent reviewer with its own controller and receipts? What must be built to make that formal rather than advisory?
11. **Migration:** What is the smallest reversible slice that proves Brain deliberation, structured cards, enforcement, observability, and recovery without committing CIS to the entire app-server model?
12. **Failure boundaries:** What happens when authentication expires, the app-server crashes, streaming is interrupted, a required MCP server is missing, usage limits are reached, or output does not match schema?

## Required reviewer research

Use current primary documentation and cite direct URLs. Independently verify:

- Codex app-server authentication, protocol stability, thread lifecycle, structured output, sandboxing, approvals, MCP, and event behavior.
- Whether app-server exposes enforceable usage data and what it does not expose for subscription-backed operation.
- Any constraints that materially affect a long-running CIS Brain integration.
- For your own execution route, disclose whether web research actually worked and list the sources used.

Do not assume this packet's claims are correct merely because they are provided here.

## Requested review output

Return a concise architecture review with:

1. Verdict: `PROCEED`, `PROCEED WITH CONDITIONS`, or `DO NOT PROCEED`.
2. Most important compatibility finding.
3. Fatal or high-risk conflicts, if any.
4. Recommended smallest safe experimental slice.
5. Required CIS contract/schema changes.
6. Workbench effects and compatibility risks.
7. What must remain unchanged in Hermes and Qwen paths.
8. Which decisions should be permanent versus explicitly transitional.
9. Corrections to factual claims in this packet.
10. Cited primary sources and a statement of actual internet-research capability.

Keep independent review separate from implementation. Distinguish verified facts, inference, and recommendation.
