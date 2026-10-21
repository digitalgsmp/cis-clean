# Cross-Review of Qwen's Independent Architecture Review

I verified Qwen's specific technical claims (PR/issue/commit citations, API field names, transport/MCP/auth behavior) against primary sources, and compared Qwen's analysis against the existing `CLAUDE_INDEPENDENT_REVIEW.md` already in this directory (apparently my own prior independent pass, done separately as the packet's process requires).

## Agreements (Qwen, Claude's prior review, and verified sources converge)

- **Separate Brain-deliberation boundary, don't touch the worker gateway.** Both reviews land on this for Q1, independently. Sound.
- **`cost_micros` must become provider-optional**, not removed — confirmed by primary sources: subscription auth exposes only token/rate-limit data (`account/rateLimits/read`, `thread/goal.tokensUsed`), never a dollar figure.
- **CIS owns authority; app-server state is evidence only.** Both reviews agree; this is the correct durable principle.
- **Required MCP servers fail closed at `thread/start`/`thread/resume`.** Verified true via [PR #10902](https://github.com/openai/codex/pull/10902) and [issue #36296](https://github.com/openai/codex/issues/36296) (a real user reported ~1hr lockout — Qwen's specific number is accurate).
- **stdio, not WebSocket, for CIS's transport choice.** Both reviews converge here, for different but compatible reasons (see below).
- **No fabricated citations.** I checked essentially every PR/issue/commit Qwen cited by number — they all exist and say roughly what Qwen claims. This was my biggest concern going in, and it's unfounded. Qwen's sourcing discipline is good.

## Disagreements and where the evidence lands

**1. Qwen's "most important compatibility finding" is not the most important one — and it missed a real tool-bypass gap.**
Qwen's headline finding is that `thread/goal` conveniently matches CIS's deliberation-budget tracking. Claude's prior review instead flagged that **`web_search` is a hosted tool that bypasses sandbox network isolation entirely and is enabled by default** in cached/indexed mode. I verified this directly against the docs:

> "Web search is a hosted tool, separate from sandboxed local command networking. It does not use the permission profile's network proxy or domain allowlist." / "For local Codex chats, Codex enables cached search by default." — [learn.chatgpt.com/docs/web-search](https://learn.chatgpt.com/docs/web-search)

Qwen *does* include `web_search: "disabled"` in its experimental-slice config (§4) and tool-bypass answer (Q3), so the mitigation is present — but Qwen never explains **why** it's necessary: `sandboxPolicy.networkAccess: false` does *not* cover this tool. Given Q3 ("tool bypass") is explicitly the packet's central safety question, this is a material gap in Qwen's risk reasoning, not just a stylistic omission. Claude's framing is correct and should take priority in synthesis.

**2. Qwen overstates app-server's production-readiness.**
Qwen's verdict rests partly on "the protocol is mature enough for production use" and treats stdio as "the recommended production transport." The primary documentation's actual, literal language is broader and more cautious:

> "The app-server command and WebSocket transport are experimental and aren't supported for production workloads." — [learn.chatgpt.com/docs/app-server](https://learn.chatgpt.com/docs/app-server), corroborated by the [Codex changelog](https://learn.chatgpt.com/docs/changelog)

This sentence, read plainly, puts the **entire app-server command** under an experimental/unsupported-for-production disclaimer — not only WebSocket. Secondary sources suggest a resolvable nuance (a transport-level *wire-format* stability table marks stdio "Stable" and WebSocket "Experimental," which is a separate axis from the blanket product-support disclaimer), but I could not fully confirm OpenAI has retracted or scoped down the blanket disclaimer. Qwen's "correction" to the packet (framing stdio as simply "the default and stable transport") swings too far toward reassurance. Claude's review preserves the distinction more faithfully by quoting the disclaimer verbatim rather than paraphrasing around it.

**Practical effect:** this doesn't change the recommended transport choice (stdio either way), but it does change what Eric is actually approving — adopting a vendor-labeled experimental, not-production-supported interface as a boundary feeding a governance system. That should be named explicitly, not softened.

**3. Qwen's WebSocket risk is miscategorized (minor, since recommendation is unaffected).**
Qwen treats WebSocket as a maturity/support issue. Verified primary-source fact: it's also a live authentication gap —

> "Non-loopback WebSocket listeners currently allow unauthenticated connections by default during rollout." — corroborated by [issue #15141](https://github.com/openai/codex/issues/15141) and [PR #22404](https://github.com/openai/codex/pull/22404)

Doesn't change the "use stdio only" recommendation both reviews reach, but if anyone ever argues for WebSocket later (e.g., for a remote Workbench), the risk is "unauthenticated network listener," not just "not GA yet." Worth preserving this distinction in the record.

## Unsupported/overreaching claims in Qwen's review

- Calling the protocol "mature enough for production use" (see above) is an inference presented with more confidence than the primary source supports.
- "`account/tokenUsage/read` with `thread_id` parameter" — I could not confirm this exact method name; search evidence points to `account/usage/read` as the actual sibling to `account/rateLimits/read`. Minor, low-stakes, but Qwen should not have stated it as verified fact at that level of specificity.
- Section 9a marks several packet claims "Confirmed" with notable confidence despite being internal-repo facts (662 tests, `hermes oneshot`, BRAIN role) that are explicitly *not independently verifiable* — Qwen correctly labels most of these as unverifiable in 9b/9c, but the verdict narrative elsewhere leans on the packet's self-reported state more trustingly than the "do not assume this packet's claims are correct" instruction warranted. Not a factual error, but a posture inconsistency.

## Missed risks (neither Qwen nor Claude's prior review names these)

- **Shared quota contention.** `account/rateLimits/read` returns account-wide usage windows. If the Brain's deliberation turns run against the same ChatGPT subscription/account the human uses interactively, Brain activity and human activity compete for the same rate-limit window. Neither review flags this as an operational risk (the Brain could throttle the human's own ChatGPT use, or vice versa).
- **Vendor ToS/account-suspension exposure.** Running a personal/workspace ChatGPT subscription as an unattended, continuously-invoked governance-adjacent automation component carries a realistic risk of ToS friction or account action, which would sever the *only* auth path for the Brain role with no fallback. This single-point-of-failure risk isn't discussed in either review and should be surfaced to Eric explicitly, even if accepted.
- **Required-MCP-server death mid-thread is undocumented.** Claude's prior review flagged this as an open question; Qwen's review is silent on it even though Qwen covers MCP failure at `thread/start`/`thread/resume` in detail. Worth keeping as an explicit unresolved item for the experimental slice to probe.

## Corrections to the packet itself (from both reviews, cross-checked and accurate)

Both Qwen's and Claude's corrections on `cost_micros` nuance and WebSocket caution hold up. Qwen's catch that `codex mcp-server` was deprecated and removed ([confirmed](https://developers.openai.com/codex/changelog): deprecated 2026-08-24, removed in CLI 0.154.0) is accurate and a genuinely useful addition the packet lacked — good independent research value-add.

## Revised verdict

**PROCEED WITH CONDITIONS** — same top-line verdict as both independent reviews, but the conditions must be tightened before Eric treats this as settled:

1. `web_search` must be explicitly disabled (or domain-allowlisted) in the Brain adapter config, and this must be documented as closing a specific, real sandbox-bypass gap — not listed as one bullet among many.
2. stdio transport only; if WebSocket is ever considered later, non-loopback use requires explicit `--ws-auth`, no exceptions.
3. The human operator should explicitly accept, in writing, that the app-server command carries OpenAI's own "experimental, not supported for production workloads" disclaimer, independent of transport choice. This is a vendor support-commitment risk, not just a maturity caveat to be routed around with "use stdio."
4. `cost_micros` becomes provider-optional in the gateway contract; wall-time + token-count + rate-limit-window checks are the enforceable budget for the Brain boundary.
5. The smallest experimental slice (both reviews converge on roughly the same shape: one stdio process, one thread, no filesystem/network/MCP, structured `outputSchema`, one forced rejection/correction cycle, one induced-crash recovery test) must also probe: (a) required-MCP death mid-thread, and (b) observe whether Brain deliberation visibly consumes the same rate-limit window as the human's interactive ChatGPT use.

## Exact decisions Eric should make next

1. **Decide whether to accept the vendor's "experimental/unsupported for production" posture for a governance-adjacent boundary**, or require Codex synthesis to find/propose a mitigation (e.g., treating the Brain boundary as non-critical/advisory until OpenAI's support posture changes). This is a policy call, not a technical one — it should not be decided implicitly by picking stdio and moving on.
2. **Approve (or reject) running the five-part experimental slice** described above, with the two additional probes (MCP mid-thread death, quota contention) added to its test list.
3. **Approve the gateway contract split**: a narrow Brain-deliberation boundary separate from the existing worker-execution ALLOW gateway, with `cost_micros` made provider-optional.
4. **Direct that `web_search: "disabled"` be a hard-coded, centrally-enforced default for any Brain thread**, not a per-thread config left to drift.
5. **Send both reviews and this cross-review to Codex for synthesis**, flagging specifically: (a) the web_search bypass as the top tool-bypass finding over the goal/budget correspondence, (b) the production-support disclaimer as a named, accepted risk rather than something resolved by transport choice, and (c) the two missed risks (quota contention, ToS/account-suspension single point of failure) for explicit disposition (accept, mitigate, or escalate).
