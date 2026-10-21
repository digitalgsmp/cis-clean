# CIS 4.37 — Codex Brain Synthesis

## Decision

**Proceed with a limited experiment, with conditions.**

Claude and Qwen independently reached the same verdict and retained it after cross-review. Codex app-server can plausibly support the CIS Brain role without replacing Hermes, OpenRouter/Qwen, the deterministic verifier, or CIS authority.

## Durable architecture decisions

1. Create a narrow **DELIBERATE** boundary for Brain conversation before Card Factory. Do not weaken the worker gateway's existing ALLOW-before-dispatch rule.
2. CIS remains the authority. App-server threads, goals, approvals, and events are evidence and conversation state only.
3. Keep provider names out of generic CIS contracts. Codex app-server is a replaceable Brain adapter.
4. Make `cost_micros` optional/provider-specific. Continue enforcing real wall-time and token/usage limits.
5. Keep Hermes as the controlled implementation-worker path and OpenRouter/Qwen as the independent review path.

## Mandatory containment conditions

1. Use local stdio only. Do not expose WebSocket.
2. Use an explicit protocol-method allowlist. Block at least `thread/shellCommand`, `process/spawn`, and `thread/inject_items` unless a future governed use is approved.
3. Leave `experimentalApi` disabled.
4. Explicitly disable hosted `web_search` for the contained Brain experiment. It is outside the command sandbox's network controls.
5. Give the Brain no direct repository-write or implementation route.
6. Treat app-server goal budgets as cooperative signals, not hard enforcement.
7. Detect app-server death and recover without blindly resuming possibly corrupt thread state.

## Smallest experimental slice

- One pinned app-server version over stdio.
- One Brain deliberation thread.
- No filesystem writes or command-network access.
- No experimental API.
- Structured deliberation output containing obstacle, investigation, proposed response, justification, and draft work cards.
- One forced governance rejection and corrected resubmission.
- One forced process-crash recovery test.
- Observe whether Brain use competes with the human's ChatGPT subscription quota.
- Do not route implementation through app-server.

## Accepted uncertainties to decide explicitly

- OpenAI currently describes app-server as experimental/unsupported for production workloads. The experiment must remain reversible and non-authoritative until that risk is accepted or the support posture changes.
- Subscription activity may contend with the human operator's account quota.
- Authentication expiry, account policy, or suspension could remove the Brain path. CIS needs a clear degraded state rather than an ungoverned fallback.
- MCP failures can block startup and have been associated with process crashes. Begin without MCP or with only one CIS-owned, tightly controlled MCP after recovery behavior is proven.

## Recommended order

1. Record these findings in the 4.37 workstream.
2. Specify the DELIBERATE contract, app-server protocol allowlist, and normalized Workbench event contract.
3. Connect the contained Codex Brain to the Workbench and Card Factory in the smallest reversible slice.
4. Prove conversation, obstacle reporting, governance rejection, correction/resubmission, and work-card creation from the top of the pipeline.
5. Proceed downward through the pipeline only as each upstream stage is proven.
6. Detour to Claude, Hermes, Qwen, or other controller work only when it is a demonstrated dependency of the next Brain/Workbench milestone.

The earlier ClaudeProcessController-then-Hermes sequence is not a prerequisite unless dependency analysis proves otherwise. Do not spend model usage completing downstream controllers merely because they were previously next in the queue.

No reviewer found a fatal conflict with the intended CIS architecture.
