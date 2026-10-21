# Spine extract — dev_continuity_events task 4.37, revisions 41–43

Read-only projection of the authority record, extracted 2026-10-20 so an
external reviewer can recover the current build direction from GitHub.
`data/*` is gitignored, so these rows are otherwise invisible remotely.

The database remains the authority. If this projection and the live spine
disagree, the spine is authoritative (ADR-ARCH-002).

The exact exported rows, including bodies, evidence references, source
references, request IDs, and request hashes, are in `events.json`.

Included records:

- Revision 41: enforced Brain coordinator preflight and capability
  reconciliation before Card Factory or worker dispatch.
- Revision 42: open contradiction—Qwen reviewer-route execution is not yet
  deterministically enforced.
- Revision 43: authoritative invariant—no model execution outside a
  registered, role-specific CIS-owned controller.

