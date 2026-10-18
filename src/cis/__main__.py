"""Operator entry point.

    PYTHONPATH=src python3 -m cis verify     # validate blueprint + contracts
    PYTHONPATH=src python3 -m cis demo       # run the slice end to end, offline
    PYTHONPATH=src python3 -m cis serve      # loopback JSON interface

``verify`` and ``demo`` touch no file: the authority is in memory unless
``--db`` is given. Nothing here reads or writes /mnt/projects/cis.
"""

from __future__ import annotations

import argparse
import json
import sys

from .authority import AuthorityStore
from .blueprint import load_blueprint
from .errors import CisError
from .interface import WorkbenchApi, run_server
from .workbench import Workbench


def _blueprint():
    return load_blueprint()


def cmd_verify(args: argparse.Namespace) -> int:
    blueprint = _blueprint()
    registry = blueprint.registry
    print(f"blueprint        {blueprint.document['blueprint_id']}")
    print(f"manifest_hash    {blueprint.manifest_hash}")
    print(f"registry_hash    {registry.registry_hash}")
    print(f"baseline_hash    {blueprint.baseline_hash}")
    print(f"current stage    {blueprint.current_stage}")
    print(f"modules          {len(registry.contracts)} contracted, "
          f"{len(blueprint.selected_module_ids)} selected")
    print(f"authorities      {len(registry.authority_owners())} with exactly one owner")
    print("\ndependency order (derived from contracts):")
    for position, module_id in enumerate(blueprint.dependency_order()):
        print(f"  {position:2d}  {registry.get(module_id).layer}  {module_id}")
    print("\nmacro stages:")
    for stage in blueprint.stages:
        marker = "->" if stage["stage_id"] == blueprint.current_stage else "  "
        print(f"  {marker} {stage['status']:<11} {stage['stage_id']}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    store = AuthorityStore(args.db or ":memory:")
    workbench = Workbench(store, blueprint=_blueprint())
    api = WorkbenchApi(workbench)

    # Every label below is a claim about what the step will show, and those
    # claims only hold against an empty authority. Replayed onto a file-backed
    # authority that already carries conversation, the objective the demo
    # redirects to already exists and step 11 refuses as a replay rather than
    # as a stale authorization — the slice still fails closed, but the
    # narration would be false. Name the conflict instead of printing it.
    if workbench.intent.count():
        raise CisError(
            "the demo narrates a first conversation and needs an empty "
            "authority; this one already holds intent transactions",
            db=args.db or ":memory:",
            intent_transactions=workbench.intent.count(),
        )

    # Direction comes from the bootstrap seam, before any request exists. A
    # request is never allowed to supply the objective it is judged under.
    workbench.set_initial_objective(
        "Reconstruct the CIS Workbench trajectory projection in the clean environment"
    )

    def show(label: str, response) -> None:
        print(f"\n=== {label} ===")
        print(response.json())

    def instruct(verbatim: str):
        return api.dispatch("POST", "/instruction", {"verbatim": verbatim})

    show("1. an earlier user idea, recorded as an ordinary exchange "
         "(HOLD: it names no selected module)",
         instruct("My questions and semantic memory fragments must recover "
                  "prior intent so important concepts do not go dormant"))

    show("2. a question that names the target module (HOLD: naming a module "
         "in a question is not authority to touch it)",
         instruct("What does cis.workbench.projection currently show?"))

    show("3. a vague fragment recovers the earlier user's exact words "
         "(continuity, with no manual ingestion)",
         instruct("I vaguely remember something about my questions making "
                  "concepts go dormant"))

    outside_words = ("Reconstruct the legacy pipeline relay in the clean "
                     "environment")
    first_outside = instruct(outside_words)
    show("4. work the validated architecture does not select (HOLD)",
         first_outside)
    second_outside = instruct(outside_words)
    show("5. the SAME request submitted again — still HOLD. Repetition "
         "creates another record of the request and no new authority",
         second_outside)
    print("\n    repeat changed nothing:",
          first_outside.body["authorization"]["reason_code"], "->",
          second_outside.body["authorization"]["reason_code"])

    allowed = instruct(
        "Reconstruct cis.workbench.projection in the clean environment")
    show("6. a concrete target instruction (ALLOW) — authorized because the "
         "validated manifest already selects this module and records its "
         "canonical evidence basis, not because anything was repeated",
         allowed)
    print("\n    canonical authorization basis:",
          json.dumps(allowed.body["authorization_basis"], indent=2,
                     sort_keys=True))

    repeated = instruct(
        "Reconstruct cis.workbench.projection in the clean environment")
    show("7. the same instruction again — a distinct transaction, bounded "
         "identically. A repeat gains no broader permission", repeated)
    print("\n    scope identical to step 6:",
          repeated.body["authorization"]["scope"]
          == allowed.body["authorization"]["scope"])

    authorization_id = allowed.body["authorization"]["authorization_id"]
    show("8. governed execution through the Layer-2 port",
         api.dispatch("POST", "/execute", {"authorization_id": authorization_id}))
    show("9. trajectory with the derived you-are-here marker",
         api.dispatch("GET", f"/trajectory/{allowed.body['transaction_id']}"))
    show("10. an explicit redirection (expect a new objective, and no "
         "authorization under an objective it just created)",
         instruct("REDIRECT: prove the execution boundary instead"))
    show("11. the earlier ALLOW is now stale (expect a fail-closed refusal)",
         api.dispatch("POST", "/execute", {"authorization_id": authorization_id}))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    store = AuthorityStore(args.db or ":memory:")
    workbench = Workbench(store, blueprint=_blueprint())
    if args.objective:
        workbench.set_initial_objective(args.objective)
    run_server(WorkbenchApi(workbench), host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cis", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="validate the blueprint and contracts")
    verify.set_defaults(func=cmd_verify)

    demo = sub.add_parser("demo", help="run the slice end to end, offline")
    demo.add_argument("--db", help="authority path (default: in memory); "
                                   "must be empty, the demo narrates a first "
                                   "conversation")
    demo.set_defaults(func=cmd_demo)

    serve = sub.add_parser("serve", help="serve the JSON interface on loopback")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8077)
    serve.add_argument("--db", help="authority path (default: in memory)")
    serve.add_argument("--objective", help="establish an initial objective")
    serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CisError as exc:
        print(f"REFUSED [{exc.code}] {exc.message}", file=sys.stderr)
        if exc.detail:
            print(json.dumps(exc.detail, indent=2, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
