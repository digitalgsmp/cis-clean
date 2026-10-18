"""The slice-2 assurance increment.

Five Layer-2 modules and one read model, each independently constructible from
a store and a blueprint. There is deliberately NO orchestrator here: a single
module that drove the verifier and then the reviewer would be a coupling point
between two things whose whole value is that they are separate, and it would be
the obvious place for a future convenience to leak the verifier's conclusions
into the reviewer's inputs.

    from cis.assurance.task_contract import TaskContractCompiler
    from cis.assurance.authority import AssuranceAuthority
    from cis.assurance.verifier import Verifier
    from cis.assurance.reviewer import Reviewer
    from cis.assurance.promotion import PromotionRecorder
    from cis.assurance.projection import AssuranceProjection

    authority = AssuranceAuthority(store)
    authority.task_contracts.freeze(compiler.compile(...))
    Verifier(store, blueprint).verify(task_contract_id)
    Reviewer(store, blueprint).review(task_contract_id)
    PromotionRecorder(store).decide(task_contract_id)
    AssuranceProjection(store, blueprint).full()

THIS FILE RE-EXPORTS NOTHING, ON PURPOSE.

Every other package in this environment re-exports its modules for
convenience. This one must not, because a package ``__init__`` that imported
both ``verifier`` and ``reviewer`` would make importing EITHER one import the
other: ``import cis.assurance.reviewer`` runs this file first. The separation
would then hold in the contracts and in the source and be false in
``sys.modules``, and ``tests/test_assurance.py`` asserts the stronger
property — that importing the reviewer in a clean interpreter leaves the
verifier unimported, and the reverse.

``cis.assurance.authority`` owns all six assurance tables; the other modules
reach them only through its disjoint facades. ``cis.interface.api`` sees the
projection and nothing else: every assurance route this increment adds is a
GET.
"""
