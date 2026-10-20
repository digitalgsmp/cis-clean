"""Failure vocabulary. Every error here is a fail-closed refusal."""


class CisError(Exception):
    """Base class. Carries a stable machine-readable code."""

    code = "CIS_ERROR"

    def __init__(self, message: str, **detail: object) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "detail": self.detail}


class ContractError(CisError):
    code = "CONTRACT_INVALID"


class BlueprintError(CisError):
    code = "BLUEPRINT_INVALID"


class AppendOnlyViolation(CisError):
    code = "APPEND_ONLY_VIOLATION"


class EvidenceConflict(CisError):
    """Evidence disagrees with itself. Fail closed; record; never invent a resolution."""

    code = "EVIDENCE_CONFLICT"


class AuthorizationRefused(CisError):
    """No valid ALLOW covers the requested execution."""

    code = "AUTHORIZATION_REFUSED"


class BindingError(AuthorizationRefused):
    """Authorization binding does not recompute from authority: mutated or stale."""

    code = "BINDING_INVALID"


class StaleAuthorization(AuthorizationRefused):
    code = "AUTHORIZATION_STALE"


class ExecutionRefused(CisError):
    code = "EXECUTION_REFUSED"


class ExecutionTimedOut(ExecutionRefused):
    """A backend did not return within its authorized wall-time budget."""

    code = "EXECUTION_TIMED_OUT"


class ExecutionBudgetExhausted(ExecutionRefused):
    """A backend exhausted a token or cost budget before completing."""

    code = "EXECUTION_BUDGET_EXHAUSTED"


class ExecutionPermissionWaitRefused(ExecutionRefused):
    """A backend stopped waiting on an interactive permission grant."""

    code = "EXECUTION_PERMISSION_WAIT_REFUSED"


class ExecutionProviderFailure(ExecutionRefused):
    """A backend's network transport or upstream provider failed."""

    code = "EXECUTION_PROVIDER_FAILURE"


class ExecutionOutputIncomplete(ExecutionRefused):
    """A backend returned empty or incomplete output for the request."""

    code = "EXECUTION_OUTPUT_INCOMPLETE"


class ExecutionArtifactInvalid(ExecutionRefused):
    """A backend produced an artifact that does not stand up on its own."""

    code = "EXECUTION_ARTIFACT_INVALID"


# ---------------------------------------------------------------------------
# Slice-2 assurance increment
# ---------------------------------------------------------------------------

class AssuranceRefused(CisError):
    """An assurance step refused rather than recording an unsupported fact."""

    code = "ASSURANCE_REFUSED"


class TaskContractRefused(AssuranceRefused):
    """A task contract could not be compiled from the template and authority."""

    code = "TASK_CONTRACT_REFUSED"


class ScopeWideningRefused(TaskContractRefused):
    """A requested path or action lies outside the compiled envelope."""

    code = "TASK_CONTRACT_WIDENING_REFUSED"


class TaskContractTampered(AssuranceRefused):
    """A frozen task contract no longer recomputes its independent digest."""

    code = "TASK_CONTRACT_TAMPERED"


class ExecutionInputRefused(AssuranceRefused):
    """An execution-input binding was refused before anything was recorded.

    Raised for every pre-append refusal: an unknown task contract, a forward
    link that does not match the contract, a digest that does not match the
    exact bytes beside it, a blank entrypoint or worker identity, a binding
    that does not recompute, and a task contract that already has a binding.
    """

    code = "EXECUTION_INPUT_REFUSED"


class ExecutionInputTampered(AssuranceRefused):
    """A recorded execution-input binding no longer stands up on its own.

    Either the row carries an unknown hash domain, or its stored bytes no
    longer hash to the digests recorded beside them, or its binding hash does
    not recompute from the stored fields.
    """

    code = "EXECUTION_INPUT_TAMPERED"


class VerificationRefused(AssuranceRefused):
    """The verifier refused to produce a result over unusable inputs."""

    code = "VERIFICATION_REFUSED"


class ReviewRefused(AssuranceRefused):
    """The reviewer refused to review: integrity, ordering or exhaustion."""

    code = "REVIEW_REFUSED"


class ObjectionCyclesExhausted(ReviewRefused):
    """Three objection cycles stand recorded; a fourth cannot exist."""

    code = "OBJECTION_CYCLES_EXHAUSTED"


class PromotionRefused(AssuranceRefused):
    """A promotion decision could not be recorded at all."""

    code = "PROMOTION_REFUSED"


class OperationalAssessmentRefused(AssuranceRefused):
    """An objection could not become a trustworthy recovery specification."""

    code = "OPERATIONAL_ASSESSMENT_REFUSED"


class RecoveryAttemptRefused(AssuranceRefused):
    """A bounded recovery could not be independently verified or recorded."""

    code = "RECOVERY_ATTEMPT_REFUSED"


class RecoveryExecutionRefused(AssuranceRefused):
    """A replacement candidate could not be carried through the existing
    authority path: a missing, stale, non-ALLOW, wrongly scoped or
    self/same-parent child authorization refuses before issuance or dispatch."""

    code = "RECOVERY_EXECUTION_REFUSED"


class WorkerSupervisionRefused(CisError):
    """A worker plan, attempt transition, budget, or fallback was refused."""

    code = "WORKER_SUPERVISION_REFUSED"


class WorkerSessionRefused(CisError):
    """A worker-model session header, request or event was refused rather
    than recorded: an unverified route, a disagreeing retry, a malformed
    digest, a duplicate authorization/route, or a request issued against a
    nonterminal or closed session."""

    code = "WORKER_SESSION_REFUSED"


class ProjectionRegenerationRefused(CisError):
    """A derived view changed without authority, mutated authority, or was omitted."""

    code = "PROJECTION_REGENERATION_REFUSED"


class HostActionRefused(CisError):
    """A host-side apply or rollback was not covered by recorded authority."""

    code = "HOST_ACTION_REFUSED"


# ---------------------------------------------------------------------------
# MASTER/TASK enforcement-policy compiler
# ---------------------------------------------------------------------------

class PolicyRefused(CisError):
    """The policy compiler or authority refused rather than compiling an
    envelope it could not stand behind."""

    code = "POLICY_REFUSED"


class PolicySchemaInvalid(PolicyRefused):
    """A policy document carries an unknown field, status or effect kind, or
    declares effects that do not match its own populated fields."""

    code = "POLICY_SCHEMA_INVALID"


class PolicyInvalidSupersession(PolicyRefused):
    """``supersedes`` names a document that does not exist, crosses lineages,
    or is not itself recorded SUPERSEDED."""

    code = "POLICY_INVALID_SUPERSESSION"


class PolicyCyclicSupersession(PolicyRefused):
    """The supersedes graph contains a cycle."""

    code = "POLICY_CYCLIC_SUPERSESSION"


class PolicyAmbiguous(PolicyRefused):
    """More than one ACTIVE policy document stands in one lineage."""

    code = "POLICY_AMBIGUOUS"


class PolicyConflict(PolicyRefused):
    """Two ACTIVE policy documents declare mutual conflict."""

    code = "POLICY_CONFLICT"


class PolicyBaselineMissing(PolicyRefused):
    """No ACTIVE master policy exists; there is no mandatory baseline."""

    code = "POLICY_BASELINE_MISSING"


class PolicyWeakensMaster(PolicyRefused):
    """A task policy would narrow less than, or widen beyond, what a master
    policy already restricts."""

    code = "POLICY_WEAKENS_MASTER"


class PolicyHold(PolicyRefused):
    """A policy document declares HOLD for this selector."""

    code = "POLICY_HOLD"


class PolicyStale(PolicyRefused):
    """A compiled envelope no longer matches the current policy authority."""

    code = "POLICY_STALE"


class PolicyTampered(PolicyRefused):
    """A policy document or compiled envelope does not recompute its own
    digest, or carries an unknown hash domain."""

    code = "POLICY_TAMPERED"


class PolicyEnvelopeMissing(PolicyRefused):
    """A governed operation was attempted with no bound policy envelope."""

    code = "POLICY_ENVELOPE_MISSING"


class PolicySourceConflict(PolicyRefused):
    """A policy_id already recorded in the source ledger is being ingested
    again with different content; a policy document's content is fixed the
    instant it is first ingested."""

    code = "POLICY_SOURCE_CONFLICT"


class PolicyProfileUnknown(PolicyRefused):
    """No deterministic profile maps this task-contract template to a
    project and risk; compiling a selector would require guessing rather
    than reading a trusted fact."""

    code = "POLICY_PROFILE_UNKNOWN"
