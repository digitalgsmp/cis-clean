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
