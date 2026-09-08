"""Deterministic P5 verifier orchestration with explicit evidence and status."""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from cybersecgpt.foundation import (
    CorrelationId,
    RequestId,
    RoutingDecisionId,
    RoutingSecurityBinding,
    SubstrateId,
)

from .budget import ReasoningBudgetDelta
from .candidates import CandidateSelectionPolicy, select_candidate_substrates
from .errors import VerificationOrchestrationError
from .lifecycle import (
    ReasoningLifecycleSnapshot,
    ReasoningState,
    transition_reasoning_state,
)
from .request import BrainRequest
from .routing import (
    RoutingDecision,
    RoutingReasoningBudgetUsage,
    validate_routing_decision,
)
from .substrates import CapabilitySnapshot, SubstrateKind, ValidatedSubstrate
from .termination import TerminationReason, TerminationRequirement

__all__ = [
    "VerificationAssertionResult",
    "VerificationAssertionStatus",
    "VerificationEvidenceReference",
    "VerificationIndependenceRequirement",
    "VerificationOrchestrationState",
    "VerificationPolicy",
    "VerificationResult",
    "VerificationStatus",
    "VerifierObservation",
    "begin_verification_orchestration",
    "finalize_verification",
    "record_verifier_observation",
]

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class VerificationStatus(StrEnum):
    """Terminal P5 verification outcomes."""

    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    CONTRADICTORY = "CONTRADICTORY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    CANCELLED = "CANCELLED"
    DEADLINE = "DEADLINE"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"


class VerificationAssertionStatus(StrEnum):
    """Per-assertion verifier observation and aggregate outcomes."""

    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    CONTRADICTORY = "CONTRADICTORY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"


class VerificationIndependenceRequirement(StrEnum):
    """Machine-evaluable independence rules for final verification."""

    NONE = "NONE"
    DISTINCT_OWNER = "DISTINCT_OWNER"
    DETERMINISTIC = "DETERMINISTIC"
    DETERMINISTIC_AND_DISTINCT_OWNER = "DETERMINISTIC_AND_DISTINCT_OWNER"

    @property
    def requires_distinct_owner(self) -> bool:
        """Return whether supporting verifiers must have independent owners."""
        return self in {
            VerificationIndependenceRequirement.DISTINCT_OWNER,
            VerificationIndependenceRequirement.DETERMINISTIC_AND_DISTINCT_OWNER,
        }

    @property
    def requires_deterministic(self) -> bool:
        """Return whether supporting verifier profiles must be deterministic."""
        return self in {
            VerificationIndependenceRequirement.DETERMINISTIC,
            VerificationIndependenceRequirement.DETERMINISTIC_AND_DISTINCT_OWNER,
        }


def _require_text(
    value: object,
    *,
    field_name: str,
    max_length: int = 512,
) -> str:
    if not isinstance(value, str):
        raise VerificationOrchestrationError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise VerificationOrchestrationError(
            f"{field_name} must be non-empty and have no surrounding whitespace"
        )
    if len(value) > max_length:
        raise VerificationOrchestrationError(
            f"{field_name} must be at most {max_length} characters"
        )
    return value


def _require_token(value: object, *, field_name: str) -> str:
    text = _require_text(value, field_name=field_name, max_length=128)
    if _TOKEN_PATTERN.fullmatch(text) is None:
        raise VerificationOrchestrationError(
            f"{field_name} must be a machine-evaluable token of at most 128 characters"
        )
    return text


def _require_tokens(
    value: object,
    *,
    field_name: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise VerificationOrchestrationError(f"{field_name} must be a tuple")
    values = tuple(
        _require_token(item, field_name=f"{field_name} item") for item in value
    )
    if not allow_empty and not values:
        raise VerificationOrchestrationError(f"{field_name} must not be empty")
    if len(set(values)) != len(values):
        raise VerificationOrchestrationError(
            f"{field_name} must not contain duplicates"
        )
    return values


def _require_references(
    value: object,
    *,
    field_name: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise VerificationOrchestrationError(f"{field_name} must be a tuple")
    values = tuple(
        _require_text(item, field_name=f"{field_name} item") for item in value
    )
    if not allow_empty and not values:
        raise VerificationOrchestrationError(f"{field_name} must not be empty")
    if len(set(values)) != len(values):
        raise VerificationOrchestrationError(
            f"{field_name} must not contain duplicates"
        )
    return values


def _require_positive_int(value: object, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise VerificationOrchestrationError(f"{field_name} must be a positive integer")
    return value


def _require_utc_datetime(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise VerificationOrchestrationError(f"{field_name} must be a datetime")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise VerificationOrchestrationError(f"{field_name} must be timezone-aware UTC")
    return value


@dataclass(frozen=True, slots=True)
class VerificationPolicy:
    """Define fail-closed verifier requirements without creating authorization."""

    policy_id: str
    policy_version: str
    required_assertions: tuple[str, ...]
    required_evidence_classes: tuple[str, ...]
    required_verifier_classes: tuple[str, ...]
    independence_requirement: VerificationIndependenceRequirement
    minimum_supporting_verifiers: int
    max_verifier_passes: int
    human_review_required: bool = False
    deadline: datetime | None = None

    def __post_init__(self) -> None:
        _require_token(self.policy_id, field_name="policy_id")
        _require_token(self.policy_version, field_name="policy_version")
        _require_tokens(
            self.required_assertions,
            field_name="required_assertions",
            allow_empty=False,
        )
        _require_tokens(
            self.required_evidence_classes,
            field_name="required_evidence_classes",
            allow_empty=True,
        )
        _require_tokens(
            self.required_verifier_classes,
            field_name="required_verifier_classes",
            allow_empty=True,
        )
        if not isinstance(
            self.independence_requirement,
            VerificationIndependenceRequirement,
        ):
            raise VerificationOrchestrationError(
                "independence_requirement must be a VerificationIndependenceRequirement"
            )
        _require_positive_int(
            self.minimum_supporting_verifiers,
            field_name="minimum_supporting_verifiers",
        )
        _require_positive_int(
            self.max_verifier_passes,
            field_name="max_verifier_passes",
        )
        if not isinstance(self.human_review_required, bool):
            raise VerificationOrchestrationError("human_review_required must be a bool")
        if self.deadline is not None:
            _require_utc_datetime(self.deadline, field_name="deadline")


@dataclass(frozen=True, slots=True)
class VerificationEvidenceReference:
    """Identify evidence and provenance without embedding evidence content."""

    evidence_ref: str
    evidence_class: str
    provenance_ref: str

    def __post_init__(self) -> None:
        _require_text(self.evidence_ref, field_name="evidence_ref")
        _require_token(self.evidence_class, field_name="evidence_class")
        _require_text(self.provenance_ref, field_name="provenance_ref")


@dataclass(frozen=True, slots=True)
class VerifierObservation:
    """Record one externally produced verifier observation.

    The observation is evidence/control metadata only. It does not grant
    authorization and does not prove that the external verifier actually ran;
    trusted runtime owners remain responsible for execution and provenance.
    """

    verifier_id: SubstrateId
    method_version: str
    assertion_id: str
    status: VerificationAssertionStatus
    evidence_refs: tuple[str, ...]
    contradictions: tuple[str, ...]
    limitations: tuple[str, ...]
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.verifier_id, SubstrateId):
            raise VerificationOrchestrationError("verifier_id must be a SubstrateId")
        _require_text(self.method_version, field_name="method_version", max_length=128)
        _require_token(self.assertion_id, field_name="assertion_id")
        if not isinstance(self.status, VerificationAssertionStatus):
            raise VerificationOrchestrationError(
                "status must be a VerificationAssertionStatus"
            )
        _require_references(
            self.evidence_refs,
            field_name="evidence_refs",
            allow_empty=True,
        )
        _require_references(
            self.contradictions,
            field_name="contradictions",
            allow_empty=True,
        )
        _require_references(
            self.limitations,
            field_name="limitations",
            allow_empty=True,
        )
        _require_utc_datetime(self.observed_at, field_name="observed_at")
        if (
            self.status is VerificationAssertionStatus.CONTRADICTORY
            and not self.contradictions
        ):
            raise VerificationOrchestrationError(
                "CONTRADICTORY observation requires contradiction references"
            )


@dataclass(frozen=True, slots=True)
class VerificationAssertionResult:
    """Aggregate verifier observations for one required assertion."""

    assertion_id: str
    status: VerificationAssertionStatus
    supporting_verifiers: tuple[SubstrateId, ...]
    evidence_refs: tuple[str, ...]
    contradictions: tuple[str, ...]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_token(self.assertion_id, field_name="assertion_id")
        if not isinstance(self.status, VerificationAssertionStatus):
            raise VerificationOrchestrationError(
                "status must be a VerificationAssertionStatus"
            )
        if not isinstance(self.supporting_verifiers, tuple):
            raise VerificationOrchestrationError(
                "supporting_verifiers must be a tuple"
            )
        if not all(
            isinstance(item, SubstrateId) for item in self.supporting_verifiers
        ):
            raise VerificationOrchestrationError(
                "supporting_verifiers must contain only SubstrateId values"
            )
        if len(set(self.supporting_verifiers)) != len(self.supporting_verifiers):
            raise VerificationOrchestrationError(
                "supporting_verifiers must not contain duplicates"
            )
        _require_references(
            self.evidence_refs,
            field_name="evidence_refs",
            allow_empty=True,
        )
        _require_references(
            self.contradictions,
            field_name="contradictions",
            allow_empty=True,
        )
        _require_references(
            self.limitations,
            field_name="limitations",
            allow_empty=True,
        )


@dataclass(frozen=True, slots=True)
class VerificationOrchestrationState:
    """Store immutable P5 verifier orchestration state and current budget ledger."""

    request_id: RequestId
    routing_decision_id: RoutingDecisionId
    correlation_id: CorrelationId
    subject_ref: str
    subject_producer_substrate_id: SubstrateId | None
    policy: VerificationPolicy
    selected_verifiers: tuple[SubstrateId, ...]
    evidence_catalog: tuple[VerificationEvidenceReference, ...]
    observations: tuple[VerifierObservation, ...]
    lifecycle: ReasoningLifecycleSnapshot
    started_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, RequestId):
            raise VerificationOrchestrationError("request_id must be a RequestId")
        if not isinstance(self.routing_decision_id, RoutingDecisionId):
            raise VerificationOrchestrationError(
                "routing_decision_id must be a RoutingDecisionId"
            )
        if not isinstance(self.correlation_id, CorrelationId):
            raise VerificationOrchestrationError(
                "correlation_id must be a CorrelationId"
            )
        _require_text(self.subject_ref, field_name="subject_ref")
        if self.subject_producer_substrate_id is not None and not isinstance(
            self.subject_producer_substrate_id,
            SubstrateId,
        ):
            raise VerificationOrchestrationError(
                "subject_producer_substrate_id must be a SubstrateId or None"
            )
        if not isinstance(self.policy, VerificationPolicy):
            raise VerificationOrchestrationError("policy must be a VerificationPolicy")
        if not isinstance(self.selected_verifiers, tuple):
            raise VerificationOrchestrationError("selected_verifiers must be a tuple")
        if not all(isinstance(item, SubstrateId) for item in self.selected_verifiers):
            raise VerificationOrchestrationError(
                "selected_verifiers must contain only SubstrateId values"
            )
        if len(set(self.selected_verifiers)) != len(self.selected_verifiers):
            raise VerificationOrchestrationError(
                "selected_verifiers must not contain duplicates"
            )
        if not isinstance(self.evidence_catalog, tuple):
            raise VerificationOrchestrationError("evidence_catalog must be a tuple")
        if not all(
            isinstance(item, VerificationEvidenceReference)
            for item in self.evidence_catalog
        ):
            raise VerificationOrchestrationError(
                "evidence_catalog must contain only "
                "VerificationEvidenceReference values"
            )
        evidence_ids = tuple(item.evidence_ref for item in self.evidence_catalog)
        if len(set(evidence_ids)) != len(evidence_ids):
            raise VerificationOrchestrationError(
                "evidence_catalog must not contain duplicate evidence refs"
            )
        if not isinstance(self.observations, tuple):
            raise VerificationOrchestrationError("observations must be a tuple")
        if not all(isinstance(item, VerifierObservation) for item in self.observations):
            raise VerificationOrchestrationError(
                "observations must contain only VerifierObservation values"
            )
        observation_keys = tuple(
            (item.verifier_id, item.assertion_id) for item in self.observations
        )
        if len(set(observation_keys)) != len(observation_keys):
            raise VerificationOrchestrationError(
                "observations must not contain duplicate verifier/assertion pairs"
            )
        if not isinstance(self.lifecycle, ReasoningLifecycleSnapshot):
            raise VerificationOrchestrationError(
                "lifecycle must be a ReasoningLifecycleSnapshot"
            )
        if self.lifecycle.routing_decision_id != self.routing_decision_id:
            raise VerificationOrchestrationError(
                "lifecycle routing decision must match routing_decision_id"
            )
        if self.lifecycle.correlation_id != self.correlation_id:
            raise VerificationOrchestrationError(
                "lifecycle correlation identity must match correlation_id"
            )
        if self.lifecycle.state is not ReasoningState.VERIFYING:
            raise VerificationOrchestrationError(
                "verification orchestration lifecycle must be VERIFYING"
            )
        _require_utc_datetime(self.started_at, field_name="started_at")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Return explicit verification status separate from generated output status."""

    request_id: RequestId
    routing_decision_id: RoutingDecisionId
    correlation_id: CorrelationId
    subject_ref: str
    policy_id: str
    policy_version: str
    status: VerificationStatus
    assertion_results: tuple[VerificationAssertionResult, ...]
    evidence_refs: tuple[str, ...]
    verifier_identities: tuple[SubstrateId, ...]
    method_versions: tuple[str, ...]
    contradictions: tuple[str, ...]
    limitations: tuple[str, ...]
    budget_state: RoutingReasoningBudgetUsage
    started_at: datetime
    finished_at: datetime
    provenance: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, RequestId):
            raise VerificationOrchestrationError("request_id must be a RequestId")
        if not isinstance(self.routing_decision_id, RoutingDecisionId):
            raise VerificationOrchestrationError(
                "routing_decision_id must be a RoutingDecisionId"
            )
        if not isinstance(self.correlation_id, CorrelationId):
            raise VerificationOrchestrationError(
                "correlation_id must be a CorrelationId"
            )
        _require_text(self.subject_ref, field_name="subject_ref")
        _require_token(self.policy_id, field_name="policy_id")
        _require_token(self.policy_version, field_name="policy_version")
        if not isinstance(self.status, VerificationStatus):
            raise VerificationOrchestrationError("status must be a VerificationStatus")
        if not isinstance(self.assertion_results, tuple):
            raise VerificationOrchestrationError("assertion_results must be a tuple")
        if not all(
            isinstance(item, VerificationAssertionResult)
            for item in self.assertion_results
        ):
            raise VerificationOrchestrationError(
                "assertion_results must contain only VerificationAssertionResult values"
            )
        _require_references(
            self.evidence_refs,
            field_name="evidence_refs",
            allow_empty=True,
        )
        if not isinstance(self.verifier_identities, tuple):
            raise VerificationOrchestrationError("verifier_identities must be a tuple")
        if not all(isinstance(item, SubstrateId) for item in self.verifier_identities):
            raise VerificationOrchestrationError(
                "verifier_identities must contain only SubstrateId values"
            )
        if len(set(self.verifier_identities)) != len(self.verifier_identities):
            raise VerificationOrchestrationError(
                "verifier_identities must not contain duplicates"
            )
        _require_references(
            self.method_versions,
            field_name="method_versions",
            allow_empty=True,
        )
        _require_references(
            self.contradictions,
            field_name="contradictions",
            allow_empty=True,
        )
        _require_references(
            self.limitations,
            field_name="limitations",
            allow_empty=True,
        )
        if not isinstance(self.budget_state, RoutingReasoningBudgetUsage):
            raise VerificationOrchestrationError(
                "budget_state must be a RoutingReasoningBudgetUsage"
            )
        if self.budget_state.decision_id != self.routing_decision_id:
            raise VerificationOrchestrationError(
                "budget_state must bind to routing_decision_id"
            )
        started_at = _require_utc_datetime(self.started_at, field_name="started_at")
        finished_at = _require_utc_datetime(self.finished_at, field_name="finished_at")
        if finished_at < started_at:
            raise VerificationOrchestrationError(
                "finished_at must not be earlier than started_at"
            )
        _require_references(self.provenance, field_name="provenance", allow_empty=False)
        if self.status is VerificationStatus.SUPPORTED:
            if not self.assertion_results or not all(
                item.status is VerificationAssertionStatus.SUPPORTED
                for item in self.assertion_results
            ):
                raise VerificationOrchestrationError(
                    "SUPPORTED result requires every assertion to be SUPPORTED"
                )


def _snapshot_by_id(
    snapshot: CapabilitySnapshot,
) -> dict[SubstrateId, ValidatedSubstrate]:
    return {item.descriptor.substrate_id: item for item in snapshot.substrates}


def _validate_common_bindings(
    request: BrainRequest,
    decision: RoutingDecision,
    lifecycle: ReasoningLifecycleSnapshot,
    snapshot: CapabilitySnapshot,
    current_binding: RoutingSecurityBinding,
    *,
    observed_at: datetime,
) -> None:
    if decision.security_binding != request.security_binding:
        raise VerificationOrchestrationError(
            "routing decision security binding must match admitted request"
        )
    if current_binding != request.security_binding:
        raise VerificationOrchestrationError(
            "current_binding must match admitted request security binding"
        )
    if lifecycle.routing_decision_id != decision.decision_id:
        raise VerificationOrchestrationError(
            "lifecycle routing decision must match supplied decision"
        )
    if lifecycle.correlation_id != request.correlation_id:
        raise VerificationOrchestrationError(
            "lifecycle correlation identity must match admitted request"
        )
    if lifecycle.state is not ReasoningState.VERIFYING:
        raise VerificationOrchestrationError(
            "verifier orchestration requires lifecycle state VERIFYING"
        )
    if snapshot.snapshot_id != current_binding.capability_snapshot_id:
        raise VerificationOrchestrationError(
            "capability snapshot must match current security binding"
        )
    validation = validate_routing_decision(
        decision,
        current_binding=current_binding,
        now=observed_at,
    )
    if not validation.valid:
        raise VerificationOrchestrationError(
            "verifier orchestration requires a current routing decision"
        )


def _validate_termination_requirement(
    requirement: TerminationRequirement,
    *,
    request: BrainRequest,
    decision: RoutingDecision,
    observed_at: datetime,
) -> None:
    if not isinstance(requirement, TerminationRequirement):
        raise VerificationOrchestrationError(
            "termination_requirement must be a TerminationRequirement"
        )
    if requirement.request_id != request.request_id:
        raise VerificationOrchestrationError(
            "termination requirement request_id must match request"
        )
    if requirement.routing_decision_id != decision.decision_id:
        raise VerificationOrchestrationError(
            "termination requirement routing decision must match decision"
        )
    if requirement.correlation_id != request.correlation_id:
        raise VerificationOrchestrationError(
            "termination requirement correlation_id must match request"
        )
    if requirement.evaluated_at != observed_at:
        raise VerificationOrchestrationError(
            "termination requirement must be evaluated at observation time"
        )


def _effective_deadline(
    request: BrainRequest,
    policy: VerificationPolicy,
) -> datetime | None:
    deadlines = tuple(
        item for item in (request.deadline, policy.deadline) if item is not None
    )
    return min(deadlines) if deadlines else None


def _selected_verifiers(
    request: BrainRequest,
    snapshot: CapabilitySnapshot,
    selection_policy: CandidateSelectionPolicy,
    verification_policy: VerificationPolicy,
    current_binding: RoutingSecurityBinding,
    subject_producer_substrate_id: SubstrateId | None,
    *,
    observed_at: datetime,
) -> tuple[SubstrateId, ...]:
    if selection_policy.allowed_substrate_kinds != (SubstrateKind.VERIFIER,):
        raise VerificationOrchestrationError(
            "verifier selection policy must allow only VERIFIER substrates"
        )
    if not set(verification_policy.required_verifier_classes).issubset(
        request.verification_requirements
    ):
        raise VerificationOrchestrationError(
            "verification policy verifier classes must be admitted request requirements"
        )
    selection = select_candidate_substrates(
        request,
        snapshot,
        selection_policy,
        current_binding=current_binding,
        observed_at=observed_at,
    )
    by_id = _snapshot_by_id(snapshot)
    candidates = [
        substrate_id
        for substrate_id in selection.selected_substrates
        if substrate_id != subject_producer_substrate_id
    ]

    if verification_policy.independence_requirement.requires_deterministic:
        deterministic_profiles = set(selection_policy.deterministic_profiles)
        candidates = [
            substrate_id
            for substrate_id in candidates
            if by_id[substrate_id].descriptor.determinism_profile
            in deterministic_profiles
        ]

    if (
        verification_policy.independence_requirement.requires_distinct_owner
        and subject_producer_substrate_id in by_id
    ):
        producer_owner = by_id[subject_producer_substrate_id].descriptor.owner
        candidates = [
            substrate_id
            for substrate_id in candidates
            if by_id[substrate_id].descriptor.owner != producer_owner
        ]

    return tuple(candidates)


def begin_verification_orchestration(
    request: BrainRequest,
    decision: RoutingDecision,
    lifecycle: ReasoningLifecycleSnapshot,
    snapshot: CapabilitySnapshot,
    selection_policy: CandidateSelectionPolicy,
    verification_policy: VerificationPolicy,
    evidence_catalog: tuple[VerificationEvidenceReference, ...],
    termination_requirement: TerminationRequirement,
    *,
    current_binding: RoutingSecurityBinding,
    subject_ref: str,
    subject_producer_substrate_id: SubstrateId | None,
    started_at: datetime,
) -> VerificationOrchestrationState:
    """Select current verifier substrates and begin immutable orchestration state."""
    if not isinstance(request, BrainRequest):
        raise VerificationOrchestrationError("request must be a BrainRequest")
    if not isinstance(decision, RoutingDecision):
        raise VerificationOrchestrationError("decision must be a RoutingDecision")
    if not isinstance(lifecycle, ReasoningLifecycleSnapshot):
        raise VerificationOrchestrationError(
            "lifecycle must be a ReasoningLifecycleSnapshot"
        )
    if not isinstance(snapshot, CapabilitySnapshot):
        raise VerificationOrchestrationError("snapshot must be a CapabilitySnapshot")
    if not isinstance(selection_policy, CandidateSelectionPolicy):
        raise VerificationOrchestrationError(
            "selection_policy must be a CandidateSelectionPolicy"
        )
    if not isinstance(verification_policy, VerificationPolicy):
        raise VerificationOrchestrationError(
            "verification_policy must be a VerificationPolicy"
        )
    if not isinstance(current_binding, RoutingSecurityBinding):
        raise VerificationOrchestrationError(
            "current_binding must be a RoutingSecurityBinding"
        )
    if subject_producer_substrate_id is not None and not isinstance(
        subject_producer_substrate_id,
        SubstrateId,
    ):
        raise VerificationOrchestrationError(
            "subject_producer_substrate_id must be a SubstrateId or None"
        )
    subject = _require_text(subject_ref, field_name="subject_ref")
    now = _require_utc_datetime(started_at, field_name="started_at")
    _validate_common_bindings(
        request,
        decision,
        lifecycle,
        snapshot,
        current_binding,
        observed_at=now,
    )
    _validate_termination_requirement(
        termination_requirement,
        request=request,
        decision=decision,
        observed_at=now,
    )
    if termination_requirement.required:
        raise VerificationOrchestrationError(
            "verification cannot begin after cancellation/deadline termination"
        )
    deadline = _effective_deadline(request, verification_policy)
    if deadline is not None and now >= deadline:
        raise VerificationOrchestrationError("verification deadline has been reached")
    if (
        verification_policy.max_verifier_passes
        > decision.reasoning_budget.max_verifier_passes
    ):
        raise VerificationOrchestrationError(
            "verification policy cannot exceed admitted verifier-pass budget"
        )
    if not isinstance(evidence_catalog, tuple):
        raise VerificationOrchestrationError("evidence_catalog must be a tuple")
    if not all(
        isinstance(item, VerificationEvidenceReference) for item in evidence_catalog
    ):
        raise VerificationOrchestrationError(
            "evidence_catalog must contain only VerificationEvidenceReference values"
        )
    evidence_ids = tuple(item.evidence_ref for item in evidence_catalog)
    if len(set(evidence_ids)) != len(evidence_ids):
        raise VerificationOrchestrationError(
            "evidence_catalog must not contain duplicate evidence refs"
        )

    selected = _selected_verifiers(
        request,
        snapshot,
        selection_policy,
        verification_policy,
        current_binding,
        subject_producer_substrate_id,
        observed_at=now,
    )
    return VerificationOrchestrationState(
        request_id=request.request_id,
        routing_decision_id=decision.decision_id,
        correlation_id=request.correlation_id,
        subject_ref=subject,
        subject_producer_substrate_id=subject_producer_substrate_id,
        policy=verification_policy,
        selected_verifiers=selected,
        evidence_catalog=evidence_catalog,
        observations=(),
        lifecycle=lifecycle,
        started_at=now,
    )


def record_verifier_observation(
    state: VerificationOrchestrationState,
    request: BrainRequest,
    decision: RoutingDecision,
    snapshot: CapabilitySnapshot,
    observation: VerifierObservation,
    termination_requirement: TerminationRequirement,
    *,
    current_binding: RoutingSecurityBinding,
) -> VerificationOrchestrationState:
    """Record one external verifier pass and consume one admitted verifier pass."""
    if not isinstance(state, VerificationOrchestrationState):
        raise VerificationOrchestrationError(
            "state must be a VerificationOrchestrationState"
        )
    if not isinstance(observation, VerifierObservation):
        raise VerificationOrchestrationError(
            "observation must be a VerifierObservation"
        )
    now = observation.observed_at
    _validate_common_bindings(
        request,
        decision,
        state.lifecycle,
        snapshot,
        current_binding,
        observed_at=now,
    )
    if state.request_id != request.request_id:
        raise VerificationOrchestrationError("state request_id must match request")
    if state.routing_decision_id != decision.decision_id:
        raise VerificationOrchestrationError(
            "state routing_decision_id must match decision"
        )
    if state.correlation_id != request.correlation_id:
        raise VerificationOrchestrationError(
            "state correlation_id must match request"
        )
    _validate_termination_requirement(
        termination_requirement,
        request=request,
        decision=decision,
        observed_at=now,
    )
    if termination_requirement.required:
        raise VerificationOrchestrationError(
            "verification observation cannot be recorded after termination"
        )
    if now < state.started_at:
        raise VerificationOrchestrationError(
            "verification observation cannot predate orchestration"
        )
    deadline = _effective_deadline(request, state.policy)
    if deadline is not None and now >= deadline:
        raise VerificationOrchestrationError(
            "verification observation cannot be recorded after deadline"
        )
    if observation.verifier_id not in state.selected_verifiers:
        raise VerificationOrchestrationError(
            "observation verifier_id was not selected for orchestration"
        )
    if observation.assertion_id not in state.policy.required_assertions:
        raise VerificationOrchestrationError(
            "observation assertion_id is not required by verification policy"
        )
    if any(
        item.verifier_id == observation.verifier_id
        and item.assertion_id == observation.assertion_id
        for item in state.observations
    ):
        raise VerificationOrchestrationError(
            "duplicate verifier/assertion observation is not allowed"
        )
    by_id = _snapshot_by_id(snapshot)
    verifier = by_id.get(observation.verifier_id)
    if (
        verifier is None
        or verifier.descriptor.substrate_kind is not SubstrateKind.VERIFIER
    ):
        raise VerificationOrchestrationError(
            "observation verifier must be a current validated VERIFIER substrate"
        )
    if observation.method_version != verifier.descriptor.substrate_version:
        raise VerificationOrchestrationError(
            "observation method_version must match verifier substrate version"
        )
    evidence_by_ref = {item.evidence_ref: item for item in state.evidence_catalog}
    unknown_evidence = tuple(
        ref for ref in observation.evidence_refs if ref not in evidence_by_ref
    )
    if unknown_evidence:
        raise VerificationOrchestrationError(
            "observation references evidence outside the admitted evidence catalog"
        )
    if (
        state.lifecycle.budget_state.usage.verifier_passes
        >= state.policy.max_verifier_passes
    ):
        raise VerificationOrchestrationError(
            "verification policy verifier-pass ceiling has been reached"
        )

    lifecycle = transition_reasoning_state(
        decision,
        state.lifecycle,
        state=ReasoningState.VERIFYING,
        cause="verifier pass recorded",
        budget_delta=ReasoningBudgetDelta(verifier_passes=1),
    )
    return VerificationOrchestrationState(
        request_id=state.request_id,
        routing_decision_id=state.routing_decision_id,
        correlation_id=state.correlation_id,
        subject_ref=state.subject_ref,
        subject_producer_substrate_id=state.subject_producer_substrate_id,
        policy=state.policy,
        selected_verifiers=state.selected_verifiers,
        evidence_catalog=state.evidence_catalog,
        observations=state.observations + (observation,),
        lifecycle=lifecycle,
        started_at=state.started_at,
    )


def _assertion_result(
    assertion_id: str,
    observations: tuple[VerifierObservation, ...],
    evidence_by_ref: dict[str, VerificationEvidenceReference],
    policy: VerificationPolicy,
    snapshot: CapabilitySnapshot,
) -> VerificationAssertionResult:
    relevant = tuple(item for item in observations if item.assertion_id == assertion_id)
    supporting = tuple(
        sorted(
            {
                item.verifier_id
                for item in relevant
                if item.status is VerificationAssertionStatus.SUPPORTED
            },
            key=lambda item: item.value,
        )
    )
    evidence_refs = tuple(
        sorted({ref for item in relevant for ref in item.evidence_refs})
    )
    contradictions = tuple(
        sorted({ref for item in relevant for ref in item.contradictions})
    )
    limitations = tuple(sorted({ref for item in relevant for ref in item.limitations}))

    statuses = {item.status for item in relevant}
    if VerificationAssertionStatus.CONTRADICTORY in statuses:
        status = VerificationAssertionStatus.CONTRADICTORY
    elif VerificationAssertionStatus.VERIFICATION_ERROR in statuses:
        status = VerificationAssertionStatus.VERIFICATION_ERROR
    elif VerificationAssertionStatus.UNSUPPORTED in statuses:
        status = VerificationAssertionStatus.UNSUPPORTED
    else:
        required_classes = set(policy.required_evidence_classes)
        observed_classes = {
            evidence_by_ref[ref].evidence_class
            for ref in evidence_refs
            if ref in evidence_by_ref
        }
        enough_support = len(supporting) >= policy.minimum_supporting_verifiers
        independence_ok = _independence_satisfied(supporting, policy, snapshot)
        if (
            enough_support
            and required_classes.issubset(observed_classes)
            and independence_ok
        ):
            status = VerificationAssertionStatus.SUPPORTED
        else:
            status = VerificationAssertionStatus.INSUFFICIENT_EVIDENCE

    return VerificationAssertionResult(
        assertion_id=assertion_id,
        status=status,
        supporting_verifiers=supporting,
        evidence_refs=evidence_refs,
        contradictions=contradictions,
        limitations=limitations,
    )


def _independence_satisfied(
    supporting: tuple[SubstrateId, ...],
    policy: VerificationPolicy,
    snapshot: CapabilitySnapshot,
) -> bool:
    if not supporting:
        return False
    by_id = _snapshot_by_id(snapshot)
    if policy.independence_requirement.requires_distinct_owner:
        owners = {by_id[item].descriptor.owner for item in supporting if item in by_id}
        if len(owners) < policy.minimum_supporting_verifiers:
            return False
    if policy.independence_requirement.requires_deterministic:
        if any(
            by_id[item].descriptor.determinism_profile == "nondeterministic"
            for item in supporting
            if item in by_id
        ):
            return False
    return True


def _overall_status(
    assertion_results: tuple[VerificationAssertionResult, ...],
    policy: VerificationPolicy,
) -> VerificationStatus:
    statuses = {item.status for item in assertion_results}
    if VerificationAssertionStatus.CONTRADICTORY in statuses:
        return VerificationStatus.CONTRADICTORY
    if VerificationAssertionStatus.VERIFICATION_ERROR in statuses:
        return VerificationStatus.VERIFICATION_ERROR
    if VerificationAssertionStatus.UNSUPPORTED in statuses:
        return VerificationStatus.UNSUPPORTED
    if VerificationAssertionStatus.INSUFFICIENT_EVIDENCE in statuses:
        return VerificationStatus.INSUFFICIENT_EVIDENCE
    if policy.human_review_required:
        return VerificationStatus.POLICY_BLOCKED
    return VerificationStatus.SUPPORTED


def finalize_verification(
    state: VerificationOrchestrationState,
    request: BrainRequest,
    decision: RoutingDecision,
    snapshot: CapabilitySnapshot,
    termination_requirement: TerminationRequirement,
    *,
    current_binding: RoutingSecurityBinding,
    finished_at: datetime,
) -> VerificationResult:
    """Finalize explicit verification status without promoting generation to fact."""
    if not isinstance(state, VerificationOrchestrationState):
        raise VerificationOrchestrationError(
            "state must be a VerificationOrchestrationState"
        )
    now = _require_utc_datetime(finished_at, field_name="finished_at")
    if now < state.started_at:
        raise VerificationOrchestrationError(
            "finished_at must not be earlier than orchestration start"
        )
    _validate_common_bindings(
        request,
        decision,
        state.lifecycle,
        snapshot,
        current_binding,
        observed_at=now,
    )
    _validate_termination_requirement(
        termination_requirement,
        request=request,
        decision=decision,
        observed_at=now,
    )
    if state.request_id != request.request_id:
        raise VerificationOrchestrationError("state request_id must match request")
    if state.routing_decision_id != decision.decision_id:
        raise VerificationOrchestrationError(
            "state routing_decision_id must match decision"
        )
    if state.correlation_id != request.correlation_id:
        raise VerificationOrchestrationError(
            "state correlation_id must match request"
        )

    evidence_by_ref = {item.evidence_ref: item for item in state.evidence_catalog}
    assertion_results = tuple(
        _assertion_result(
            assertion_id,
            state.observations,
            evidence_by_ref,
            state.policy,
            snapshot,
        )
        for assertion_id in state.policy.required_assertions
    )

    if termination_requirement.required:
        if termination_requirement.reason is TerminationReason.DEADLINE:
            status = VerificationStatus.DEADLINE
        else:
            status = VerificationStatus.CANCELLED
    else:
        deadline = _effective_deadline(request, state.policy)
        if deadline is not None and now >= deadline:
            status = VerificationStatus.DEADLINE
        else:
            status = _overall_status(assertion_results, state.policy)

    evidence_refs = tuple(
        sorted({ref for item in state.observations for ref in item.evidence_refs})
    )
    verifier_identities = tuple(
        sorted(
            {item.verifier_id for item in state.observations},
            key=lambda item: item.value,
        )
    )
    method_versions = tuple(
        sorted(
            {
                f"{item.verifier_id.value}@{item.method_version}"
                for item in state.observations
            }
        )
    )
    contradictions = tuple(
        sorted({ref for item in state.observations for ref in item.contradictions})
    )
    limitations = tuple(
        sorted({ref for item in state.observations for ref in item.limitations})
    )
    provenance = (
        f"verification-policy:{state.policy.policy_id}@{state.policy.policy_version}",
        f"routing-decision:{decision.decision_id.value}",
        f"capability-snapshot:{snapshot.snapshot_id.value}",
    )
    return VerificationResult(
        request_id=state.request_id,
        routing_decision_id=state.routing_decision_id,
        correlation_id=state.correlation_id,
        subject_ref=state.subject_ref,
        policy_id=state.policy.policy_id,
        policy_version=state.policy.policy_version,
        status=status,
        assertion_results=assertion_results,
        evidence_refs=evidence_refs,
        verifier_identities=verifier_identities,
        method_versions=method_versions,
        contradictions=contradictions,
        limitations=limitations,
        budget_state=state.lifecycle.budget_state,
        started_at=state.started_at,
        finished_at=now,
        provenance=provenance,
    )
