"""Deterministic P5 cancellation and deadline propagation control."""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from cybersecgpt.foundation import CorrelationId, RequestId, RoutingDecisionId, SubstrateId

from .errors import TerminationPropagationError
from .lifecycle import ReasoningLifecycleSnapshot
from .request import BrainRequest
from .routing import RoutingDecision

__all__ = [
    "TerminationAcknowledgement",
    "TerminationAcknowledgementState",
    "TerminationPropagation",
    "TerminationPropagationEvaluation",
    "TerminationPropagationStatus",
    "TerminationReason",
    "TerminationRequirement",
    "TerminationTarget",
    "TerminationTargetKind",
    "acknowledge_termination_target",
    "begin_termination_propagation",
    "evaluate_termination_propagation",
    "evaluate_termination_requirement",
]

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class TerminationReason(StrEnum):
    """Machine-evaluable reasons that new execution must stop."""

    CANCELLATION = "CANCELLATION"
    DEADLINE = "DEADLINE"
    TERMINAL_STATE = "TERMINAL_STATE"


class TerminationTargetKind(StrEnum):
    """Active component classes that can receive a stop request."""

    MODEL = "MODEL"
    RETRIEVAL = "RETRIEVAL"
    TOOL = "TOOL"
    VERIFIER = "VERIFIER"


class TerminationAcknowledgementState(StrEnum):
    """Externally observed stop state for one active component."""

    STOPPED = "STOPPED"
    CLEANUP_PENDING = "CLEANUP_PENDING"
    FAILED_TO_STOP = "FAILED_TO_STOP"


class TerminationPropagationStatus(StrEnum):
    """Aggregate propagation state independent of deadline timing."""

    PENDING = "PENDING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


def _require_token(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TerminationPropagationError(f"{field_name} must be a string")
    if _TOKEN_PATTERN.fullmatch(value) is None:
        raise TerminationPropagationError(
            f"{field_name} must be a machine-evaluable token of at most 128 characters"
        )
    return value


def _require_optional_token(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_token(value, field_name=field_name)


def _require_utc_datetime(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TerminationPropagationError(f"{field_name} must be a datetime")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise TerminationPropagationError(f"{field_name} must be timezone-aware UTC")
    return value


def _require_sequence(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TerminationPropagationError("sequence must be a non-negative integer")
    return value


def _validate_execution_bindings(
    request: BrainRequest,
    decision: RoutingDecision,
    lifecycle: ReasoningLifecycleSnapshot,
) -> None:
    if decision.security_binding != request.security_binding:
        raise TerminationPropagationError(
            "routing decision security binding must match the admitted request"
        )
    if lifecycle.routing_decision_id != decision.decision_id:
        raise TerminationPropagationError(
            "lifecycle routing decision must match the supplied decision"
        )
    if lifecycle.correlation_id != request.correlation_id:
        raise TerminationPropagationError(
            "lifecycle correlation identity must match the admitted request"
        )


@dataclass(frozen=True, slots=True)
class TerminationRequirement:
    """Record whether cancellation/deadline control requires a safe stop.

    ``required=False`` means only that this termination layer has not observed a
    stop condition. It is never permission to execute or perform a side effect.
    """

    request_id: RequestId
    routing_decision_id: RoutingDecisionId
    correlation_id: CorrelationId
    evaluated_at: datetime
    required: bool
    reason: TerminationReason | None
    triggered_at: datetime | None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, RequestId):
            raise TerminationPropagationError("request_id must be a RequestId")
        if not isinstance(self.routing_decision_id, RoutingDecisionId):
            raise TerminationPropagationError(
                "routing_decision_id must be a RoutingDecisionId"
            )
        if not isinstance(self.correlation_id, CorrelationId):
            raise TerminationPropagationError("correlation_id must be a CorrelationId")
        evaluated_at = _require_utc_datetime(
            self.evaluated_at,
            field_name="evaluated_at",
        )
        if not isinstance(self.required, bool):
            raise TerminationPropagationError("required must be a bool")
        if self.reason is not None and not isinstance(self.reason, TerminationReason):
            raise TerminationPropagationError("reason must be a TerminationReason or None")
        if self.triggered_at is not None:
            triggered_at = _require_utc_datetime(
                self.triggered_at,
                field_name="triggered_at",
            )
            if triggered_at > evaluated_at:
                raise TerminationPropagationError(
                    "triggered_at must not be later than evaluated_at"
                )
        if self.required != (self.reason is not None):
            raise TerminationPropagationError(
                "required must be true exactly when a termination reason exists"
            )
        if self.required != (self.triggered_at is not None):
            raise TerminationPropagationError(
                "required must be true exactly when triggered_at exists"
            )


@dataclass(frozen=True, slots=True)
class TerminationTarget:
    """Identify one externally active component to receive a safe-stop request."""

    target_ref: str
    substrate_id: SubstrateId
    target_kind: TerminationTargetKind
    side_effect_capable: bool
    cleanup_required: bool

    def __post_init__(self) -> None:
        _require_token(self.target_ref, field_name="target_ref")
        if not isinstance(self.substrate_id, SubstrateId):
            raise TerminationPropagationError("substrate_id must be a SubstrateId")
        if not isinstance(self.target_kind, TerminationTargetKind):
            raise TerminationPropagationError(
                "target_kind must be a TerminationTargetKind"
            )
        if not isinstance(self.side_effect_capable, bool):
            raise TerminationPropagationError("side_effect_capable must be a bool")
        if not isinstance(self.cleanup_required, bool):
            raise TerminationPropagationError("cleanup_required must be a bool")


@dataclass(frozen=True, slots=True)
class TerminationAcknowledgement:
    """Record an external component's immutable response to a stop request."""

    target_ref: str
    state: TerminationAcknowledgementState
    acknowledged_at: datetime
    evidence_preserved_or_not_applicable: bool
    detail_code: str
    cleanup_authorization_ref: str | None = None

    def __post_init__(self) -> None:
        _require_token(self.target_ref, field_name="target_ref")
        if not isinstance(self.state, TerminationAcknowledgementState):
            raise TerminationPropagationError(
                "state must be a TerminationAcknowledgementState"
            )
        _require_utc_datetime(self.acknowledged_at, field_name="acknowledged_at")
        if not isinstance(self.evidence_preserved_or_not_applicable, bool):
            raise TerminationPropagationError(
                "evidence_preserved_or_not_applicable must be a bool"
            )
        _require_token(self.detail_code, field_name="detail_code")
        _require_optional_token(
            self.cleanup_authorization_ref,
            field_name="cleanup_authorization_ref",
        )
        if self.state is TerminationAcknowledgementState.STOPPED:
            if not self.evidence_preserved_or_not_applicable:
                raise TerminationPropagationError(
                    "STOPPED acknowledgement must preserve evidence or mark it not applicable"
                )
        if self.state is TerminationAcknowledgementState.CLEANUP_PENDING:
            if self.cleanup_authorization_ref is None:
                raise TerminationPropagationError(
                    "CLEANUP_PENDING requires an external cleanup_authorization_ref"
                )


@dataclass(frozen=True, slots=True)
class TerminationPropagation:
    """Store immutable cancellation/deadline propagation state.

    Once this object exists, the represented execution is stop-required and this
    control layer never permits a new side effect. Runtime owners perform the
    actual stop/cleanup actions and return acknowledgements.
    """

    request_id: RequestId
    routing_decision_id: RoutingDecisionId
    correlation_id: CorrelationId
    reason: TerminationReason
    triggered_at: datetime
    propagation_started_at: datetime
    propagation_deadline: datetime
    targets: tuple[TerminationTarget, ...]
    acknowledgements: tuple[TerminationAcknowledgement, ...]
    sequence: int

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, RequestId):
            raise TerminationPropagationError("request_id must be a RequestId")
        if not isinstance(self.routing_decision_id, RoutingDecisionId):
            raise TerminationPropagationError(
                "routing_decision_id must be a RoutingDecisionId"
            )
        if not isinstance(self.correlation_id, CorrelationId):
            raise TerminationPropagationError("correlation_id must be a CorrelationId")
        if self.reason not in {
            TerminationReason.CANCELLATION,
            TerminationReason.DEADLINE,
        }:
            raise TerminationPropagationError(
                "propagation reason must be CANCELLATION or DEADLINE"
            )
        triggered_at = _require_utc_datetime(
            self.triggered_at,
            field_name="triggered_at",
        )
        propagation_started_at = _require_utc_datetime(
            self.propagation_started_at,
            field_name="propagation_started_at",
        )
        propagation_deadline = _require_utc_datetime(
            self.propagation_deadline,
            field_name="propagation_deadline",
        )
        if triggered_at > propagation_started_at:
            raise TerminationPropagationError(
                "triggered_at must not be later than propagation_started_at"
            )
        if propagation_deadline <= propagation_started_at:
            raise TerminationPropagationError(
                "propagation_deadline must be later than propagation_started_at"
            )
        if not isinstance(self.targets, tuple):
            raise TerminationPropagationError("targets must be a tuple")
        if not all(isinstance(target, TerminationTarget) for target in self.targets):
            raise TerminationPropagationError(
                "targets must contain only TerminationTarget values"
            )
        target_refs = tuple(target.target_ref for target in self.targets)
        if len(set(target_refs)) != len(target_refs):
            raise TerminationPropagationError("targets must not contain duplicate refs")
        if target_refs != tuple(sorted(target_refs)):
            raise TerminationPropagationError("targets must be sorted by target_ref")
        if not isinstance(self.acknowledgements, tuple):
            raise TerminationPropagationError("acknowledgements must be a tuple")
        if not all(
            isinstance(item, TerminationAcknowledgement)
            for item in self.acknowledgements
        ):
            raise TerminationPropagationError(
                "acknowledgements must contain only TerminationAcknowledgement values"
            )
        acknowledgement_refs = tuple(
            item.target_ref for item in self.acknowledgements
        )
        if len(set(acknowledgement_refs)) != len(acknowledgement_refs):
            raise TerminationPropagationError(
                "acknowledgements must not contain duplicate target refs"
            )
        if acknowledgement_refs != tuple(sorted(acknowledgement_refs)):
            raise TerminationPropagationError(
                "acknowledgements must be sorted by target_ref"
            )
        if not set(acknowledgement_refs).issubset(target_refs):
            raise TerminationPropagationError(
                "acknowledgements must refer only to declared termination targets"
            )
        for acknowledgement in self.acknowledgements:
            if acknowledgement.acknowledged_at < propagation_started_at:
                raise TerminationPropagationError(
                    "acknowledgement cannot predate propagation_started_at"
                )
        sequence = _require_sequence(self.sequence)
        if sequence != len(self.acknowledgements):
            raise TerminationPropagationError(
                "sequence must equal the number of immutable acknowledgements"
            )

    @property
    def blocks_new_side_effects(self) -> bool:
        """Return the invariant enforced by every propagation state."""
        return True


@dataclass(frozen=True, slots=True)
class TerminationPropagationEvaluation:
    """Summarize stop/cleanup acknowledgement state without executing cleanup."""

    request_id: RequestId
    routing_decision_id: RoutingDecisionId
    evaluated_at: datetime
    status: TerminationPropagationStatus
    deadline_exceeded: bool
    pending_target_refs: tuple[str, ...]
    cleanup_pending_target_refs: tuple[str, ...]
    failed_target_refs: tuple[str, ...]
    late_ack_target_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, RequestId):
            raise TerminationPropagationError("request_id must be a RequestId")
        if not isinstance(self.routing_decision_id, RoutingDecisionId):
            raise TerminationPropagationError(
                "routing_decision_id must be a RoutingDecisionId"
            )
        _require_utc_datetime(self.evaluated_at, field_name="evaluated_at")
        if not isinstance(self.status, TerminationPropagationStatus):
            raise TerminationPropagationError(
                "status must be a TerminationPropagationStatus"
            )
        if not isinstance(self.deadline_exceeded, bool):
            raise TerminationPropagationError("deadline_exceeded must be a bool")
        for field_name, value in (
            ("pending_target_refs", self.pending_target_refs),
            ("cleanup_pending_target_refs", self.cleanup_pending_target_refs),
            ("failed_target_refs", self.failed_target_refs),
            ("late_ack_target_refs", self.late_ack_target_refs),
        ):
            if not isinstance(value, tuple):
                raise TerminationPropagationError(f"{field_name} must be a tuple")
            for item in value:
                _require_token(item, field_name=f"{field_name} item")
            if len(set(value)) != len(value):
                raise TerminationPropagationError(
                    f"{field_name} must not contain duplicates"
                )
            if value != tuple(sorted(value)):
                raise TerminationPropagationError(f"{field_name} must be sorted")


def evaluate_termination_requirement(
    request: BrainRequest,
    decision: RoutingDecision,
    lifecycle: ReasoningLifecycleSnapshot,
    *,
    observed_at: datetime,
    cancellation_requested_at: datetime | None = None,
) -> TerminationRequirement:
    """Determine whether cancellation/deadline control requires a safe stop.

    A non-required result is not an authorization result. Callers must still use
    the authoritative security-policy and side-effect admission boundaries.
    """
    if not isinstance(request, BrainRequest):
        raise TerminationPropagationError("request must be a BrainRequest")
    if not isinstance(decision, RoutingDecision):
        raise TerminationPropagationError("decision must be a RoutingDecision")
    if not isinstance(lifecycle, ReasoningLifecycleSnapshot):
        raise TerminationPropagationError(
            "lifecycle must be a ReasoningLifecycleSnapshot"
        )
    now = _require_utc_datetime(observed_at, field_name="observed_at")
    if now < request.admitted_at:
        raise TerminationPropagationError("observed_at cannot predate request admission")
    _validate_execution_bindings(request, decision, lifecycle)

    cancellation_at: datetime | None = None
    if cancellation_requested_at is not None:
        cancellation_at = _require_utc_datetime(
            cancellation_requested_at,
            field_name="cancellation_requested_at",
        )
        if cancellation_at < request.admitted_at:
            raise TerminationPropagationError(
                "cancellation_requested_at cannot predate request admission"
            )

    if lifecycle.state.is_terminal:
        return TerminationRequirement(
            request_id=request.request_id,
            routing_decision_id=decision.decision_id,
            correlation_id=request.correlation_id,
            evaluated_at=now,
            required=True,
            reason=TerminationReason.TERMINAL_STATE,
            triggered_at=now,
        )

    deadline = request.deadline
    reached_cancellation = cancellation_at is not None and cancellation_at <= now
    reached_deadline = deadline is not None and deadline <= now

    if reached_cancellation and reached_deadline:
        if deadline <= cancellation_at:
            reason = TerminationReason.DEADLINE
            triggered_at = deadline
        else:
            reason = TerminationReason.CANCELLATION
            triggered_at = cancellation_at
    elif reached_cancellation:
        reason = TerminationReason.CANCELLATION
        triggered_at = cancellation_at
    elif reached_deadline:
        reason = TerminationReason.DEADLINE
        triggered_at = deadline
    else:
        reason = None
        triggered_at = None

    return TerminationRequirement(
        request_id=request.request_id,
        routing_decision_id=decision.decision_id,
        correlation_id=request.correlation_id,
        evaluated_at=now,
        required=reason is not None,
        reason=reason,
        triggered_at=triggered_at,
    )


def begin_termination_propagation(
    request: BrainRequest,
    decision: RoutingDecision,
    lifecycle: ReasoningLifecycleSnapshot,
    requirement: TerminationRequirement,
    *,
    targets: tuple[TerminationTarget, ...],
    propagation_deadline: datetime,
) -> TerminationPropagation:
    """Create an immutable stop request for the currently active component set."""
    if not isinstance(request, BrainRequest):
        raise TerminationPropagationError("request must be a BrainRequest")
    if not isinstance(decision, RoutingDecision):
        raise TerminationPropagationError("decision must be a RoutingDecision")
    if not isinstance(lifecycle, ReasoningLifecycleSnapshot):
        raise TerminationPropagationError(
            "lifecycle must be a ReasoningLifecycleSnapshot"
        )
    if not isinstance(requirement, TerminationRequirement):
        raise TerminationPropagationError(
            "requirement must be a TerminationRequirement"
        )
    _validate_execution_bindings(request, decision, lifecycle)
    if not requirement.required or requirement.reason not in {
        TerminationReason.CANCELLATION,
        TerminationReason.DEADLINE,
    }:
        raise TerminationPropagationError(
            "propagation requires an active cancellation or deadline condition"
        )
    if requirement.request_id != request.request_id:
        raise TerminationPropagationError("requirement request_id does not match request")
    if requirement.routing_decision_id != decision.decision_id:
        raise TerminationPropagationError(
            "requirement routing_decision_id does not match decision"
        )
    if requirement.correlation_id != request.correlation_id:
        raise TerminationPropagationError(
            "requirement correlation_id does not match request"
        )
    if requirement.triggered_at is None:
        raise TerminationPropagationError("required termination must have triggered_at")
    if not isinstance(targets, tuple):
        raise TerminationPropagationError("targets must be a tuple")
    if not all(isinstance(target, TerminationTarget) for target in targets):
        raise TerminationPropagationError(
            "targets must contain only TerminationTarget values"
        )
    ordered_targets = tuple(sorted(targets, key=lambda item: item.target_ref))
    target_refs = tuple(target.target_ref for target in ordered_targets)
    if len(set(target_refs)) != len(target_refs):
        raise TerminationPropagationError("targets must not contain duplicate refs")
    stop_deadline = _require_utc_datetime(
        propagation_deadline,
        field_name="propagation_deadline",
    )
    if stop_deadline <= requirement.evaluated_at:
        raise TerminationPropagationError(
            "propagation_deadline must be later than requirement evaluation"
        )

    return TerminationPropagation(
        request_id=request.request_id,
        routing_decision_id=decision.decision_id,
        correlation_id=request.correlation_id,
        reason=requirement.reason,
        triggered_at=requirement.triggered_at,
        propagation_started_at=requirement.evaluated_at,
        propagation_deadline=stop_deadline,
        targets=ordered_targets,
        acknowledgements=(),
        sequence=0,
    )


def acknowledge_termination_target(
    propagation: TerminationPropagation,
    acknowledgement: TerminationAcknowledgement,
) -> TerminationPropagation:
    """Append exactly one immutable external stop/cleanup acknowledgement."""
    if not isinstance(propagation, TerminationPropagation):
        raise TerminationPropagationError(
            "propagation must be a TerminationPropagation"
        )
    if not isinstance(acknowledgement, TerminationAcknowledgement):
        raise TerminationPropagationError(
            "acknowledgement must be a TerminationAcknowledgement"
        )
    target_refs = {target.target_ref for target in propagation.targets}
    acknowledged_refs = {
        item.target_ref for item in propagation.acknowledgements
    }
    if acknowledgement.target_ref not in target_refs:
        raise TerminationPropagationError(
            "acknowledgement target is not part of this propagation"
        )
    if acknowledgement.target_ref in acknowledged_refs:
        raise TerminationPropagationError(
            "termination target has already acknowledged this propagation"
        )
    if acknowledgement.acknowledged_at < propagation.propagation_started_at:
        raise TerminationPropagationError(
            "acknowledgement cannot predate propagation_started_at"
        )

    acknowledgements = tuple(
        sorted(
            (*propagation.acknowledgements, acknowledgement),
            key=lambda item: item.target_ref,
        )
    )
    return TerminationPropagation(
        request_id=propagation.request_id,
        routing_decision_id=propagation.routing_decision_id,
        correlation_id=propagation.correlation_id,
        reason=propagation.reason,
        triggered_at=propagation.triggered_at,
        propagation_started_at=propagation.propagation_started_at,
        propagation_deadline=propagation.propagation_deadline,
        targets=propagation.targets,
        acknowledgements=acknowledgements,
        sequence=propagation.sequence + 1,
    )


def evaluate_termination_propagation(
    propagation: TerminationPropagation,
    *,
    observed_at: datetime,
) -> TerminationPropagationEvaluation:
    """Evaluate stop completion, cleanup/failure state, and deadline compliance."""
    if not isinstance(propagation, TerminationPropagation):
        raise TerminationPropagationError(
            "propagation must be a TerminationPropagation"
        )
    now = _require_utc_datetime(observed_at, field_name="observed_at")
    if now < propagation.propagation_started_at:
        raise TerminationPropagationError(
            "observed_at cannot predate propagation_started_at"
        )

    acknowledgement_by_ref = {
        item.target_ref: item for item in propagation.acknowledgements
    }
    pending = tuple(
        target.target_ref
        for target in propagation.targets
        if target.target_ref not in acknowledgement_by_ref
    )
    cleanup_pending = tuple(
        item.target_ref
        for item in propagation.acknowledgements
        if item.state is TerminationAcknowledgementState.CLEANUP_PENDING
    )
    failed = tuple(
        item.target_ref
        for item in propagation.acknowledgements
        if item.state is TerminationAcknowledgementState.FAILED_TO_STOP
    )
    late = tuple(
        item.target_ref
        for item in propagation.acknowledgements
        if item.acknowledged_at > propagation.propagation_deadline
    )

    if failed:
        status = TerminationPropagationStatus.FAILED
    elif not pending and not cleanup_pending:
        status = TerminationPropagationStatus.COMPLETE
    else:
        status = TerminationPropagationStatus.PENDING

    deadline_exceeded = bool(late) or (
        now >= propagation.propagation_deadline
        and status is not TerminationPropagationStatus.COMPLETE
    )
    return TerminationPropagationEvaluation(
        request_id=propagation.request_id,
        routing_decision_id=propagation.routing_decision_id,
        evaluated_at=now,
        status=status,
        deadline_exceeded=deadline_exceeded,
        pending_target_refs=tuple(sorted(pending)),
        cleanup_pending_target_refs=tuple(sorted(cleanup_pending)),
        failed_target_refs=tuple(sorted(failed)),
        late_ack_target_refs=tuple(sorted(late)),
    )
