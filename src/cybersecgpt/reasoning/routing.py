"""Immutable P5 routing decisions and deterministic validity checks."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from cybersecgpt.foundation import (
    RoutingDecisionId,
    RoutingSecurityBinding,
    SubstrateId,
)

from .budget import (
    ReasoningBudget,
    ReasoningBudgetDelta,
    ReasoningBudgetUsage,
    consume_reasoning_budget,
)
from .errors import (
    RoutingDecisionError,
    RoutingDecisionValidationError,
    RoutingReasoningBudgetError,
)

__all__ = [
    "RoutingDecision",
    "RoutingDecisionInvalidReason",
    "RoutingDecisionReasonCode",
    "RoutingDecisionValidation",
    "RoutingReasoningBudgetUsage",
    "begin_routing_reasoning_budget",
    "consume_routing_reasoning_budget",
    "validate_routing_decision",
]


class RoutingDecisionReasonCode(StrEnum):
    """Structured factors allowed in the initial P5 routing contract."""

    CAPABILITY_MATCH = "CAPABILITY_MATCH"
    OFFLINE_REQUIRED = "OFFLINE_REQUIRED"
    DETERMINISTIC_ROUTE_REQUIRED = "DETERMINISTIC_ROUTE_REQUIRED"
    SECURITY_POLICY_RESTRICTION = "SECURITY_POLICY_RESTRICTION"
    DATA_CLASSIFICATION_RESTRICTION = "DATA_CLASSIFICATION_RESTRICTION"
    LOWER_RESOURCE_ROUTE_SUFFICIENT = "LOWER_RESOURCE_ROUTE_SUFFICIENT"
    PRIMARY_ROUTE_UNAVAILABLE = "PRIMARY_ROUTE_UNAVAILABLE"
    VERIFICATION_ESCALATION = "VERIFICATION_ESCALATION"
    UNCERTAINTY_ESCALATION = "UNCERTAINTY_ESCALATION"
    DEADLINE_RESTRICTION = "DEADLINE_RESTRICTION"
    STALE_DECISION_REJECTED = "STALE_DECISION_REJECTED"


class RoutingDecisionInvalidReason(StrEnum):
    """Machine-evaluable reasons that a routing decision cannot be reused."""

    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRED = "EXPIRED"
    REQUEST_MISMATCH = "REQUEST_MISMATCH"
    AUTHORIZATION_CONTEXT_MISMATCH = "AUTHORIZATION_CONTEXT_MISMATCH"
    SECURITY_POLICY_REVISION_MISMATCH = "SECURITY_POLICY_REVISION_MISMATCH"
    EFFECTIVE_DATA_CLASSIFICATION_MISMATCH = "EFFECTIVE_DATA_CLASSIFICATION_MISMATCH"
    PROVIDER_NETWORK_POLICY_MISMATCH = "PROVIDER_NETWORK_POLICY_MISMATCH"
    OFFLINE_REQUIREMENT_MISMATCH = "OFFLINE_REQUIREMENT_MISMATCH"
    CAPABILITY_SNAPSHOT_MISMATCH = "CAPABILITY_SNAPSHOT_MISMATCH"


def _require_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise RoutingDecisionError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise RoutingDecisionError(
            f"{field_name} must be non-empty and have no surrounding whitespace"
        )
    return value


def _require_utc_datetime(
    value: object,
    *,
    field_name: str,
    error_type: type[RoutingDecisionError],
) -> datetime:
    if not isinstance(value, datetime):
        raise error_type(f"{field_name} must be a datetime")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise error_type(f"{field_name} must be timezone-aware UTC")
    return value


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    """Store one immutable admitted routing decision.

    This object is control metadata, not an authorization grant.
    """

    decision_id: RoutingDecisionId
    security_binding: RoutingSecurityBinding
    router_policy_id: str
    router_policy_version: str
    selected_substrates: tuple[SubstrateId, ...]
    reason_codes: tuple[RoutingDecisionReasonCode, ...]
    reasoning_budget: ReasoningBudget
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.decision_id, RoutingDecisionId):
            raise RoutingDecisionError("decision_id must be a RoutingDecisionId")
        if not isinstance(self.security_binding, RoutingSecurityBinding):
            raise RoutingDecisionError(
                "security_binding must be a RoutingSecurityBinding"
            )

        _require_text(self.router_policy_id, field_name="router_policy_id")
        _require_text(
            self.router_policy_version,
            field_name="router_policy_version",
        )

        if not isinstance(self.selected_substrates, tuple):
            raise RoutingDecisionError("selected_substrates must be a tuple")
        if not self.selected_substrates:
            raise RoutingDecisionError("selected_substrates must not be empty")
        if not all(
            isinstance(substrate_id, SubstrateId)
            for substrate_id in self.selected_substrates
        ):
            raise RoutingDecisionError(
                "selected_substrates must contain only SubstrateId values"
            )
        if len(set(self.selected_substrates)) != len(self.selected_substrates):
            raise RoutingDecisionError(
                "selected_substrates must not contain duplicates"
            )

        if not isinstance(self.reason_codes, tuple):
            raise RoutingDecisionError("reason_codes must be a tuple")
        if not self.reason_codes:
            raise RoutingDecisionError("reason_codes must not be empty")
        if not all(
            isinstance(reason_code, RoutingDecisionReasonCode)
            for reason_code in self.reason_codes
        ):
            raise RoutingDecisionError(
                "reason_codes must contain only RoutingDecisionReasonCode values"
            )
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise RoutingDecisionError("reason_codes must not contain duplicates")

        if not isinstance(self.reasoning_budget, ReasoningBudget):
            raise RoutingDecisionError("reasoning_budget must be a ReasoningBudget")

        created_at = _require_utc_datetime(
            self.created_at,
            field_name="created_at",
            error_type=RoutingDecisionError,
        )
        expires_at = _require_utc_datetime(
            self.expires_at,
            field_name="expires_at",
            error_type=RoutingDecisionError,
        )
        if expires_at <= created_at:
            raise RoutingDecisionError("expires_at must be later than created_at")


@dataclass(frozen=True, slots=True)
class RoutingDecisionValidation:
    """Return deterministic routing-decision validity without granting permission."""

    decision_id: RoutingDecisionId
    validated_at: datetime
    valid: bool
    invalid_reasons: tuple[RoutingDecisionInvalidReason, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.decision_id, RoutingDecisionId):
            raise RoutingDecisionValidationError(
                "decision_id must be a RoutingDecisionId"
            )
        _require_utc_datetime(
            self.validated_at,
            field_name="validated_at",
            error_type=RoutingDecisionValidationError,
        )
        if not isinstance(self.valid, bool):
            raise RoutingDecisionValidationError("valid must be a bool")
        if not isinstance(self.invalid_reasons, tuple):
            raise RoutingDecisionValidationError("invalid_reasons must be a tuple")
        if not all(
            isinstance(reason, RoutingDecisionInvalidReason)
            for reason in self.invalid_reasons
        ):
            raise RoutingDecisionValidationError(
                "invalid_reasons must contain only RoutingDecisionInvalidReason values"
            )
        if len(set(self.invalid_reasons)) != len(self.invalid_reasons):
            raise RoutingDecisionValidationError(
                "invalid_reasons must not contain duplicates"
            )
        if self.valid != (not self.invalid_reasons):
            raise RoutingDecisionValidationError(
                "valid must be true exactly when invalid_reasons is empty"
            )


@dataclass(frozen=True, slots=True)
class RoutingReasoningBudgetUsage:
    """Bind one immutable budget-usage ledger to one routing decision identity."""

    decision_id: RoutingDecisionId
    usage: ReasoningBudgetUsage

    def __post_init__(self) -> None:
        if not isinstance(self.decision_id, RoutingDecisionId):
            raise RoutingReasoningBudgetError("decision_id must be a RoutingDecisionId")
        if not isinstance(self.usage, ReasoningBudgetUsage):
            raise RoutingReasoningBudgetError("usage must be a ReasoningBudgetUsage")


def begin_routing_reasoning_budget(
    decision: RoutingDecision,
) -> RoutingReasoningBudgetUsage:
    """Create a zero-usage ledger bound to the decision's admitted budget."""
    if not isinstance(decision, RoutingDecision):
        raise RoutingReasoningBudgetError("decision must be a RoutingDecision")
    return RoutingReasoningBudgetUsage(
        decision_id=decision.decision_id,
        usage=ReasoningBudgetUsage(budget=decision.reasoning_budget),
    )


def consume_routing_reasoning_budget(
    decision: RoutingDecision,
    state: RoutingReasoningBudgetUsage,
    delta: ReasoningBudgetDelta,
) -> RoutingReasoningBudgetUsage:
    """Consume budget only when the ledger remains bound to the same decision."""
    if not isinstance(decision, RoutingDecision):
        raise RoutingReasoningBudgetError("decision must be a RoutingDecision")
    if not isinstance(state, RoutingReasoningBudgetUsage):
        raise RoutingReasoningBudgetError("state must be a RoutingReasoningBudgetUsage")
    if state.decision_id != decision.decision_id:
        raise RoutingReasoningBudgetError(
            "budget usage routing decision does not match the admitted decision"
        )
    if state.usage.budget != decision.reasoning_budget:
        raise RoutingReasoningBudgetError(
            "budget usage does not match the admitted routing decision budget"
        )

    return RoutingReasoningBudgetUsage(
        decision_id=state.decision_id,
        usage=consume_reasoning_budget(state.usage, delta),
    )


def validate_routing_decision(
    decision: RoutingDecision,
    *,
    current_binding: RoutingSecurityBinding,
    now: datetime,
) -> RoutingDecisionValidation:
    """Validate lifetime and exact security-binding freshness.

    This function does not authenticate the supplied binding, evaluate policy,
    authorize a target, consume a grant, or permit a side effect.
    """
    if not isinstance(decision, RoutingDecision):
        raise RoutingDecisionValidationError("decision must be a RoutingDecision")
    if not isinstance(current_binding, RoutingSecurityBinding):
        raise RoutingDecisionValidationError(
            "current_binding must be a RoutingSecurityBinding"
        )
    validated_at = _require_utc_datetime(
        now,
        field_name="now",
        error_type=RoutingDecisionValidationError,
    )

    invalid_reasons: list[RoutingDecisionInvalidReason] = []

    if validated_at < decision.created_at:
        invalid_reasons.append(RoutingDecisionInvalidReason.NOT_YET_VALID)
    if validated_at >= decision.expires_at:
        invalid_reasons.append(RoutingDecisionInvalidReason.EXPIRED)

    admitted = decision.security_binding
    if current_binding.request_id != admitted.request_id:
        invalid_reasons.append(RoutingDecisionInvalidReason.REQUEST_MISMATCH)
    if current_binding.authorization_context_id != admitted.authorization_context_id:
        invalid_reasons.append(
            RoutingDecisionInvalidReason.AUTHORIZATION_CONTEXT_MISMATCH
        )
    if (
        current_binding.security_policy_revision_id
        != admitted.security_policy_revision_id
    ):
        invalid_reasons.append(
            RoutingDecisionInvalidReason.SECURITY_POLICY_REVISION_MISMATCH
        )
    if (
        current_binding.effective_data_classification
        != admitted.effective_data_classification
    ):
        invalid_reasons.append(
            RoutingDecisionInvalidReason.EFFECTIVE_DATA_CLASSIFICATION_MISMATCH
        )
    if current_binding.provider_network_policy != admitted.provider_network_policy:
        invalid_reasons.append(
            RoutingDecisionInvalidReason.PROVIDER_NETWORK_POLICY_MISMATCH
        )
    if current_binding.offline_required != admitted.offline_required:
        invalid_reasons.append(
            RoutingDecisionInvalidReason.OFFLINE_REQUIREMENT_MISMATCH
        )
    if current_binding.capability_snapshot_id != admitted.capability_snapshot_id:
        invalid_reasons.append(
            RoutingDecisionInvalidReason.CAPABILITY_SNAPSHOT_MISMATCH
        )

    reasons = tuple(invalid_reasons)
    return RoutingDecisionValidation(
        decision_id=decision.decision_id,
        validated_at=validated_at,
        valid=not reasons,
        invalid_reasons=reasons,
    )
