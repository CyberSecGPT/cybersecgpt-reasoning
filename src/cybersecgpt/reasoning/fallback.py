"""Deterministic P5 fallback replanning with fresh-route and budget continuity."""

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

from .budget import ReasoningBudgetError, ReasoningBudgetUsage
from .candidates import (
    CandidateSelectionPolicy,
    CandidateSelectionResult,
    select_candidate_substrates,
)
from .errors import FallbackReplanError
from .request import BrainRequest
from .routing import (
    RoutingDecision,
    RoutingDecisionReasonCode,
    RoutingDecisionValidation,
    RoutingReasoningBudgetUsage,
    validate_routing_decision,
)
from .substrates import (
    CapabilitySnapshot,
    SubstrateAvailabilityState,
    SubstrateKind,
    ValidatedSubstrate,
)
from .termination import TerminationRequirement

__all__ = [
    "FallbackReplanPolicy",
    "FallbackReplanResult",
    "FallbackReplanStatus",
    "FallbackTrigger",
    "replan_fallback_route",
]

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_BUDGET_COUNTER_FIELDS = (
    "candidates",
    "branch_depth",
    "steps",
    "model_tokens",
    "tool_calls",
    "retrieval_calls",
    "verifier_passes",
)


class FallbackTrigger(StrEnum):
    """Machine-evaluable reasons that may justify a fresh fallback route."""

    PRIMARY_ROUTE_UNAVAILABLE = "PRIMARY_ROUTE_UNAVAILABLE"
    ROUTE_EXECUTION_FAILURE = "ROUTE_EXECUTION_FAILURE"
    STALE_ROUTING_DECISION = "STALE_ROUTING_DECISION"
    VERIFICATION_ESCALATION = "VERIFICATION_ESCALATION"
    UNCERTAINTY_ESCALATION = "UNCERTAINTY_ESCALATION"


class FallbackReplanStatus(StrEnum):
    """Outcome of deterministic fallback route replanning."""

    ROUTE_SELECTED = "ROUTE_SELECTED"
    NO_VALID_ROUTE = "NO_VALID_ROUTE"


def _require_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise FallbackReplanError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise FallbackReplanError(
            f"{field_name} must be non-empty and have no surrounding whitespace"
        )
    return value


def _require_token(value: object, *, field_name: str) -> str:
    text = _require_text(value, field_name=field_name)
    if _TOKEN_PATTERN.fullmatch(text) is None:
        raise FallbackReplanError(
            f"{field_name} must be a machine-evaluable token of at most 128 characters"
        )
    return text


def _require_utc_datetime(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise FallbackReplanError(f"{field_name} must be a datetime")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise FallbackReplanError(f"{field_name} must be timezone-aware UTC")
    return value


def _require_unique_texts(
    value: object,
    *,
    field_name: str,
    allow_empty: bool,
    tokenized: bool,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise FallbackReplanError(f"{field_name} must be a tuple")
    validator = _require_token if tokenized else _require_text
    values = tuple(
        validator(item, field_name=f"{field_name} item") for item in value
    )
    if not allow_empty and not values:
        raise FallbackReplanError(f"{field_name} must not be empty")
    if len(set(values)) != len(values):
        raise FallbackReplanError(f"{field_name} must not contain duplicates")
    return values


@dataclass(frozen=True, slots=True)
class FallbackReplanPolicy:
    """Explicitly narrow fallback choices without creating authorization.

    The fallback overlay is intentionally separate from the authoritative security
    and candidate-selection policy. Every field can only narrow the candidate
    policy during replanning; it cannot enable a network class, substrate kind,
    degraded route, owner, or fan-out that was not otherwise allowed.
    """

    fallback_policy_id: str
    fallback_policy_version: str
    allowed_triggers: tuple[FallbackTrigger, ...]
    allowed_owner_refs: tuple[str, ...]
    allowed_substrate_kinds: tuple[SubstrateKind, ...]
    allowed_network_requirements: tuple[str, ...]
    allow_degraded: bool
    max_selected_substrates: int
    allow_previous_substrate_reuse: bool = False

    def __post_init__(self) -> None:
        _require_text(self.fallback_policy_id, field_name="fallback_policy_id")
        _require_text(
            self.fallback_policy_version,
            field_name="fallback_policy_version",
        )
        if not isinstance(self.allowed_triggers, tuple):
            raise FallbackReplanError("allowed_triggers must be a tuple")
        if not self.allowed_triggers:
            raise FallbackReplanError("allowed_triggers must not be empty")
        if not all(isinstance(item, FallbackTrigger) for item in self.allowed_triggers):
            raise FallbackReplanError(
                "allowed_triggers must contain only FallbackTrigger values"
            )
        if len(set(self.allowed_triggers)) != len(self.allowed_triggers):
            raise FallbackReplanError("allowed_triggers must not contain duplicates")
        _require_unique_texts(
            self.allowed_owner_refs,
            field_name="allowed_owner_refs",
            allow_empty=False,
            tokenized=False,
        )
        if not isinstance(self.allowed_substrate_kinds, tuple):
            raise FallbackReplanError("allowed_substrate_kinds must be a tuple")
        if not self.allowed_substrate_kinds:
            raise FallbackReplanError("allowed_substrate_kinds must not be empty")
        if not all(
            isinstance(item, SubstrateKind) for item in self.allowed_substrate_kinds
        ):
            raise FallbackReplanError(
                "allowed_substrate_kinds must contain only SubstrateKind values"
            )
        if len(set(self.allowed_substrate_kinds)) != len(self.allowed_substrate_kinds):
            raise FallbackReplanError(
                "allowed_substrate_kinds must not contain duplicates"
            )
        _require_unique_texts(
            self.allowed_network_requirements,
            field_name="allowed_network_requirements",
            allow_empty=True,
            tokenized=True,
        )
        if not isinstance(self.allow_degraded, bool):
            raise FallbackReplanError("allow_degraded must be a bool")
        if (
            not isinstance(self.max_selected_substrates, int)
            or isinstance(self.max_selected_substrates, bool)
            or self.max_selected_substrates <= 0
        ):
            raise FallbackReplanError(
                "max_selected_substrates must be a positive integer"
            )
        if not isinstance(self.allow_previous_substrate_reuse, bool):
            raise FallbackReplanError(
                "allow_previous_substrate_reuse must be a bool"
            )


@dataclass(frozen=True, slots=True)
class FallbackReplanResult:
    """Link one prior decision to a fresh fallback decision or explicit exhaustion."""

    request_id: RequestId
    correlation_id: CorrelationId
    previous_decision_id: RoutingDecisionId
    trigger: FallbackTrigger
    replanned_at: datetime
    policy: FallbackReplanPolicy
    previous_validation: RoutingDecisionValidation
    unavailable_substrates: tuple[SubstrateId, ...]
    candidate_selection: CandidateSelectionResult
    status: FallbackReplanStatus
    replacement_decision: RoutingDecision | None
    replacement_budget_state: RoutingReasoningBudgetUsage | None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, RequestId):
            raise FallbackReplanError("request_id must be a RequestId")
        if not isinstance(self.correlation_id, CorrelationId):
            raise FallbackReplanError("correlation_id must be a CorrelationId")
        if not isinstance(self.previous_decision_id, RoutingDecisionId):
            raise FallbackReplanError(
                "previous_decision_id must be a RoutingDecisionId"
            )
        if not isinstance(self.trigger, FallbackTrigger):
            raise FallbackReplanError("trigger must be a FallbackTrigger")
        _require_utc_datetime(self.replanned_at, field_name="replanned_at")
        if not isinstance(self.policy, FallbackReplanPolicy):
            raise FallbackReplanError("policy must be a FallbackReplanPolicy")
        if not isinstance(self.previous_validation, RoutingDecisionValidation):
            raise FallbackReplanError(
                "previous_validation must be a RoutingDecisionValidation"
            )
        if self.previous_validation.decision_id != self.previous_decision_id:
            raise FallbackReplanError(
                "previous_validation must describe previous_decision_id"
            )
        if not isinstance(self.unavailable_substrates, tuple):
            raise FallbackReplanError("unavailable_substrates must be a tuple")
        if not all(
            isinstance(item, SubstrateId) for item in self.unavailable_substrates
        ):
            raise FallbackReplanError(
                "unavailable_substrates must contain only SubstrateId values"
            )
        unavailable_values = tuple(item.value for item in self.unavailable_substrates)
        if len(set(unavailable_values)) != len(unavailable_values):
            raise FallbackReplanError(
                "unavailable_substrates must not contain duplicates"
            )
        if unavailable_values != tuple(sorted(unavailable_values)):
            raise FallbackReplanError(
                "unavailable_substrates must be sorted by SubstrateId"
            )
        if not isinstance(self.candidate_selection, CandidateSelectionResult):
            raise FallbackReplanError(
                "candidate_selection must be a CandidateSelectionResult"
            )
        if self.candidate_selection.request_id != self.request_id:
            raise FallbackReplanError(
                "candidate_selection request_id must match request_id"
            )
        if not isinstance(self.status, FallbackReplanStatus):
            raise FallbackReplanError("status must be a FallbackReplanStatus")

        selected = self.candidate_selection.selected_substrates
        if self.status is FallbackReplanStatus.ROUTE_SELECTED:
            if not selected:
                raise FallbackReplanError(
                    "ROUTE_SELECTED requires selected fallback substrates"
                )
            if not isinstance(self.replacement_decision, RoutingDecision):
                raise FallbackReplanError(
                    "ROUTE_SELECTED requires a replacement RoutingDecision"
                )
            if not isinstance(
                self.replacement_budget_state,
                RoutingReasoningBudgetUsage,
            ):
                raise FallbackReplanError(
                    "ROUTE_SELECTED requires replacement budget state"
                )
            if self.replacement_decision.decision_id == self.previous_decision_id:
                raise FallbackReplanError(
                    "fallback routing decision must use a fresh identity"
                )
            if self.replacement_decision.selected_substrates != selected:
                raise FallbackReplanError(
                    "replacement decision must match selected fallback substrates"
                )
            if (
                self.replacement_budget_state.decision_id
                != self.replacement_decision.decision_id
            ):
                raise FallbackReplanError(
                    "replacement budget state must bind to replacement decision"
                )
            if (
                self.replacement_budget_state.usage.budget
                != self.replacement_decision.reasoning_budget
            ):
                raise FallbackReplanError(
                    "replacement budget must match replacement decision budget"
                )
        else:
            if selected:
                raise FallbackReplanError(
                    "NO_VALID_ROUTE must not contain selected fallback substrates"
                )
            if self.replacement_decision is not None:
                raise FallbackReplanError(
                    "NO_VALID_ROUTE must not contain a replacement decision"
                )
            if self.replacement_budget_state is not None:
                raise FallbackReplanError(
                    "NO_VALID_ROUTE must not contain replacement budget state"
                )


def _validate_fallback_policy_narrowing(
    fallback_policy: FallbackReplanPolicy,
    candidate_policy: CandidateSelectionPolicy,
) -> None:
    if not set(fallback_policy.allowed_substrate_kinds).issubset(
        candidate_policy.allowed_substrate_kinds
    ):
        raise FallbackReplanError(
            "fallback substrate kinds must be a subset of candidate policy"
        )
    if not set(fallback_policy.allowed_network_requirements).issubset(
        candidate_policy.allowed_network_requirements
    ):
        raise FallbackReplanError(
            "fallback network requirements must be a subset of candidate policy"
        )
    if fallback_policy.allow_degraded and not candidate_policy.allow_degraded:
        raise FallbackReplanError(
            "fallback policy cannot enable degraded routes "
            "disallowed by candidate policy"
        )
    if (
        fallback_policy.max_selected_substrates
        > candidate_policy.max_selected_substrates
    ):
        raise FallbackReplanError(
            "fallback max_selected_substrates cannot exceed candidate policy"
        )


def _validate_request_continuity(
    previous_request: BrainRequest,
    current_request: BrainRequest,
    *,
    current_binding: RoutingSecurityBinding,
    observed_at: datetime,
) -> None:
    if previous_request.request_id != current_request.request_id:
        raise FallbackReplanError("fallback cannot change request identity")
    if previous_request.correlation_id != current_request.correlation_id:
        raise FallbackReplanError("fallback cannot change correlation identity")
    if current_request.security_binding != current_binding:
        raise FallbackReplanError(
            "current request security binding must match current_binding"
        )
    if current_request.admitted_at < previous_request.admitted_at:
        raise FallbackReplanError("current request admission cannot move backward")
    if current_request.admitted_at > observed_at:
        raise FallbackReplanError("current request admission cannot be in the future")

    for field_name in (
        "task_type",
        "domain",
        "task_complexity",
        "safety_impact",
        "source_data_classification",
        "identity_context_ref",
        "input_json",
    ):
        if getattr(previous_request, field_name) != getattr(
            current_request,
            field_name,
        ):
            raise FallbackReplanError(
                f"fallback cannot change request field: {field_name}"
            )

    for field_name in (
        "max_latency_ms",
        "max_compute_units",
        "max_memory_bytes",
    ):
        if getattr(current_request, field_name) > getattr(previous_request, field_name):
            raise FallbackReplanError(
                f"fallback cannot widen request ceiling: {field_name}"
            )

    previous_accuracy = previous_request.required_accuracy
    current_accuracy = current_request.required_accuracy
    if previous_accuracy is not None and (
        current_accuracy is None or current_accuracy < previous_accuracy
    ):
        raise FallbackReplanError("fallback cannot lower required_accuracy")
    if (
        previous_request.required_determinism
        and not current_request.required_determinism
    ):
        raise FallbackReplanError("fallback cannot remove required determinism")
    if (
        previous_request.required_explainability
        and not current_request.required_explainability
    ):
        raise FallbackReplanError("fallback cannot remove required explainability")
    if not set(previous_request.verification_requirements).issubset(
        current_request.verification_requirements
    ):
        raise FallbackReplanError("fallback cannot reduce verification requirements")

    previous_deadline = previous_request.deadline
    current_deadline = current_request.deadline
    if previous_deadline is not None and (
        current_deadline is None or current_deadline > previous_deadline
    ):
        raise FallbackReplanError("fallback cannot extend or remove request deadline")

    previous_binding = previous_request.security_binding
    if (
        current_binding.authorization_context_id
        != previous_binding.authorization_context_id
    ):
        raise FallbackReplanError(
            "fallback cannot substitute authorization context"
        )
    if (
        current_binding.effective_data_classification
        != previous_binding.effective_data_classification
    ):
        raise FallbackReplanError(
            "fallback cannot change effective data classification without "
            "an explicit architecture-supported ordering"
        )
    if (
        current_binding.provider_network_policy
        != previous_binding.provider_network_policy
    ):
        raise FallbackReplanError("fallback cannot change provider/network policy")
    if previous_binding.offline_required and not current_binding.offline_required:
        raise FallbackReplanError("fallback cannot relax offline requirement")


def _carry_budget_usage(
    previous_request: BrainRequest,
    current_request: BrainRequest,
    previous_decision: RoutingDecision,
    previous_budget_state: RoutingReasoningBudgetUsage,
) -> ReasoningBudgetUsage:
    if previous_request.reasoning_budget != previous_decision.reasoning_budget:
        raise FallbackReplanError(
            "previous request budget must match previous routing decision budget"
        )
    if previous_budget_state.decision_id != previous_decision.decision_id:
        raise FallbackReplanError(
            "previous budget state must bind to previous routing decision"
        )
    if previous_budget_state.usage.budget != previous_decision.reasoning_budget:
        raise FallbackReplanError(
            "previous budget usage must match previous routing decision budget"
        )

    previous_budget = previous_decision.reasoning_budget
    current_budget = current_request.reasoning_budget
    if current_budget.policy_name != previous_budget.policy_name:
        raise FallbackReplanError("fallback cannot change reasoning budget policy name")
    if not set(previous_budget.stop_conditions).issubset(
        current_budget.stop_conditions
    ):
        raise FallbackReplanError("fallback cannot remove reasoning stop conditions")
    for field_name in _BUDGET_COUNTER_FIELDS:
        maximum = f"max_{field_name}"
        if getattr(current_budget, maximum) > getattr(previous_budget, maximum):
            raise FallbackReplanError(
                f"fallback cannot enlarge reasoning budget: {maximum}"
            )

    usage = previous_budget_state.usage
    try:
        return ReasoningBudgetUsage(
            budget=current_budget,
            candidates=usage.candidates,
            branch_depth=usage.branch_depth,
            steps=usage.steps,
            model_tokens=usage.model_tokens,
            tool_calls=usage.tool_calls,
            retrieval_calls=usage.retrieval_calls,
            verifier_passes=usage.verifier_passes,
        )
    except ReasoningBudgetError as exc:
        raise FallbackReplanError(
            "fallback budget cannot be narrowed below already consumed usage"
        ) from exc


def _validate_termination_state(
    requirement: TerminationRequirement,
    *,
    current_request: BrainRequest,
    previous_decision: RoutingDecision,
    observed_at: datetime,
) -> None:
    if not isinstance(requirement, TerminationRequirement):
        raise FallbackReplanError(
            "termination_requirement must be a TerminationRequirement"
        )
    if requirement.request_id != current_request.request_id:
        raise FallbackReplanError(
            "termination requirement request_id must match current request"
        )
    if requirement.routing_decision_id != previous_decision.decision_id:
        raise FallbackReplanError(
            "termination requirement must bind to previous routing decision"
        )
    if requirement.correlation_id != current_request.correlation_id:
        raise FallbackReplanError(
            "termination requirement correlation_id must match current request"
        )
    if requirement.evaluated_at != observed_at:
        raise FallbackReplanError(
            "termination requirement must be evaluated at replanning time"
        )
    if requirement.required:
        raise FallbackReplanError(
            "fallback replanning is forbidden after cancellation/deadline stop"
        )


def _fallback_rank_key(substrate: ValidatedSubstrate) -> tuple[int, int, int, int, str]:
    descriptor = substrate.descriptor
    latency = descriptor.resource_profile.max_latency_ms
    if latency is None:
        raise FallbackReplanError(
            "eligible fallback candidate cannot have unbounded latency"
        )
    return (
        int(descriptor.availability_state is SubstrateAvailabilityState.DEGRADED),
        descriptor.resource_profile.min_compute_units,
        descriptor.resource_profile.min_memory_bytes,
        latency,
        descriptor.substrate_id.value,
    )


def _select_fallback_substrates(
    previous_decision: RoutingDecision,
    snapshot: CapabilitySnapshot,
    base_selection: CandidateSelectionResult,
    fallback_policy: FallbackReplanPolicy,
    unavailable_substrates: tuple[SubstrateId, ...],
) -> tuple[SubstrateId, ...]:
    evaluation_by_id = {
        item.substrate_id: item for item in base_selection.evaluations
    }
    excluded = set(unavailable_substrates)
    if not fallback_policy.allow_previous_substrate_reuse:
        excluded.update(previous_decision.selected_substrates)

    candidates: list[ValidatedSubstrate] = []
    allowed_kinds = set(fallback_policy.allowed_substrate_kinds)
    allowed_network = set(fallback_policy.allowed_network_requirements)
    allowed_owners = set(fallback_policy.allowed_owner_refs)
    for substrate in snapshot.substrates:
        descriptor = substrate.descriptor
        evaluation = evaluation_by_id[descriptor.substrate_id]
        if not evaluation.eligible or descriptor.substrate_id in excluded:
            continue
        if descriptor.owner not in allowed_owners:
            continue
        if descriptor.substrate_kind not in allowed_kinds:
            continue
        if not set(descriptor.network_requirements).issubset(allowed_network):
            continue
        if (
            descriptor.availability_state is SubstrateAvailabilityState.DEGRADED
            and not fallback_policy.allow_degraded
        ):
            continue
        candidates.append(substrate)

    candidates.sort(key=_fallback_rank_key)
    return tuple(
        item.descriptor.substrate_id
        for item in candidates[: fallback_policy.max_selected_substrates]
    )


def _with_fallback_selection(
    base: CandidateSelectionResult,
    selected_substrates: tuple[SubstrateId, ...],
) -> CandidateSelectionResult:
    reason_codes = list(base.reason_codes)
    capability_match = RoutingDecisionReasonCode.CAPABILITY_MATCH
    if selected_substrates and capability_match not in reason_codes:
        reason_codes.insert(0, capability_match)
    if not selected_substrates and capability_match in reason_codes:
        reason_codes.remove(capability_match)
    return CandidateSelectionResult(
        request_id=base.request_id,
        capability_snapshot_id=base.capability_snapshot_id,
        policy=base.policy,
        observed_at=base.observed_at,
        evaluations=base.evaluations,
        selected_substrates=selected_substrates,
        reason_codes=tuple(reason_codes),
    )


def _trigger_reason_code(trigger: FallbackTrigger) -> RoutingDecisionReasonCode:
    if trigger in {
        FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE,
        FallbackTrigger.ROUTE_EXECUTION_FAILURE,
    }:
        return RoutingDecisionReasonCode.PRIMARY_ROUTE_UNAVAILABLE
    if trigger is FallbackTrigger.STALE_ROUTING_DECISION:
        return RoutingDecisionReasonCode.STALE_DECISION_REJECTED
    if trigger is FallbackTrigger.VERIFICATION_ESCALATION:
        return RoutingDecisionReasonCode.VERIFICATION_ESCALATION
    return RoutingDecisionReasonCode.UNCERTAINTY_ESCALATION


def _replacement_reason_codes(
    base: CandidateSelectionResult,
    trigger: FallbackTrigger,
) -> tuple[RoutingDecisionReasonCode, ...]:
    codes = list(base.reason_codes)
    trigger_code = _trigger_reason_code(trigger)
    if trigger_code not in codes:
        codes.append(trigger_code)
    return tuple(codes)


def replan_fallback_route(
    previous_request: BrainRequest,
    current_request: BrainRequest,
    previous_decision: RoutingDecision,
    previous_budget_state: RoutingReasoningBudgetUsage,
    snapshot: CapabilitySnapshot,
    candidate_policy: CandidateSelectionPolicy,
    fallback_policy: FallbackReplanPolicy,
    termination_requirement: TerminationRequirement,
    *,
    trigger: FallbackTrigger,
    unavailable_substrates: tuple[SubstrateId, ...],
    current_binding: RoutingSecurityBinding,
    new_decision_id: RoutingDecisionId,
    observed_at: datetime,
    replacement_expires_at: datetime,
) -> FallbackReplanResult:
    """Replan a fresh fallback route without relaxing request/security constraints.

    This function performs deterministic Reasoning-side control validation only.
    It does not authenticate security bindings, grant authorization, execute a
    substrate, call a provider, or perform a side effect.
    """
    if not isinstance(previous_request, BrainRequest):
        raise FallbackReplanError("previous_request must be a BrainRequest")
    if not isinstance(current_request, BrainRequest):
        raise FallbackReplanError("current_request must be a BrainRequest")
    if not isinstance(previous_decision, RoutingDecision):
        raise FallbackReplanError("previous_decision must be a RoutingDecision")
    if not isinstance(previous_budget_state, RoutingReasoningBudgetUsage):
        raise FallbackReplanError(
            "previous_budget_state must be a RoutingReasoningBudgetUsage"
        )
    if not isinstance(snapshot, CapabilitySnapshot):
        raise FallbackReplanError("snapshot must be a CapabilitySnapshot")
    if not isinstance(candidate_policy, CandidateSelectionPolicy):
        raise FallbackReplanError(
            "candidate_policy must be a CandidateSelectionPolicy"
        )
    if not isinstance(fallback_policy, FallbackReplanPolicy):
        raise FallbackReplanError("fallback_policy must be a FallbackReplanPolicy")
    if not isinstance(trigger, FallbackTrigger):
        raise FallbackReplanError("trigger must be a FallbackTrigger")
    if trigger not in fallback_policy.allowed_triggers:
        raise FallbackReplanError("fallback trigger is not allowed by fallback policy")
    if not isinstance(current_binding, RoutingSecurityBinding):
        raise FallbackReplanError(
            "current_binding must be a RoutingSecurityBinding"
        )
    if not isinstance(new_decision_id, RoutingDecisionId):
        raise FallbackReplanError("new_decision_id must be a RoutingDecisionId")
    if new_decision_id == previous_decision.decision_id:
        raise FallbackReplanError("fallback decision must use a fresh identity")
    now = _require_utc_datetime(observed_at, field_name="observed_at")
    expires_at = _require_utc_datetime(
        replacement_expires_at,
        field_name="replacement_expires_at",
    )
    if expires_at <= now:
        raise FallbackReplanError(
            "replacement_expires_at must be later than observed_at"
        )

    if previous_decision.security_binding != previous_request.security_binding:
        raise FallbackReplanError(
            "previous decision security binding must match previous request"
        )
    if previous_request.admitted_at > now:
        raise FallbackReplanError("previous request admission cannot be in the future")
    _validate_request_continuity(
        previous_request,
        current_request,
        current_binding=current_binding,
        observed_at=now,
    )
    _validate_fallback_policy_narrowing(fallback_policy, candidate_policy)
    _validate_termination_state(
        termination_requirement,
        current_request=current_request,
        previous_decision=previous_decision,
        observed_at=now,
    )
    carried_usage = _carry_budget_usage(
        previous_request,
        current_request,
        previous_decision,
        previous_budget_state,
    )

    current_deadline = current_request.deadline
    if current_deadline is not None and expires_at > current_deadline:
        raise FallbackReplanError(
            "replacement decision cannot outlive current request deadline"
        )

    if not isinstance(unavailable_substrates, tuple):
        raise FallbackReplanError("unavailable_substrates must be a tuple")
    if not all(isinstance(item, SubstrateId) for item in unavailable_substrates):
        raise FallbackReplanError(
            "unavailable_substrates must contain only SubstrateId values"
        )
    unavailable_values = tuple(item.value for item in unavailable_substrates)
    if len(set(unavailable_values)) != len(unavailable_values):
        raise FallbackReplanError(
            "unavailable_substrates must not contain duplicates"
        )
    ordered_unavailable = tuple(
        sorted(unavailable_substrates, key=lambda item: item.value)
    )
    if trigger in {
        FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE,
        FallbackTrigger.ROUTE_EXECUTION_FAILURE,
    } and not ordered_unavailable:
        raise FallbackReplanError(
            "route failure fallback requires an unavailable substrate identity"
        )

    previous_validation = validate_routing_decision(
        previous_decision,
        current_binding=current_binding,
        now=now,
    )
    if trigger is FallbackTrigger.STALE_ROUTING_DECISION and previous_validation.valid:
        raise FallbackReplanError(
            "STALE_ROUTING_DECISION requires an invalid previous routing decision"
        )

    base_selection = select_candidate_substrates(
        current_request,
        snapshot,
        candidate_policy,
        current_binding=current_binding,
        observed_at=now,
    )
    selected = _select_fallback_substrates(
        previous_decision,
        snapshot,
        base_selection,
        fallback_policy,
        ordered_unavailable,
    )
    fallback_selection = _with_fallback_selection(base_selection, selected)

    if not selected:
        return FallbackReplanResult(
            request_id=current_request.request_id,
            correlation_id=current_request.correlation_id,
            previous_decision_id=previous_decision.decision_id,
            trigger=trigger,
            replanned_at=now,
            policy=fallback_policy,
            previous_validation=previous_validation,
            unavailable_substrates=ordered_unavailable,
            candidate_selection=fallback_selection,
            status=FallbackReplanStatus.NO_VALID_ROUTE,
            replacement_decision=None,
            replacement_budget_state=None,
        )

    replacement = RoutingDecision(
        decision_id=new_decision_id,
        security_binding=current_binding,
        router_policy_id=candidate_policy.router_policy_id,
        router_policy_version=candidate_policy.router_policy_version,
        selected_substrates=selected,
        reason_codes=_replacement_reason_codes(fallback_selection, trigger),
        reasoning_budget=current_request.reasoning_budget,
        created_at=now,
        expires_at=expires_at,
    )
    replacement_budget_state = RoutingReasoningBudgetUsage(
        decision_id=new_decision_id,
        usage=carried_usage,
    )
    return FallbackReplanResult(
        request_id=current_request.request_id,
        correlation_id=current_request.correlation_id,
        previous_decision_id=previous_decision.decision_id,
        trigger=trigger,
        replanned_at=now,
        policy=fallback_policy,
        previous_validation=previous_validation,
        unavailable_substrates=ordered_unavailable,
        candidate_selection=fallback_selection,
        status=FallbackReplanStatus.ROUTE_SELECTED,
        replacement_decision=replacement,
        replacement_budget_state=replacement_budget_state,
    )
