"""Deterministic P5 reasoning lifecycle transitions with bounded budget snapshots."""

from dataclasses import dataclass
from enum import StrEnum

from cybersecgpt.foundation import RoutingDecisionId

from .budget import ReasoningBudgetDelta
from .errors import ReasoningLifecycleError
from .routing import (
    RoutingDecision,
    RoutingReasoningBudgetUsage,
    begin_routing_reasoning_budget,
    consume_routing_reasoning_budget,
)

__all__ = [
    "ReasoningLifecycleSnapshot",
    "ReasoningState",
    "begin_reasoning_lifecycle",
    "transition_reasoning_state",
]


class ReasoningState(StrEnum):
    """Machine-evaluable P5 reasoning lifecycle states."""

    ADMITTED = "ADMITTED"
    PLANNING = "PLANNING"
    GATHERING_EVIDENCE = "GATHERING_EVIDENCE"
    GENERATING_CANDIDATES = "GENERATING_CANDIDATES"
    AWAITING_POLICY = "AWAITING_POLICY"
    EXECUTING_AUTHORIZED_TOOL = "EXECUTING_AUTHORIZED_TOOL"
    VERIFYING = "VERIFYING"
    REVISING = "REVISING"
    COMPLETED = "COMPLETED"
    DEFERRED = "DEFERRED"
    DENIED = "DENIED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        """Return whether the state forbids every subsequent transition."""
        return self in _TERMINAL_STATES


_TERMINAL_STATES = frozenset(
    {
        ReasoningState.COMPLETED,
        ReasoningState.DEFERRED,
        ReasoningState.DENIED,
        ReasoningState.FAILED,
        ReasoningState.CANCELLED,
    }
)

_COMMON_STOP_STATES = frozenset(
    {
        ReasoningState.DEFERRED,
        ReasoningState.FAILED,
        ReasoningState.CANCELLED,
    }
)

_ALLOWED_TRANSITIONS: dict[ReasoningState, frozenset[ReasoningState]] = {
    ReasoningState.ADMITTED: frozenset(
        {
            ReasoningState.PLANNING,
            ReasoningState.DEFERRED,
            ReasoningState.DENIED,
            ReasoningState.FAILED,
            ReasoningState.CANCELLED,
        }
    ),
    ReasoningState.PLANNING: frozenset(
        {
            ReasoningState.GATHERING_EVIDENCE,
            ReasoningState.GENERATING_CANDIDATES,
            ReasoningState.AWAITING_POLICY,
            ReasoningState.VERIFYING,
            ReasoningState.COMPLETED,
            *_COMMON_STOP_STATES,
        }
    ),
    ReasoningState.GATHERING_EVIDENCE: frozenset(
        {
            ReasoningState.PLANNING,
            ReasoningState.GENERATING_CANDIDATES,
            ReasoningState.AWAITING_POLICY,
            ReasoningState.VERIFYING,
            ReasoningState.REVISING,
            ReasoningState.COMPLETED,
            *_COMMON_STOP_STATES,
        }
    ),
    ReasoningState.GENERATING_CANDIDATES: frozenset(
        {
            ReasoningState.GATHERING_EVIDENCE,
            ReasoningState.AWAITING_POLICY,
            ReasoningState.VERIFYING,
            ReasoningState.REVISING,
            ReasoningState.COMPLETED,
            *_COMMON_STOP_STATES,
        }
    ),
    ReasoningState.AWAITING_POLICY: frozenset(
        {
            ReasoningState.PLANNING,
            ReasoningState.GATHERING_EVIDENCE,
            ReasoningState.EXECUTING_AUTHORIZED_TOOL,
            ReasoningState.VERIFYING,
            ReasoningState.DENIED,
            *_COMMON_STOP_STATES,
        }
    ),
    ReasoningState.EXECUTING_AUTHORIZED_TOOL: frozenset(
        {
            ReasoningState.GATHERING_EVIDENCE,
            ReasoningState.GENERATING_CANDIDATES,
            ReasoningState.VERIFYING,
            ReasoningState.REVISING,
            ReasoningState.COMPLETED,
            *_COMMON_STOP_STATES,
        }
    ),
    ReasoningState.VERIFYING: frozenset(
        {
            ReasoningState.REVISING,
            ReasoningState.COMPLETED,
            *_COMMON_STOP_STATES,
        }
    ),
    ReasoningState.REVISING: frozenset(
        {
            ReasoningState.PLANNING,
            ReasoningState.GATHERING_EVIDENCE,
            ReasoningState.GENERATING_CANDIDATES,
            ReasoningState.AWAITING_POLICY,
            ReasoningState.VERIFYING,
            *_COMMON_STOP_STATES,
        }
    ),
    ReasoningState.COMPLETED: frozenset(),
    ReasoningState.DEFERRED: frozenset(),
    ReasoningState.DENIED: frozenset(),
    ReasoningState.FAILED: frozenset(),
    ReasoningState.CANCELLED: frozenset(),
}


def _require_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ReasoningLifecycleError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise ReasoningLifecycleError(
            f"{field_name} must be non-empty and have no surrounding whitespace"
        )
    return value


def _require_sequence(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReasoningLifecycleError("sequence must be a non-negative integer")
    return value


def _require_transition(
    previous_state: ReasoningState,
    state: ReasoningState,
) -> None:
    if previous_state.is_terminal:
        raise ReasoningLifecycleError(
            f"terminal reasoning state cannot transition: {previous_state.value}"
        )
    if state not in _ALLOWED_TRANSITIONS[previous_state]:
        raise ReasoningLifecycleError(
            "reasoning state transition is not allowed: "
            f"{previous_state.value} -> {state.value}"
        )


@dataclass(frozen=True, slots=True)
class ReasoningLifecycleSnapshot:
    """Store one immutable lifecycle snapshot suitable for audit and resumption.

    The snapshot is control metadata only. A state name, including
    ``EXECUTING_AUTHORIZED_TOOL``, never creates permission or replaces an
    authoritative policy/authorization decision.
    """

    routing_decision_id: RoutingDecisionId
    correlation_id: str
    sequence: int
    previous_state: ReasoningState | None
    state: ReasoningState
    cause: str
    budget_state: RoutingReasoningBudgetUsage

    def __post_init__(self) -> None:
        if not isinstance(self.routing_decision_id, RoutingDecisionId):
            raise ReasoningLifecycleError(
                "routing_decision_id must be a RoutingDecisionId"
            )
        _require_text(self.correlation_id, field_name="correlation_id")
        sequence = _require_sequence(self.sequence)
        if not isinstance(self.state, ReasoningState):
            raise ReasoningLifecycleError("state must be a ReasoningState")
        _require_text(self.cause, field_name="cause")
        if not isinstance(self.budget_state, RoutingReasoningBudgetUsage):
            raise ReasoningLifecycleError(
                "budget_state must be a RoutingReasoningBudgetUsage"
            )
        if self.budget_state.decision_id != self.routing_decision_id:
            raise ReasoningLifecycleError(
                "budget_state routing decision must match routing_decision_id"
            )

        if sequence == 0:
            if self.previous_state is not None:
                raise ReasoningLifecycleError(
                    "initial lifecycle snapshot must not have previous_state"
                )
            if self.state is not ReasoningState.ADMITTED:
                raise ReasoningLifecycleError(
                    "initial lifecycle snapshot must be ADMITTED"
                )
            return

        if not isinstance(self.previous_state, ReasoningState):
            raise ReasoningLifecycleError(
                "non-initial lifecycle snapshot requires previous_state"
            )
        if self.state is ReasoningState.ADMITTED:
            raise ReasoningLifecycleError("ADMITTED may only be the initial state")
        _require_transition(self.previous_state, self.state)


def begin_reasoning_lifecycle(
    decision: RoutingDecision,
    *,
    correlation_id: str,
    cause: str = "admitted",
) -> ReasoningLifecycleSnapshot:
    """Create the initial ADMITTED lifecycle snapshot for one routing decision."""
    if not isinstance(decision, RoutingDecision):
        raise ReasoningLifecycleError("decision must be a RoutingDecision")
    correlation = _require_text(correlation_id, field_name="correlation_id")
    initial_cause = _require_text(cause, field_name="cause")
    return ReasoningLifecycleSnapshot(
        routing_decision_id=decision.decision_id,
        correlation_id=correlation,
        sequence=0,
        previous_state=None,
        state=ReasoningState.ADMITTED,
        cause=initial_cause,
        budget_state=begin_routing_reasoning_budget(decision),
    )


def transition_reasoning_state(
    decision: RoutingDecision,
    snapshot: ReasoningLifecycleSnapshot,
    *,
    state: ReasoningState,
    cause: str,
    budget_delta: ReasoningBudgetDelta | None = None,
) -> ReasoningLifecycleSnapshot:
    """Advance one legal state with exact sequence and bounded budget accounting."""
    if not isinstance(decision, RoutingDecision):
        raise ReasoningLifecycleError("decision must be a RoutingDecision")
    if not isinstance(snapshot, ReasoningLifecycleSnapshot):
        raise ReasoningLifecycleError("snapshot must be a ReasoningLifecycleSnapshot")
    if not isinstance(state, ReasoningState):
        raise ReasoningLifecycleError("state must be a ReasoningState")
    transition_cause = _require_text(cause, field_name="cause")
    if budget_delta is None:
        delta = ReasoningBudgetDelta()
    elif isinstance(budget_delta, ReasoningBudgetDelta):
        delta = budget_delta
    else:
        raise ReasoningLifecycleError("budget_delta must be a ReasoningBudgetDelta")
    if snapshot.routing_decision_id != decision.decision_id:
        raise ReasoningLifecycleError(
            "lifecycle routing decision does not match supplied decision"
        )

    _require_transition(snapshot.state, state)
    next_budget_state = consume_routing_reasoning_budget(
        decision,
        snapshot.budget_state,
        delta,
    )
    return ReasoningLifecycleSnapshot(
        routing_decision_id=snapshot.routing_decision_id,
        correlation_id=snapshot.correlation_id,
        sequence=snapshot.sequence + 1,
        previous_state=snapshot.state,
        state=state,
        cause=transition_cause,
        budget_state=next_budget_state,
    )
