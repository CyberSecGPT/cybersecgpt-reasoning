"""Public P5 reasoning-control contracts for CyberSecGPT."""

from .budget import (
    ReasoningBudget,
    ReasoningBudgetDelta,
    ReasoningBudgetDimension,
    ReasoningBudgetExceededError,
    ReasoningBudgetUsage,
    consume_reasoning_budget,
    exhausted_reasoning_budget_dimensions,
)
from .errors import (
    ReasoningBudgetError,
    ReasoningError,
    ReasoningLifecycleError,
    RoutingDecisionError,
    RoutingDecisionValidationError,
    RoutingReasoningBudgetError,
)
from .lifecycle import (
    ReasoningLifecycleSnapshot,
    ReasoningState,
    begin_reasoning_lifecycle,
    transition_reasoning_state,
)
from .routing import (
    RoutingDecision,
    RoutingDecisionInvalidReason,
    RoutingDecisionReasonCode,
    RoutingDecisionValidation,
    RoutingReasoningBudgetUsage,
    begin_routing_reasoning_budget,
    consume_routing_reasoning_budget,
    validate_routing_decision,
)

__all__ = [
    "ReasoningError",
    "ReasoningBudgetError",
    "ReasoningBudgetExceededError",
    "ReasoningBudget",
    "ReasoningBudgetDelta",
    "ReasoningBudgetDimension",
    "ReasoningBudgetUsage",
    "consume_reasoning_budget",
    "exhausted_reasoning_budget_dimensions",
    "ReasoningLifecycleError",
    "ReasoningLifecycleSnapshot",
    "ReasoningState",
    "begin_reasoning_lifecycle",
    "transition_reasoning_state",
    "RoutingReasoningBudgetError",
    "RoutingReasoningBudgetUsage",
    "begin_routing_reasoning_budget",
    "consume_routing_reasoning_budget",
    "RoutingDecisionError",
    "RoutingDecisionValidationError",
    "RoutingDecision",
    "RoutingDecisionInvalidReason",
    "RoutingDecisionReasonCode",
    "RoutingDecisionValidation",
    "validate_routing_decision",
]
