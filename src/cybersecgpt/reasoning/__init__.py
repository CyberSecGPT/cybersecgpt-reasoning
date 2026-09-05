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
    RoutingDecisionError,
    RoutingDecisionValidationError,
)
from .routing import (
    RoutingDecision,
    RoutingDecisionInvalidReason,
    RoutingDecisionReasonCode,
    RoutingDecisionValidation,
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
    "RoutingDecisionError",
    "RoutingDecisionValidationError",
    "RoutingDecision",
    "RoutingDecisionInvalidReason",
    "RoutingDecisionReasonCode",
    "RoutingDecisionValidation",
    "validate_routing_decision",
]
