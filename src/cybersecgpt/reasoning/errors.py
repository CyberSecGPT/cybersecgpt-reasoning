"""Typed public errors for CyberSecGPT reasoning control."""

__all__ = [
    "BrainRequestError",
    "ReasoningError",
    "ReasoningBudgetError",
    "ReasoningLifecycleError",
    "RoutingReasoningBudgetError",
    "RoutingDecisionError",
    "RoutingDecisionValidationError",
]


class ReasoningError(Exception):
    """Base error for reasoning-control contract failures."""


class BrainRequestError(ReasoningError):
    """Report an invalid normalized Native Brain request or admission input."""


class ReasoningBudgetError(ReasoningError):
    """Report an invalid reasoning-budget value or operation."""


class ReasoningLifecycleError(ReasoningError):
    """Report an invalid reasoning lifecycle value or transition."""


class RoutingReasoningBudgetError(ReasoningBudgetError):
    """Report an invalid routing-to-reasoning-budget binding or operation."""


class RoutingDecisionError(ReasoningError):
    """Report an invalid routing-decision value."""


class RoutingDecisionValidationError(RoutingDecisionError):
    """Report an invalid request to the routing-decision validator."""
