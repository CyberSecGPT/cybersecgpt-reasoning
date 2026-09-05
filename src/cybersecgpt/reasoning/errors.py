"""Typed public errors for CyberSecGPT reasoning control."""

__all__ = [
    "ReasoningError",
    "ReasoningBudgetError",
    "RoutingDecisionError",
    "RoutingDecisionValidationError",
]


class ReasoningError(Exception):
    """Base error for reasoning-control contract failures."""


class ReasoningBudgetError(ReasoningError):
    """Report an invalid reasoning-budget value or operation."""


class RoutingDecisionError(ReasoningError):
    """Report an invalid routing-decision value."""


class RoutingDecisionValidationError(RoutingDecisionError):
    """Report an invalid request to the routing-decision validator."""
