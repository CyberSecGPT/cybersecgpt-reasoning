"""Typed public errors for CyberSecGPT reasoning control."""

__all__ = [
    "ReasoningError",
    "RoutingDecisionError",
    "RoutingDecisionValidationError",
]


class ReasoningError(Exception):
    """Base error for reasoning-control contract failures."""


class RoutingDecisionError(ReasoningError):
    """Report an invalid routing-decision value."""


class RoutingDecisionValidationError(RoutingDecisionError):
    """Report an invalid request to the routing-decision validator."""
