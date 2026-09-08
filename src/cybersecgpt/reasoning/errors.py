"""Typed public errors for CyberSecGPT reasoning control."""

__all__ = [
    "BrainRequestError",
    "CandidateSelectionError",
    "FallbackReplanError",
    "ReasoningError",
    "ReasoningBudgetError",
    "ReasoningLifecycleError",
    "RoutingReasoningBudgetError",
    "RoutingDecisionError",
    "RoutingDecisionValidationError",
    "SubstrateDiscoveryError",
    "TerminationPropagationError",
    "VerificationOrchestrationError",
]


class ReasoningError(Exception):
    """Base error for reasoning-control contract failures."""


class BrainRequestError(ReasoningError):
    """Report an invalid normalized Native Brain request or admission input."""


class CandidateSelectionError(ReasoningError):
    """Report invalid deterministic substrate candidate selection state."""


class FallbackReplanError(ReasoningError):
    """Report invalid or unsafe fallback replanning control state."""


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


class SubstrateDiscoveryError(ReasoningError):
    """Report invalid substrate metadata, validation evidence, or snapshot state."""


class TerminationPropagationError(ReasoningError):
    """Report invalid cancellation/deadline propagation control state."""


class VerificationOrchestrationError(ReasoningError):
    """Report invalid or unsafe verifier orchestration control state."""
