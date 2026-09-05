"""Tests for the conservative public Reasoning API."""

import cybersecgpt.reasoning as reasoning


def test_public_api_is_explicit() -> None:
    assert reasoning.__all__ == [
        "ReasoningError",
        "RoutingDecisionError",
        "RoutingDecisionValidationError",
        "RoutingDecision",
        "RoutingDecisionInvalidReason",
        "RoutingDecisionReasonCode",
        "RoutingDecisionValidation",
        "validate_routing_decision",
    ]
    assert all(hasattr(reasoning, name) for name in reasoning.__all__)
