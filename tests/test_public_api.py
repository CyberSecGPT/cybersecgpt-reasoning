"""Tests for the conservative public Reasoning API."""

import cybersecgpt.reasoning as reasoning


def test_public_api_is_explicit() -> None:
    assert reasoning.__all__ == [
        "ReasoningError",
        "BrainRequestError",
        "BrainRequest",
        "admit_brain_request",
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
    assert all(hasattr(reasoning, name) for name in reasoning.__all__)
