"""Tests for P5 bounded reasoning-budget control."""

from dataclasses import FrozenInstanceError
from typing import cast

import pytest

from cybersecgpt.reasoning import (
    ReasoningBudget,
    ReasoningBudgetDelta,
    ReasoningBudgetDimension,
    ReasoningBudgetError,
    ReasoningBudgetExceededError,
    ReasoningBudgetUsage,
    consume_reasoning_budget,
    exhausted_reasoning_budget_dimensions,
)


def make_budget(**overrides: object) -> ReasoningBudget:
    values: dict[str, object] = {
        "policy_name": "NORMAL",
        "max_candidates": 4,
        "max_branch_depth": 3,
        "max_steps": 8,
        "max_model_tokens": 1024,
        "max_tool_calls": 2,
        "max_retrieval_calls": 3,
        "max_verifier_passes": 2,
        "stop_conditions": ("supported", "policy_blocked"),
    }
    values.update(overrides)
    return ReasoningBudget(**values)  # type: ignore[arg-type]


def test_budget_is_immutable_and_preserves_explicit_profile() -> None:
    budget = make_budget()

    assert budget.policy_name == "NORMAL"
    assert budget.max_steps == 8
    assert budget.stop_conditions == ("supported", "policy_blocked")

    with pytest.raises(FrozenInstanceError):
        budget.max_steps = 9  # type: ignore[misc]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"policy_name": 7}, "policy_name"),
        ({"policy_name": ""}, "policy_name"),
        ({"policy_name": " NORMAL"}, "policy_name"),
        ({"max_candidates": True}, "max_candidates"),
        ({"max_candidates": -1}, "max_candidates"),
        ({"stop_conditions": ["supported"]}, "stop_conditions"),
        ({"stop_conditions": ("",)}, "stop_conditions item"),
        ({"stop_conditions": (" supported",)}, "stop_conditions item"),
        ({"stop_conditions": ("supported", "supported")}, "duplicates"),
    ],
)
def test_budget_rejects_invalid_contract_values(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ReasoningBudgetError, match=message):
        make_budget(**overrides)


def test_zero_ceiling_is_explicitly_supported() -> None:
    budget = make_budget(max_tool_calls=0, max_retrieval_calls=0)
    usage = ReasoningBudgetUsage(budget=budget)

    assert exhausted_reasoning_budget_dimensions(usage) == (
        ReasoningBudgetDimension.TOOL_CALLS,
        ReasoningBudgetDimension.RETRIEVAL_CALLS,
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"budget": "NORMAL"}, "budget"),
        ({"candidates": -1}, "candidates"),
        ({"steps": 9}, "STEPS"),
    ],
)
def test_usage_rejects_invalid_or_over_budget_state(
    overrides: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {"budget": make_budget()}
    values.update(overrides)

    with pytest.raises(ReasoningBudgetError, match=message):
        ReasoningBudgetUsage(**values)  # type: ignore[arg-type]


def test_delta_rejects_negative_or_boolean_counters() -> None:
    with pytest.raises(ReasoningBudgetError, match="steps"):
        ReasoningBudgetDelta(steps=-1)
    with pytest.raises(ReasoningBudgetError, match="tool_calls"):
        ReasoningBudgetDelta(tool_calls=True)  # type: ignore[arg-type]


def test_consumption_is_monotonic_and_branch_depth_is_high_water_mark() -> None:
    budget = make_budget()
    initial = ReasoningBudgetUsage(budget=budget)

    first = consume_reasoning_budget(
        initial,
        ReasoningBudgetDelta(
            candidates=2,
            branch_depth=2,
            steps=3,
            model_tokens=100,
            tool_calls=1,
            retrieval_calls=1,
            verifier_passes=1,
        ),
    )
    second = consume_reasoning_budget(
        first,
        ReasoningBudgetDelta(
            candidates=1,
            branch_depth=1,
            steps=2,
            model_tokens=50,
            retrieval_calls=1,
        ),
    )

    assert initial.candidates == 0
    assert first.candidates == 2
    assert second.candidates == 3
    assert second.branch_depth == 2
    assert second.steps == 5
    assert second.model_tokens == 150
    assert second.tool_calls == 1
    assert second.retrieval_calls == 2
    assert second.verifier_passes == 1


def test_exact_ceiling_is_allowed_and_reported_as_exhausted() -> None:
    budget = ReasoningBudget(
        policy_name="DEEP",
        max_candidates=2,
        max_branch_depth=2,
        max_steps=2,
        max_model_tokens=2,
        max_tool_calls=2,
        max_retrieval_calls=2,
        max_verifier_passes=2,
    )
    usage = consume_reasoning_budget(
        ReasoningBudgetUsage(budget=budget),
        ReasoningBudgetDelta(
            candidates=2,
            branch_depth=2,
            steps=2,
            model_tokens=2,
            tool_calls=2,
            retrieval_calls=2,
            verifier_passes=2,
        ),
    )

    assert exhausted_reasoning_budget_dimensions(usage) == (
        ReasoningBudgetDimension.CANDIDATES,
        ReasoningBudgetDimension.BRANCH_DEPTH,
        ReasoningBudgetDimension.STEPS,
        ReasoningBudgetDimension.MODEL_TOKENS,
        ReasoningBudgetDimension.TOOL_CALLS,
        ReasoningBudgetDimension.RETRIEVAL_CALLS,
        ReasoningBudgetDimension.VERIFIER_PASSES,
    )


def test_consumption_fails_closed_on_multiple_exceeded_dimensions() -> None:
    budget = make_budget(max_candidates=1, max_steps=1)
    usage = ReasoningBudgetUsage(budget=budget, candidates=1, steps=1)

    with pytest.raises(ReasoningBudgetExceededError) as captured:
        consume_reasoning_budget(
            usage,
            ReasoningBudgetDelta(candidates=1, steps=1),
        )

    assert captured.value.dimensions == (
        ReasoningBudgetDimension.CANDIDATES,
        ReasoningBudgetDimension.STEPS,
    )
    assert str(captured.value) == "reasoning budget exceeded: CANDIDATES, STEPS"
    assert usage.candidates == 1
    assert usage.steps == 1


def test_branch_depth_above_ceiling_fails_closed() -> None:
    usage = ReasoningBudgetUsage(budget=make_budget(max_branch_depth=1))

    with pytest.raises(ReasoningBudgetExceededError) as captured:
        consume_reasoning_budget(usage, ReasoningBudgetDelta(branch_depth=2))

    assert captured.value.dimensions == (ReasoningBudgetDimension.BRANCH_DEPTH,)


def test_budget_functions_reject_wrong_input_types() -> None:
    budget = make_budget()
    usage = ReasoningBudgetUsage(budget=budget)

    with pytest.raises(ReasoningBudgetError, match="usage"):
        consume_reasoning_budget(
            cast(ReasoningBudgetUsage, "usage"),
            ReasoningBudgetDelta(),
        )
    with pytest.raises(ReasoningBudgetError, match="delta"):
        consume_reasoning_budget(
            usage,
            cast(ReasoningBudgetDelta, "delta"),
        )
    with pytest.raises(ReasoningBudgetError, match="usage"):
        exhausted_reasoning_budget_dimensions(
            cast(ReasoningBudgetUsage, "usage")
        )
