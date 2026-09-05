"""Tests for deterministic P5 reasoning lifecycle control."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from cybersecgpt.foundation import (
    AuthorizationContextId,
    CapabilitySnapshotId,
    CorrelationId,
    RequestId,
    RoutingDecisionId,
    RoutingSecurityBinding,
    SecurityPolicyRevisionId,
    SubstrateId,
)

from cybersecgpt.reasoning import (
    ReasoningBudget,
    ReasoningBudgetDelta,
    ReasoningBudgetExceededError,
    ReasoningBudgetUsage,
    ReasoningLifecycleError,
    ReasoningLifecycleSnapshot,
    ReasoningState,
    RoutingDecision,
    RoutingDecisionReasonCode,
    RoutingReasoningBudgetError,
    RoutingReasoningBudgetUsage,
    begin_reasoning_lifecycle,
    transition_reasoning_state,
)

CREATED_AT = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
CORRELATION_ID = CorrelationId("correlation-1")


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
    }
    values.update(overrides)
    return ReasoningBudget(**values)  # type: ignore[arg-type]


def make_decision(**overrides: object) -> RoutingDecision:
    binding = RoutingSecurityBinding(
        request_id=RequestId("request-1"),
        authorization_context_id=AuthorizationContextId("authorization-1"),
        security_policy_revision_id=SecurityPolicyRevisionId("policy-7"),
        effective_data_classification="restricted",
        provider_network_policy="native-only",
        offline_required=True,
        capability_snapshot_id=CapabilitySnapshotId("capabilities-4"),
    )
    values: dict[str, object] = {
        "decision_id": RoutingDecisionId("route-1"),
        "security_binding": binding,
        "router_policy_id": "native-core-router",
        "router_policy_version": "p5-v1",
        "selected_substrates": (SubstrateId("native-general"),),
        "reason_codes": (RoutingDecisionReasonCode.CAPABILITY_MATCH,),
        "reasoning_budget": make_budget(),
        "created_at": CREATED_AT,
        "expires_at": CREATED_AT + timedelta(minutes=5),
    }
    values.update(overrides)
    return RoutingDecision(**values)  # type: ignore[arg-type]


def make_initial_snapshot(**overrides: object) -> ReasoningLifecycleSnapshot:
    decision = make_decision()
    state = begin_reasoning_lifecycle(
        decision,
        correlation_id=CORRELATION_ID,
    )
    values: dict[str, object] = {
        "routing_decision_id": state.routing_decision_id,
        "correlation_id": state.correlation_id,
        "sequence": state.sequence,
        "previous_state": state.previous_state,
        "state": state.state,
        "cause": state.cause,
        "budget_state": state.budget_state,
    }
    values.update(overrides)
    return ReasoningLifecycleSnapshot(**values)  # type: ignore[arg-type]


def test_begin_lifecycle_creates_immutable_admitted_snapshot() -> None:
    decision = make_decision()
    snapshot = begin_reasoning_lifecycle(
        decision,
        correlation_id=CORRELATION_ID,
        cause="request admitted",
    )

    assert snapshot.routing_decision_id == decision.decision_id
    assert snapshot.correlation_id == CORRELATION_ID
    assert snapshot.sequence == 0
    assert snapshot.previous_state is None
    assert snapshot.state is ReasoningState.ADMITTED
    assert snapshot.cause == "request admitted"
    assert snapshot.budget_state.decision_id == decision.decision_id
    assert snapshot.budget_state.usage.budget == decision.reasoning_budget
    assert snapshot.budget_state.usage.steps == 0

    with pytest.raises(FrozenInstanceError):
        snapshot.sequence = 1  # type: ignore[misc]


def test_reasoning_state_terminal_property() -> None:
    for state in (
        ReasoningState.COMPLETED,
        ReasoningState.DEFERRED,
        ReasoningState.DENIED,
        ReasoningState.FAILED,
        ReasoningState.CANCELLED,
    ):
        assert state.is_terminal is True

    assert ReasoningState.PLANNING.is_terminal is False


def test_lifecycle_progresses_with_exact_sequence_and_budget_snapshots() -> None:
    decision = make_decision()
    admitted = begin_reasoning_lifecycle(decision, correlation_id=CORRELATION_ID)
    planning = transition_reasoning_state(
        decision,
        admitted,
        state=ReasoningState.PLANNING,
        cause="plan required",
        budget_delta=ReasoningBudgetDelta(steps=1),
    )
    awaiting_policy = transition_reasoning_state(
        decision,
        planning,
        state=ReasoningState.AWAITING_POLICY,
        cause="tool proposal requires policy",
        budget_delta=ReasoningBudgetDelta(steps=1),
    )
    executing = transition_reasoning_state(
        decision,
        awaiting_policy,
        state=ReasoningState.EXECUTING_AUTHORIZED_TOOL,
        cause="external authorization reference validated by caller",
        budget_delta=ReasoningBudgetDelta(steps=1, tool_calls=1),
    )
    verifying = transition_reasoning_state(
        decision,
        executing,
        state=ReasoningState.VERIFYING,
        cause="verify tool evidence",
        budget_delta=ReasoningBudgetDelta(steps=1, verifier_passes=1),
    )
    completed = transition_reasoning_state(
        decision,
        verifying,
        state=ReasoningState.COMPLETED,
        cause="verification policy satisfied",
    )

    assert planning.sequence == 1
    assert planning.previous_state is ReasoningState.ADMITTED
    assert awaiting_policy.sequence == 2
    assert executing.sequence == 3
    assert verifying.sequence == 4
    assert completed.sequence == 5
    assert completed.previous_state is ReasoningState.VERIFYING
    assert completed.correlation_id == CORRELATION_ID
    assert completed.budget_state.usage.steps == 4
    assert completed.budget_state.usage.tool_calls == 1
    assert completed.budget_state.usage.verifier_passes == 1
    assert admitted.budget_state.usage.steps == 0


@pytest.mark.parametrize(
    "terminal_state",
    [
        ReasoningState.COMPLETED,
        ReasoningState.DEFERRED,
        ReasoningState.DENIED,
        ReasoningState.FAILED,
        ReasoningState.CANCELLED,
    ],
)
def test_terminal_state_occurs_once_and_rejects_further_transition(
    terminal_state: ReasoningState,
) -> None:
    decision = make_decision()
    snapshot = begin_reasoning_lifecycle(decision, correlation_id=CORRELATION_ID)
    if terminal_state is ReasoningState.COMPLETED:
        snapshot = transition_reasoning_state(
            decision,
            snapshot,
            state=ReasoningState.PLANNING,
            cause="plan",
        )
    snapshot = transition_reasoning_state(
        decision,
        snapshot,
        state=terminal_state,
        cause="terminal outcome",
    )

    with pytest.raises(ReasoningLifecycleError, match="terminal"):
        transition_reasoning_state(
            decision,
            snapshot,
            state=ReasoningState.PLANNING,
            cause="illegal restart",
        )


def test_tool_execution_state_requires_awaiting_policy() -> None:
    decision = make_decision()
    admitted = begin_reasoning_lifecycle(decision, correlation_id=CORRELATION_ID)
    planning = transition_reasoning_state(
        decision,
        admitted,
        state=ReasoningState.PLANNING,
        cause="plan",
    )

    with pytest.raises(ReasoningLifecycleError, match="not allowed"):
        transition_reasoning_state(
            decision,
            planning,
            state=ReasoningState.EXECUTING_AUTHORIZED_TOOL,
            cause="attempted policy bypass",
        )


def test_admitted_cannot_be_reentered() -> None:
    decision = make_decision()
    planning = transition_reasoning_state(
        decision,
        begin_reasoning_lifecycle(decision, correlation_id=CORRELATION_ID),
        state=ReasoningState.PLANNING,
        cause="plan",
    )

    with pytest.raises(ReasoningLifecycleError, match="not allowed"):
        transition_reasoning_state(
            decision,
            planning,
            state=ReasoningState.ADMITTED,
            cause="illegal reset",
        )


def test_transition_fails_closed_on_budget_exhaustion() -> None:
    decision = make_decision(reasoning_budget=make_budget(max_steps=0))
    admitted = begin_reasoning_lifecycle(decision, correlation_id=CORRELATION_ID)

    with pytest.raises(ReasoningBudgetExceededError):
        transition_reasoning_state(
            decision,
            admitted,
            state=ReasoningState.PLANNING,
            cause="plan",
            budget_delta=ReasoningBudgetDelta(steps=1),
        )

    assert admitted.sequence == 0
    assert admitted.budget_state.usage.steps == 0


def test_transition_rejects_substituted_routing_budget_state() -> None:
    decision = make_decision(reasoning_budget=make_budget(max_steps=2))
    admitted = begin_reasoning_lifecycle(decision, correlation_id=CORRELATION_ID)
    forged_budget_state = RoutingReasoningBudgetUsage(
        decision_id=decision.decision_id,
        usage=ReasoningBudgetUsage(budget=make_budget(max_steps=9)),
    )
    forged_snapshot = ReasoningLifecycleSnapshot(
        routing_decision_id=admitted.routing_decision_id,
        correlation_id=admitted.correlation_id,
        sequence=admitted.sequence,
        previous_state=admitted.previous_state,
        state=admitted.state,
        cause=admitted.cause,
        budget_state=forged_budget_state,
    )

    with pytest.raises(RoutingReasoningBudgetError, match="does not match"):
        transition_reasoning_state(
            decision,
            forged_snapshot,
            state=ReasoningState.PLANNING,
            cause="plan",
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"routing_decision_id": "route-1"}, "routing_decision_id"),
        ({"correlation_id": "correlation-1"}, "correlation_id"),
        ({"correlation_id": 7}, "correlation_id"),
        ({"sequence": True}, "sequence"),
        ({"sequence": -1}, "sequence"),
        ({"state": "ADMITTED"}, "state"),
        ({"cause": 7}, "cause"),
        ({"cause": ""}, "cause"),
        ({"cause": " admitted"}, "cause"),
        ({"budget_state": "budget"}, "budget_state"),
        ({"previous_state": ReasoningState.PLANNING}, "previous_state"),
        ({"state": ReasoningState.PLANNING}, "ADMITTED"),
    ],
)
def test_initial_snapshot_rejects_invalid_fields(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ReasoningLifecycleError, match=message):
        make_initial_snapshot(**overrides)


def test_snapshot_rejects_budget_decision_mismatch() -> None:
    budget_state = RoutingReasoningBudgetUsage(
        decision_id=RoutingDecisionId("route-2"),
        usage=ReasoningBudgetUsage(budget=make_budget()),
    )

    with pytest.raises(ReasoningLifecycleError, match="budget_state routing decision"):
        make_initial_snapshot(budget_state=budget_state)


@pytest.mark.parametrize(
    ("previous_state", "state", "message"),
    [
        (None, ReasoningState.PLANNING, "previous_state"),
        ("PLANNING", ReasoningState.VERIFYING, "previous_state"),
        (ReasoningState.PLANNING, ReasoningState.ADMITTED, "ADMITTED"),
        (
            ReasoningState.PLANNING,
            ReasoningState.EXECUTING_AUTHORIZED_TOOL,
            "not allowed",
        ),
        (ReasoningState.COMPLETED, ReasoningState.PLANNING, "terminal"),
    ],
)
def test_non_initial_snapshot_rejects_invalid_transition_metadata(
    previous_state: object,
    state: ReasoningState,
    message: str,
) -> None:
    with pytest.raises(ReasoningLifecycleError, match=message):
        make_initial_snapshot(
            sequence=1,
            previous_state=previous_state,
            state=state,
        )


def test_direct_non_initial_snapshot_accepts_valid_transition() -> None:
    snapshot = make_initial_snapshot(
        sequence=1,
        previous_state=ReasoningState.ADMITTED,
        state=ReasoningState.PLANNING,
        cause="plan",
    )

    assert snapshot.sequence == 1
    assert snapshot.previous_state is ReasoningState.ADMITTED
    assert snapshot.state is ReasoningState.PLANNING


@pytest.mark.parametrize(
    ("decision", "correlation_id", "cause", "message"),
    [
        ("decision", CORRELATION_ID, "admitted", "decision"),
        (make_decision(), "correlation-1", "admitted", "correlation_id"),
        (make_decision(), 7, "admitted", "correlation_id"),
        (make_decision(), CORRELATION_ID, 7, "cause"),
        (make_decision(), CORRELATION_ID, "", "cause"),
    ],
)
def test_begin_lifecycle_rejects_invalid_inputs(
    decision: object,
    correlation_id: object,
    cause: object,
    message: str,
) -> None:
    with pytest.raises(ReasoningLifecycleError, match=message):
        begin_reasoning_lifecycle(
            cast(RoutingDecision, decision),
            correlation_id=cast(CorrelationId, correlation_id),
            cause=cast(str, cause),
        )


def test_transition_rejects_invalid_inputs_and_decision_mismatch() -> None:
    decision = make_decision()
    snapshot = begin_reasoning_lifecycle(decision, correlation_id=CORRELATION_ID)

    with pytest.raises(ReasoningLifecycleError, match="decision"):
        transition_reasoning_state(
            cast(RoutingDecision, "decision"),
            snapshot,
            state=ReasoningState.PLANNING,
            cause="plan",
        )
    with pytest.raises(ReasoningLifecycleError, match="snapshot"):
        transition_reasoning_state(
            decision,
            cast(ReasoningLifecycleSnapshot, "snapshot"),
            state=ReasoningState.PLANNING,
            cause="plan",
        )
    with pytest.raises(ReasoningLifecycleError, match="state"):
        transition_reasoning_state(
            decision,
            snapshot,
            state=cast(ReasoningState, "PLANNING"),
            cause="plan",
        )
    with pytest.raises(ReasoningLifecycleError, match="cause"):
        transition_reasoning_state(
            decision,
            snapshot,
            state=ReasoningState.PLANNING,
            cause=cast(str, 7),
        )
    with pytest.raises(ReasoningLifecycleError, match="budget_delta"):
        transition_reasoning_state(
            decision,
            snapshot,
            state=ReasoningState.PLANNING,
            cause="plan",
            budget_delta=cast(ReasoningBudgetDelta, "delta"),
        )

    other_decision = make_decision(decision_id=RoutingDecisionId("route-2"))
    with pytest.raises(ReasoningLifecycleError, match="does not match"):
        transition_reasoning_state(
            other_decision,
            snapshot,
            state=ReasoningState.PLANNING,
            cause="plan",
        )
