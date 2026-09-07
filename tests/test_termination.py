"""Tests for deterministic P5 cancellation and deadline propagation."""

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
    BrainRequest,
    ReasoningBudget,
    ReasoningLifecycleSnapshot,
    ReasoningState,
    RoutingDecision,
    RoutingDecisionReasonCode,
    TerminationAcknowledgement,
    TerminationAcknowledgementState,
    TerminationPropagation,
    TerminationPropagationError,
    TerminationPropagationEvaluation,
    TerminationPropagationStatus,
    TerminationReason,
    TerminationRequirement,
    TerminationTarget,
    TerminationTargetKind,
    acknowledge_termination_target,
    begin_reasoning_lifecycle,
    begin_termination_propagation,
    evaluate_termination_propagation,
    evaluate_termination_requirement,
    transition_reasoning_state,
)

NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
ADMITTED_AT = NOW - timedelta(minutes=2)
CORRELATION_ID = CorrelationId("correlation-termination")
REQUEST_ID = RequestId("request-termination")
DECISION_ID = RoutingDecisionId("route-termination")


def make_binding(**overrides: object) -> RoutingSecurityBinding:
    values: dict[str, object] = {
        "request_id": REQUEST_ID,
        "authorization_context_id": AuthorizationContextId("auth-termination"),
        "security_policy_revision_id": SecurityPolicyRevisionId("policy-termination"),
        "effective_data_classification": "restricted",
        "provider_network_policy": "native-only",
        "offline_required": True,
        "capability_snapshot_id": CapabilitySnapshotId("capabilities-termination"),
    }
    values.update(overrides)
    return RoutingSecurityBinding(**values)  # type: ignore[arg-type]


def make_budget() -> ReasoningBudget:
    return ReasoningBudget(
        policy_name="NORMAL",
        max_candidates=4,
        max_branch_depth=3,
        max_steps=8,
        max_model_tokens=1024,
        max_tool_calls=2,
        max_retrieval_calls=2,
        max_verifier_passes=2,
    )


def make_decision(**overrides: object) -> RoutingDecision:
    values: dict[str, object] = {
        "decision_id": DECISION_ID,
        "security_binding": make_binding(),
        "router_policy_id": "native-core-router",
        "router_policy_version": "p5-v1",
        "selected_substrates": (
            SubstrateId("model:native-general"),
            SubstrateId("verifier:deterministic"),
        ),
        "reason_codes": (RoutingDecisionReasonCode.CAPABILITY_MATCH,),
        "reasoning_budget": make_budget(),
        "created_at": ADMITTED_AT + timedelta(seconds=10),
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(overrides)
    return RoutingDecision(**values)  # type: ignore[arg-type]


def make_request(
    decision: RoutingDecision | None = None,
    **overrides: object,
) -> BrainRequest:
    actual_decision = decision or make_decision()
    values: dict[str, object] = {
        "request_id": actual_decision.security_binding.request_id,
        "correlation_id": CORRELATION_ID,
        "security_binding": actual_decision.security_binding,
        "task_type": "reasoning",
        "domain": "general",
        "task_complexity": "normal",
        "safety_impact": "low",
        "source_data_classification": None,
        "identity_context_ref": None,
        "max_latency_ms": 1000,
        "max_compute_units": 4,
        "max_memory_bytes": 4096,
        "reasoning_budget": actual_decision.reasoning_budget,
        "required_accuracy": None,
        "required_determinism": False,
        "required_explainability": False,
        "verification_requirements": (),
        "admitted_at": ADMITTED_AT,
        "deadline": NOW + timedelta(minutes=1),
        "input_json": "{}",
    }
    values.update(overrides)
    return BrainRequest(**values)  # type: ignore[arg-type]


def make_lifecycle(
    decision: RoutingDecision | None = None,
    *,
    correlation_id: CorrelationId = CORRELATION_ID,
) -> ReasoningLifecycleSnapshot:
    actual_decision = decision or make_decision()
    return begin_reasoning_lifecycle(
        actual_decision,
        correlation_id=correlation_id,
    )


def make_target(
    target_ref: str = "model.active-1",
    **overrides: object,
) -> TerminationTarget:
    values: dict[str, object] = {
        "target_ref": target_ref,
        "substrate_id": SubstrateId("model:native-general"),
        "target_kind": TerminationTargetKind.MODEL,
        "side_effect_capable": False,
        "cleanup_required": False,
    }
    values.update(overrides)
    return TerminationTarget(**values)  # type: ignore[arg-type]


def make_acknowledgement(
    target_ref: str = "model.active-1",
    **overrides: object,
) -> TerminationAcknowledgement:
    values: dict[str, object] = {
        "target_ref": target_ref,
        "state": TerminationAcknowledgementState.STOPPED,
        "acknowledged_at": NOW + timedelta(seconds=2),
        "evidence_preserved_or_not_applicable": True,
        "detail_code": "safe_stop_complete",
        "cleanup_authorization_ref": None,
    }
    values.update(overrides)
    return TerminationAcknowledgement(**values)  # type: ignore[arg-type]


def make_requirement(
    decision: RoutingDecision | None = None,
    request: BrainRequest | None = None,
    lifecycle: ReasoningLifecycleSnapshot | None = None,
    *,
    observed_at: datetime = NOW,
    cancellation_requested_at: datetime | None = NOW - timedelta(seconds=1),
) -> TerminationRequirement:
    actual_decision = decision or make_decision()
    actual_request = request or make_request(actual_decision)
    actual_lifecycle = lifecycle or make_lifecycle(actual_decision)
    return evaluate_termination_requirement(
        actual_request,
        actual_decision,
        actual_lifecycle,
        observed_at=observed_at,
        cancellation_requested_at=cancellation_requested_at,
    )


def make_propagation(
    *,
    targets: tuple[TerminationTarget, ...] | None = None,
    deadline: datetime = NOW + timedelta(seconds=10),
) -> TerminationPropagation:
    decision = make_decision()
    request = make_request(decision)
    lifecycle = make_lifecycle(decision)
    requirement = make_requirement(
        decision,
        request,
        lifecycle,
    )
    return begin_termination_propagation(
        request,
        decision,
        lifecycle,
        requirement,
        targets=targets if targets is not None else (make_target(),),
        propagation_deadline=deadline,
    )


def test_requirement_is_not_permission_and_detects_cancellation() -> None:
    decision = make_decision()
    request = make_request(decision)
    lifecycle = make_lifecycle(decision)

    active = evaluate_termination_requirement(
        request,
        decision,
        lifecycle,
        observed_at=NOW,
        cancellation_requested_at=NOW + timedelta(seconds=1),
    )
    assert active.required is False
    assert active.reason is None
    assert active.triggered_at is None

    cancelled = evaluate_termination_requirement(
        request,
        decision,
        lifecycle,
        observed_at=NOW,
        cancellation_requested_at=NOW - timedelta(seconds=1),
    )
    assert cancelled.required is True
    assert cancelled.reason is TerminationReason.CANCELLATION
    assert cancelled.triggered_at == NOW - timedelta(seconds=1)

    with pytest.raises(FrozenInstanceError):
        cancelled.required = False  # type: ignore[misc]


def test_requirement_detects_deadline_and_earliest_stop_condition() -> None:
    decision = make_decision()
    deadline = NOW - timedelta(seconds=2)
    request = make_request(decision, deadline=deadline)
    lifecycle = make_lifecycle(decision)

    deadline_only = evaluate_termination_requirement(
        request,
        decision,
        lifecycle,
        observed_at=NOW,
    )
    assert deadline_only.reason is TerminationReason.DEADLINE
    assert deadline_only.triggered_at == deadline

    deadline_first = evaluate_termination_requirement(
        request,
        decision,
        lifecycle,
        observed_at=NOW,
        cancellation_requested_at=NOW - timedelta(seconds=1),
    )
    assert deadline_first.reason is TerminationReason.DEADLINE

    cancellation_first_request = make_request(
        decision,
        deadline=NOW - timedelta(seconds=1),
    )
    cancellation_first = evaluate_termination_requirement(
        cancellation_first_request,
        decision,
        lifecycle,
        observed_at=NOW,
        cancellation_requested_at=NOW - timedelta(seconds=2),
    )
    assert cancellation_first.reason is TerminationReason.CANCELLATION


def test_terminal_lifecycle_is_stop_required_without_new_propagation() -> None:
    decision = make_decision()
    request = make_request(decision)
    lifecycle = make_lifecycle(decision)
    cancelled = transition_reasoning_state(
        decision,
        lifecycle,
        state=ReasoningState.CANCELLED,
        cause="external cancellation",
    )

    requirement = evaluate_termination_requirement(
        request,
        decision,
        cancelled,
        observed_at=NOW,
    )
    assert requirement.required is True
    assert requirement.reason is TerminationReason.TERMINAL_STATE
    assert requirement.triggered_at == NOW

    with pytest.raises(TerminationPropagationError, match="active cancellation"):
        begin_termination_propagation(
            request,
            decision,
            cancelled,
            requirement,
            targets=(),
            propagation_deadline=NOW + timedelta(seconds=5),
        )


def test_begin_propagation_sorts_targets_and_blocks_new_side_effects() -> None:
    decision = make_decision()
    request = make_request(decision)
    lifecycle = make_lifecycle(decision)
    requirement = make_requirement(decision, request, lifecycle)
    tool_target = make_target(
        "tool.active-2",
        substrate_id=SubstrateId("tool:authorized"),
        target_kind=TerminationTargetKind.TOOL,
        side_effect_capable=True,
        cleanup_required=True,
    )
    model_target = make_target("model.active-1")

    propagation = begin_termination_propagation(
        request,
        decision,
        lifecycle,
        requirement,
        targets=(tool_target, model_target),
        propagation_deadline=NOW + timedelta(seconds=10),
    )

    assert propagation.reason is TerminationReason.CANCELLATION
    assert propagation.triggered_at == NOW - timedelta(seconds=1)
    assert propagation.propagation_started_at == NOW
    assert propagation.blocks_new_side_effects is True
    assert propagation.sequence == 0
    assert propagation.acknowledgements == ()
    assert tuple(target.target_ref for target in propagation.targets) == (
        "model.active-1",
        "tool.active-2",
    )


def test_acknowledgements_are_monotonic_sorted_and_complete() -> None:
    propagation = make_propagation(
        targets=(
            make_target("tool.active-2", target_kind=TerminationTargetKind.TOOL),
            make_target("model.active-1"),
        )
    )
    tool_ack = make_acknowledgement(
        "tool.active-2",
        acknowledged_at=NOW + timedelta(seconds=3),
    )
    model_ack = make_acknowledgement(
        "model.active-1",
        acknowledged_at=NOW + timedelta(seconds=2),
    )

    one = acknowledge_termination_target(propagation, tool_ack)
    two = acknowledge_termination_target(one, model_ack)

    assert one.sequence == 1
    assert two.sequence == 2
    assert tuple(item.target_ref for item in two.acknowledgements) == (
        "model.active-1",
        "tool.active-2",
    )
    evaluation = evaluate_termination_propagation(
        two,
        observed_at=NOW + timedelta(seconds=4),
    )
    assert evaluation.status is TerminationPropagationStatus.COMPLETE
    assert evaluation.deadline_exceeded is False
    assert evaluation.pending_target_refs == ()
    assert evaluation.cleanup_pending_target_refs == ()
    assert evaluation.failed_target_refs == ()
    assert evaluation.late_ack_target_refs == ()


def test_evaluation_reports_pending_cleanup_failure_and_deadline() -> None:
    targets = (
        make_target("model.active-1"),
        make_target(
            "tool.active-2",
            target_kind=TerminationTargetKind.TOOL,
            cleanup_required=True,
        ),
        make_target(
            "verifier.active-3",
            substrate_id=SubstrateId("verifier:deterministic"),
            target_kind=TerminationTargetKind.VERIFIER,
        ),
    )
    propagation = make_propagation(
        targets=targets,
        deadline=NOW + timedelta(seconds=5),
    )
    cleanup = make_acknowledgement(
        "tool.active-2",
        state=TerminationAcknowledgementState.CLEANUP_PENDING,
        cleanup_authorization_ref="cleanup-grant-1",
        acknowledged_at=NOW + timedelta(seconds=1),
    )
    failed = make_acknowledgement(
        "verifier.active-3",
        state=TerminationAcknowledgementState.FAILED_TO_STOP,
        evidence_preserved_or_not_applicable=False,
        detail_code="stop_failed",
        acknowledged_at=NOW + timedelta(seconds=2),
    )
    state = acknowledge_termination_target(propagation, cleanup)
    state = acknowledge_termination_target(state, failed)

    before_deadline = evaluate_termination_propagation(
        state,
        observed_at=NOW + timedelta(seconds=3),
    )
    assert before_deadline.status is TerminationPropagationStatus.FAILED
    assert before_deadline.deadline_exceeded is False
    assert before_deadline.pending_target_refs == ("model.active-1",)
    assert before_deadline.cleanup_pending_target_refs == ("tool.active-2",)
    assert before_deadline.failed_target_refs == ("verifier.active-3",)

    after_deadline = evaluate_termination_propagation(
        state,
        observed_at=NOW + timedelta(seconds=6),
    )
    assert after_deadline.deadline_exceeded is True


def test_late_acknowledgement_remains_visible_after_completion() -> None:
    propagation = make_propagation(deadline=NOW + timedelta(seconds=2))
    late = make_acknowledgement(
        acknowledged_at=NOW + timedelta(seconds=3),
    )
    state = acknowledge_termination_target(propagation, late)
    evaluation = evaluate_termination_propagation(
        state,
        observed_at=NOW + timedelta(seconds=4),
    )

    assert evaluation.status is TerminationPropagationStatus.COMPLETE
    assert evaluation.deadline_exceeded is True
    assert evaluation.late_ack_target_refs == ("model.active-1",)


def test_empty_active_target_set_is_immediately_complete() -> None:
    propagation = make_propagation(targets=())
    evaluation = evaluate_termination_propagation(
        propagation,
        observed_at=NOW,
    )
    assert evaluation.status is TerminationPropagationStatus.COMPLETE
    assert evaluation.deadline_exceeded is False


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"request_id": "request"}, "request_id"),
        ({"routing_decision_id": "route"}, "routing_decision_id"),
        ({"correlation_id": "correlation"}, "correlation_id"),
        ({"evaluated_at": "now"}, "evaluated_at"),
        ({"required": 1}, "required"),
        ({"reason": "DEADLINE"}, "reason"),
        ({"triggered_at": "now"}, "triggered_at"),
        (
            {"triggered_at": NOW + timedelta(seconds=1)},
            "must not be later",
        ),
        ({"required": True, "reason": None, "triggered_at": NOW}, "reason exists"),
        (
            {"required": True, "reason": TerminationReason.DEADLINE, "triggered_at": None},
            "triggered_at exists",
        ),
    ],
)
def test_requirement_rejects_invalid_state(
    kwargs: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "request_id": REQUEST_ID,
        "routing_decision_id": DECISION_ID,
        "correlation_id": CORRELATION_ID,
        "evaluated_at": NOW,
        "required": False,
        "reason": None,
        "triggered_at": None,
    }
    values.update(kwargs)
    with pytest.raises(TerminationPropagationError, match=message):
        TerminationRequirement(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"target_ref": "bad ref"}, "target_ref"),
        ({"substrate_id": "model"}, "substrate_id"),
        ({"target_kind": "MODEL"}, "target_kind"),
        ({"side_effect_capable": 1}, "side_effect_capable"),
        ({"cleanup_required": 1}, "cleanup_required"),
    ],
)
def test_target_rejects_invalid_state(
    kwargs: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "target_ref": "model.active-1",
        "substrate_id": SubstrateId("model:native-general"),
        "target_kind": TerminationTargetKind.MODEL,
        "side_effect_capable": False,
        "cleanup_required": False,
    }
    values.update(kwargs)
    with pytest.raises(TerminationPropagationError, match=message):
        TerminationTarget(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"target_ref": "bad ref"}, "target_ref"),
        ({"state": "STOPPED"}, "state"),
        ({"acknowledged_at": "now"}, "acknowledged_at"),
        ({"evidence_preserved_or_not_applicable": 1}, "evidence_preserved"),
        ({"detail_code": "bad code"}, "detail_code"),
        ({"cleanup_authorization_ref": "bad ref"}, "cleanup_authorization_ref"),
        ({"evidence_preserved_or_not_applicable": False}, "preserve evidence"),
        (
            {
                "state": TerminationAcknowledgementState.CLEANUP_PENDING,
                "cleanup_authorization_ref": None,
            },
            "cleanup_authorization_ref",
        ),
    ],
)
def test_acknowledgement_rejects_invalid_state(
    kwargs: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "target_ref": "model.active-1",
        "state": TerminationAcknowledgementState.STOPPED,
        "acknowledged_at": NOW,
        "evidence_preserved_or_not_applicable": True,
        "detail_code": "safe_stop_complete",
        "cleanup_authorization_ref": None,
    }
    values.update(kwargs)
    with pytest.raises(TerminationPropagationError, match=message):
        TerminationAcknowledgement(**values)  # type: ignore[arg-type]


def test_propagation_rejects_invalid_core_state() -> None:
    target = make_target()
    ack = make_acknowledgement(acknowledged_at=NOW + timedelta(seconds=1))
    values: dict[str, object] = {
        "request_id": REQUEST_ID,
        "routing_decision_id": DECISION_ID,
        "correlation_id": CORRELATION_ID,
        "reason": TerminationReason.CANCELLATION,
        "triggered_at": NOW - timedelta(seconds=1),
        "propagation_started_at": NOW,
        "propagation_deadline": NOW + timedelta(seconds=5),
        "targets": (target,),
        "acknowledgements": (ack,),
        "sequence": 1,
    }
    cases: tuple[tuple[str, object, str], ...] = (
        ("request_id", "request", "request_id"),
        ("routing_decision_id", "route", "routing_decision_id"),
        ("correlation_id", "correlation", "correlation_id"),
        ("reason", TerminationReason.TERMINAL_STATE, "propagation reason"),
        ("triggered_at", "now", "triggered_at"),
        ("propagation_started_at", "now", "propagation_started_at"),
        ("propagation_deadline", "later", "propagation_deadline"),
        ("sequence", -1, "sequence"),
    )
    for field_name, value, message in cases:
        invalid = dict(values)
        invalid[field_name] = value
        with pytest.raises(TerminationPropagationError, match=message):
            TerminationPropagation(**invalid)  # type: ignore[arg-type]

    invalid = dict(values)
    invalid["triggered_at"] = NOW + timedelta(seconds=1)
    with pytest.raises(TerminationPropagationError, match="triggered_at"):
        TerminationPropagation(**invalid)  # type: ignore[arg-type]

    invalid = dict(values)
    invalid["propagation_deadline"] = NOW
    with pytest.raises(TerminationPropagationError, match="propagation_deadline"):
        TerminationPropagation(**invalid)  # type: ignore[arg-type]


def test_propagation_rejects_invalid_target_and_acknowledgement_collections() -> None:
    target_a = make_target("model.a")
    target_b = make_target("model.b")
    ack_a = make_acknowledgement("model.a", acknowledged_at=NOW + timedelta(seconds=1))
    base: dict[str, object] = {
        "request_id": REQUEST_ID,
        "routing_decision_id": DECISION_ID,
        "correlation_id": CORRELATION_ID,
        "reason": TerminationReason.CANCELLATION,
        "triggered_at": NOW - timedelta(seconds=1),
        "propagation_started_at": NOW,
        "propagation_deadline": NOW + timedelta(seconds=5),
        "targets": (target_a,),
        "acknowledgements": (),
        "sequence": 0,
    }

    invalid_cases: tuple[tuple[str, object, str], ...] = (
        ("targets", [target_a], "targets must be a tuple"),
        ("targets", ("target",), "TerminationTarget"),
        ("targets", (target_a, target_a), "duplicate refs"),
        ("targets", (target_b, target_a), "sorted by target_ref"),
        ("acknowledgements", [ack_a], "acknowledgements must be a tuple"),
        ("acknowledgements", ("ack",), "TerminationAcknowledgement"),
    )
    for field_name, value, message in invalid_cases:
        invalid = dict(base)
        invalid[field_name] = value
        with pytest.raises(TerminationPropagationError, match=message):
            TerminationPropagation(**invalid)  # type: ignore[arg-type]

    invalid = dict(base)
    invalid.update(
        acknowledgements=(ack_a, ack_a),
        sequence=2,
    )
    with pytest.raises(TerminationPropagationError, match="duplicate target refs"):
        TerminationPropagation(**invalid)  # type: ignore[arg-type]

    ack_b = make_acknowledgement("model.b", acknowledged_at=NOW + timedelta(seconds=1))
    invalid = dict(base)
    invalid.update(
        targets=(target_a, target_b),
        acknowledgements=(ack_b, ack_a),
        sequence=2,
    )
    with pytest.raises(TerminationPropagationError, match="sorted by target_ref"):
        TerminationPropagation(**invalid)  # type: ignore[arg-type]

    invalid = dict(base)
    invalid.update(
        acknowledgements=(ack_b,),
        sequence=1,
    )
    with pytest.raises(TerminationPropagationError, match="declared termination targets"):
        TerminationPropagation(**invalid)  # type: ignore[arg-type]

    early_ack = make_acknowledgement(
        "model.a",
        acknowledged_at=NOW - timedelta(seconds=1),
    )
    invalid = dict(base)
    invalid.update(
        acknowledgements=(early_ack,),
        sequence=1,
    )
    with pytest.raises(TerminationPropagationError, match="cannot predate"):
        TerminationPropagation(**invalid)  # type: ignore[arg-type]

    invalid = dict(base)
    invalid["sequence"] = 1
    with pytest.raises(TerminationPropagationError, match="number of immutable"):
        TerminationPropagation(**invalid)  # type: ignore[arg-type]


def test_requirement_function_rejects_invalid_inputs_and_bindings() -> None:
    decision = make_decision()
    request = make_request(decision)
    lifecycle = make_lifecycle(decision)

    with pytest.raises(TerminationPropagationError, match="request must"):
        evaluate_termination_requirement(  # type: ignore[arg-type]
            "request",
            decision,
            lifecycle,
            observed_at=NOW,
        )
    with pytest.raises(TerminationPropagationError, match="decision must"):
        evaluate_termination_requirement(  # type: ignore[arg-type]
            request,
            "decision",
            lifecycle,
            observed_at=NOW,
        )
    with pytest.raises(TerminationPropagationError, match="lifecycle must"):
        evaluate_termination_requirement(  # type: ignore[arg-type]
            request,
            decision,
            "lifecycle",
            observed_at=NOW,
        )
    with pytest.raises(TerminationPropagationError, match="observed_at"):
        evaluate_termination_requirement(
            request,
            decision,
            lifecycle,
            observed_at=cast(datetime, "now"),
        )
    with pytest.raises(TerminationPropagationError, match="predate request admission"):
        evaluate_termination_requirement(
            request,
            decision,
            lifecycle,
            observed_at=ADMITTED_AT - timedelta(seconds=1),
        )
    with pytest.raises(TerminationPropagationError, match="cancellation_requested_at"):
        evaluate_termination_requirement(
            request,
            decision,
            lifecycle,
            observed_at=NOW,
            cancellation_requested_at=cast(datetime, "cancel"),
        )
    with pytest.raises(TerminationPropagationError, match="cannot predate"):
        evaluate_termination_requirement(
            request,
            decision,
            lifecycle,
            observed_at=NOW,
            cancellation_requested_at=ADMITTED_AT - timedelta(seconds=1),
        )

    other_binding = make_binding(
        authorization_context_id=AuthorizationContextId("other-auth")
    )
    other_decision = make_decision(security_binding=other_binding)
    with pytest.raises(TerminationPropagationError, match="security binding"):
        evaluate_termination_requirement(
            request,
            other_decision,
            make_lifecycle(other_decision),
            observed_at=NOW,
        )

    other_decision_id = make_decision(
        decision_id=RoutingDecisionId("route-other"),
    )
    with pytest.raises(TerminationPropagationError, match="lifecycle routing decision"):
        evaluate_termination_requirement(
            request,
            decision,
            make_lifecycle(other_decision_id),
            observed_at=NOW,
        )

    with pytest.raises(TerminationPropagationError, match="correlation identity"):
        evaluate_termination_requirement(
            request,
            decision,
            make_lifecycle(
                decision,
                correlation_id=CorrelationId("correlation-other"),
            ),
            observed_at=NOW,
        )


def test_begin_propagation_rejects_invalid_inputs_and_mismatches() -> None:
    decision = make_decision()
    request = make_request(decision)
    lifecycle = make_lifecycle(decision)
    requirement = make_requirement(decision, request, lifecycle)

    with pytest.raises(TerminationPropagationError, match="request must"):
        begin_termination_propagation(  # type: ignore[arg-type]
            "request",
            decision,
            lifecycle,
            requirement,
            targets=(),
            propagation_deadline=NOW + timedelta(seconds=1),
        )
    with pytest.raises(TerminationPropagationError, match="decision must"):
        begin_termination_propagation(  # type: ignore[arg-type]
            request,
            "decision",
            lifecycle,
            requirement,
            targets=(),
            propagation_deadline=NOW + timedelta(seconds=1),
        )
    with pytest.raises(TerminationPropagationError, match="lifecycle must"):
        begin_termination_propagation(  # type: ignore[arg-type]
            request,
            decision,
            "lifecycle",
            requirement,
            targets=(),
            propagation_deadline=NOW + timedelta(seconds=1),
        )
    with pytest.raises(TerminationPropagationError, match="requirement must"):
        begin_termination_propagation(  # type: ignore[arg-type]
            request,
            decision,
            lifecycle,
            "requirement",
            targets=(),
            propagation_deadline=NOW + timedelta(seconds=1),
        )

    inactive = evaluate_termination_requirement(
        request,
        decision,
        lifecycle,
        observed_at=NOW,
        cancellation_requested_at=None,
    )
    with pytest.raises(TerminationPropagationError, match="active cancellation"):
        begin_termination_propagation(
            request,
            decision,
            lifecycle,
            inactive,
            targets=(),
            propagation_deadline=NOW + timedelta(seconds=1),
        )

    mismatched_request = TerminationRequirement(
        request_id=RequestId("request-other"),
        routing_decision_id=requirement.routing_decision_id,
        correlation_id=requirement.correlation_id,
        evaluated_at=requirement.evaluated_at,
        required=True,
        reason=TerminationReason.CANCELLATION,
        triggered_at=requirement.triggered_at,
    )
    with pytest.raises(TerminationPropagationError, match="request_id"):
        begin_termination_propagation(
            request,
            decision,
            lifecycle,
            mismatched_request,
            targets=(),
            propagation_deadline=NOW + timedelta(seconds=1),
        )

    mismatched_decision = TerminationRequirement(
        request_id=requirement.request_id,
        routing_decision_id=RoutingDecisionId("route-other"),
        correlation_id=requirement.correlation_id,
        evaluated_at=requirement.evaluated_at,
        required=True,
        reason=TerminationReason.CANCELLATION,
        triggered_at=requirement.triggered_at,
    )
    with pytest.raises(TerminationPropagationError, match="routing_decision_id"):
        begin_termination_propagation(
            request,
            decision,
            lifecycle,
            mismatched_decision,
            targets=(),
            propagation_deadline=NOW + timedelta(seconds=1),
        )

    mismatched_correlation = TerminationRequirement(
        request_id=requirement.request_id,
        routing_decision_id=requirement.routing_decision_id,
        correlation_id=CorrelationId("correlation-other"),
        evaluated_at=requirement.evaluated_at,
        required=True,
        reason=TerminationReason.CANCELLATION,
        triggered_at=requirement.triggered_at,
    )
    with pytest.raises(TerminationPropagationError, match="correlation_id"):
        begin_termination_propagation(
            request,
            decision,
            lifecycle,
            mismatched_correlation,
            targets=(),
            propagation_deadline=NOW + timedelta(seconds=1),
        )

    with pytest.raises(TerminationPropagationError, match="targets must be a tuple"):
        begin_termination_propagation(
            request,
            decision,
            lifecycle,
            requirement,
            targets=cast(tuple[TerminationTarget, ...], []),
            propagation_deadline=NOW + timedelta(seconds=1),
        )
    with pytest.raises(TerminationPropagationError, match="TerminationTarget"):
        begin_termination_propagation(
            request,
            decision,
            lifecycle,
            requirement,
            targets=cast(tuple[TerminationTarget, ...], ("target",)),
            propagation_deadline=NOW + timedelta(seconds=1),
        )
    target = make_target()
    with pytest.raises(TerminationPropagationError, match="duplicate refs"):
        begin_termination_propagation(
            request,
            decision,
            lifecycle,
            requirement,
            targets=(target, target),
            propagation_deadline=NOW + timedelta(seconds=1),
        )
    with pytest.raises(TerminationPropagationError, match="propagation_deadline"):
        begin_termination_propagation(
            request,
            decision,
            lifecycle,
            requirement,
            targets=(),
            propagation_deadline=cast(datetime, "deadline"),
        )
    with pytest.raises(TerminationPropagationError, match="later than"):
        begin_termination_propagation(
            request,
            decision,
            lifecycle,
            requirement,
            targets=(),
            propagation_deadline=NOW,
        )


def test_acknowledge_function_rejects_invalid_or_repeated_target() -> None:
    propagation = make_propagation()
    acknowledgement = make_acknowledgement()

    with pytest.raises(TerminationPropagationError, match="propagation must"):
        acknowledge_termination_target(  # type: ignore[arg-type]
            "propagation",
            acknowledgement,
        )
    with pytest.raises(TerminationPropagationError, match="acknowledgement must"):
        acknowledge_termination_target(  # type: ignore[arg-type]
            propagation,
            "acknowledgement",
        )
    with pytest.raises(TerminationPropagationError, match="not part"):
        acknowledge_termination_target(
            propagation,
            make_acknowledgement("model.unknown"),
        )
    state = acknowledge_termination_target(propagation, acknowledgement)
    with pytest.raises(TerminationPropagationError, match="already acknowledged"):
        acknowledge_termination_target(state, acknowledgement)
    with pytest.raises(TerminationPropagationError, match="cannot predate"):
        acknowledge_termination_target(
            propagation,
            make_acknowledgement(
                acknowledged_at=NOW - timedelta(seconds=1),
            ),
        )


def test_evaluation_rejects_invalid_input_and_time() -> None:
    propagation = make_propagation()
    with pytest.raises(TerminationPropagationError, match="propagation must"):
        evaluate_termination_propagation(  # type: ignore[arg-type]
            "propagation",
            observed_at=NOW,
        )
    with pytest.raises(TerminationPropagationError, match="observed_at"):
        evaluate_termination_propagation(
            propagation,
            observed_at=cast(datetime, "now"),
        )
    with pytest.raises(TerminationPropagationError, match="cannot predate"):
        evaluate_termination_propagation(
            propagation,
            observed_at=NOW - timedelta(seconds=1),
        )


def test_evaluation_contract_rejects_invalid_state() -> None:
    values: dict[str, object] = {
        "request_id": REQUEST_ID,
        "routing_decision_id": DECISION_ID,
        "evaluated_at": NOW,
        "status": TerminationPropagationStatus.PENDING,
        "deadline_exceeded": False,
        "pending_target_refs": ("model.a",),
        "cleanup_pending_target_refs": (),
        "failed_target_refs": (),
        "late_ack_target_refs": (),
    }
    cases: tuple[tuple[str, object, str], ...] = (
        ("request_id", "request", "request_id"),
        ("routing_decision_id", "route", "routing_decision_id"),
        ("evaluated_at", "now", "evaluated_at"),
        ("status", "PENDING", "status"),
        ("deadline_exceeded", 1, "deadline_exceeded"),
        ("pending_target_refs", ["model.a"], "must be a tuple"),
        ("pending_target_refs", ("bad ref",), "machine-evaluable token"),
        ("pending_target_refs", ("model.a", "model.a"), "duplicates"),
        ("pending_target_refs", ("model.b", "model.a"), "sorted"),
    )
    for field_name, value, message in cases:
        invalid = dict(values)
        invalid[field_name] = value
        with pytest.raises(TerminationPropagationError, match=message):
            TerminationPropagationEvaluation(**invalid)  # type: ignore[arg-type]
