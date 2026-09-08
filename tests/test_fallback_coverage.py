"""Targeted defensive coverage for deterministic P5 fallback replanning."""

from datetime import datetime, timedelta, timezone
from typing import cast

import pytest
from cybersecgpt.foundation import (
    AuthorizationContextId,
    CorrelationId,
    RequestId,
    RoutingDecisionId,
    RoutingSecurityBinding,
    SubstrateId,
)

from cybersecgpt.reasoning import (
    CandidateSelectionResult,
    FallbackReplanError,
    FallbackReplanPolicy,
    FallbackReplanResult,
    FallbackReplanStatus,
    FallbackTrigger,
    ReasoningBudget,
    ReasoningBudgetUsage,
    RoutingDecision,
    RoutingDecisionReasonCode,
    RoutingDecisionValidation,
    RoutingReasoningBudgetUsage,
    SubstrateAvailabilityState,
    SubstrateKind,
    TerminationRequirement,
    replan_fallback_route,
)

from .test_candidates import NOW, make_binding, make_policy, make_request, make_snapshot
from .test_fallback import (
    FALLBACK_DECISION_ID,
    FALLBACK_ID,
    OWNER,
    PRIMARY_DECISION_ID,
    PRIMARY_ID,
    make_budget_state,
    make_decision,
    make_fallback_descriptor,
    make_fallback_policy,
    make_inactive_termination,
    make_primary_descriptor,
    run_replan,
)


def _successful_result() -> FallbackReplanResult:
    return run_replan()


def _result_values(result: FallbackReplanResult) -> dict[str, object]:
    return {
        "request_id": result.request_id,
        "correlation_id": result.correlation_id,
        "previous_decision_id": result.previous_decision_id,
        "trigger": result.trigger,
        "replanned_at": result.replanned_at,
        "policy": result.policy,
        "previous_validation": result.previous_validation,
        "unavailable_substrates": result.unavailable_substrates,
        "candidate_selection": result.candidate_selection,
        "status": result.status,
        "replacement_decision": result.replacement_decision,
        "replacement_budget_state": result.replacement_budget_state,
    }


def test_policy_rejects_invalid_text_and_collection_shapes() -> None:
    cases: tuple[tuple[dict[str, object], str], ...] = (
        ({"fallback_policy_id": 1}, "fallback_policy_id must be a string"),
        ({"fallback_policy_id": " bad"}, "fallback_policy_id"),
        ({"fallback_policy_version": ""}, "fallback_policy_version"),
        ({"allowed_triggers": [FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE]}, "tuple"),
        ({"allowed_triggers": ()}, "must not be empty"),
        ({"allowed_triggers": ("PRIMARY_ROUTE_UNAVAILABLE",)}, "FallbackTrigger"),
        (
            {
                "allowed_triggers": (
                    FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE,
                    FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE,
                )
            },
            "duplicates",
        ),
        ({"allowed_owner_refs": [OWNER]}, "allowed_owner_refs must be a tuple"),
        ({"allowed_owner_refs": ()}, "allowed_owner_refs must not be empty"),
        ({"allowed_owner_refs": (" owner",)}, "allowed_owner_refs item"),
        ({"allowed_owner_refs": (OWNER, OWNER)}, "allowed_owner_refs"),
        ({"allowed_substrate_kinds": [SubstrateKind.NATIVE_MODEL]}, "tuple"),
        ({"allowed_substrate_kinds": ()}, "must not be empty"),
        ({"allowed_substrate_kinds": ("NATIVE_MODEL",)}, "SubstrateKind"),
        (
            {
                "allowed_substrate_kinds": (
                    SubstrateKind.NATIVE_MODEL,
                    SubstrateKind.NATIVE_MODEL,
                )
            },
            "duplicates",
        ),
        ({"allowed_network_requirements": ("bad token",)}, "machine-evaluable"),
        ({"allowed_network_requirements": ("none", "none")}, "duplicates"),
        ({"allow_degraded": 1}, "allow_degraded"),
        ({"max_selected_substrates": True}, "positive integer"),
        ({"max_selected_substrates": 0}, "positive integer"),
        ({"allow_previous_substrate_reuse": 1}, "allow_previous_substrate_reuse"),
    )
    for overrides, message in cases:
        with pytest.raises(FallbackReplanError, match=message):
            make_fallback_policy(**overrides)


def test_replanned_at_rejects_wrong_or_non_utc_datetime() -> None:
    result = _successful_result()
    values = _result_values(result)
    values["replanned_at"] = "now"
    with pytest.raises(FallbackReplanError, match="replanned_at must be a datetime"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]

    values["replanned_at"] = datetime(2026, 9, 8, 12, 0)
    with pytest.raises(FallbackReplanError, match="timezone-aware UTC"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]

    values["replanned_at"] = datetime(
        2026,
        9,
        8,
        12,
        0,
        tzinfo=timezone(timedelta(hours=1)),
    )
    with pytest.raises(FallbackReplanError, match="timezone-aware UTC"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]


def test_result_rejects_invalid_identity_and_metadata_types() -> None:
    result = _successful_result()
    cases: tuple[tuple[str, object, str], ...] = (
        ("request_id", "request", "request_id"),
        ("correlation_id", "correlation", "correlation_id"),
        ("previous_decision_id", "route", "previous_decision_id"),
        ("trigger", "PRIMARY_ROUTE_UNAVAILABLE", "trigger"),
        ("policy", "policy", "policy"),
        ("previous_validation", "validation", "previous_validation"),
        ("unavailable_substrates", [PRIMARY_ID], "tuple"),
        ("unavailable_substrates", ("primary",), "SubstrateId"),
        ("candidate_selection", "selection", "candidate_selection"),
        ("status", "ROUTE_SELECTED", "status"),
    )
    for field_name, value, message in cases:
        values = _result_values(result)
        values[field_name] = value
        with pytest.raises(FallbackReplanError, match=message):
            FallbackReplanResult(**values)  # type: ignore[arg-type]


def test_result_rejects_validation_and_unavailable_identity_inconsistency() -> None:
    result = _successful_result()
    values = _result_values(result)
    values["previous_validation"] = RoutingDecisionValidation(
        decision_id=RoutingDecisionId("other-route"),
        validated_at=NOW,
        valid=True,
        invalid_reasons=(),
    )
    with pytest.raises(FallbackReplanError, match="previous_decision_id"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]

    values = _result_values(result)
    values["unavailable_substrates"] = (PRIMARY_ID, PRIMARY_ID)
    with pytest.raises(FallbackReplanError, match="duplicates"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]

    values = _result_values(result)
    values["unavailable_substrates"] = (
        SubstrateId("z-substrate"),
        SubstrateId("a-substrate"),
    )
    with pytest.raises(FallbackReplanError, match="sorted"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]


def test_result_rejects_candidate_request_mismatch() -> None:
    result = _successful_result()
    selection = result.candidate_selection
    mismatched = CandidateSelectionResult(
        request_id=RequestId("other-request"),
        capability_snapshot_id=selection.capability_snapshot_id,
        policy=selection.policy,
        observed_at=selection.observed_at,
        evaluations=selection.evaluations,
        selected_substrates=selection.selected_substrates,
        reason_codes=selection.reason_codes,
    )
    values = _result_values(result)
    values["candidate_selection"] = mismatched
    with pytest.raises(FallbackReplanError, match="candidate_selection request_id"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]


def test_route_selected_result_rejects_replacement_inconsistency() -> None:
    result = _successful_result()
    assert result.replacement_decision is not None
    assert result.replacement_budget_state is not None

    cases: list[tuple[dict[str, object], str]] = [
        ({"replacement_decision": None}, "replacement RoutingDecision"),
        ({"replacement_budget_state": None}, "replacement budget state"),
    ]
    for overrides, message in cases:
        values = _result_values(result)
        values.update(overrides)
        with pytest.raises(FallbackReplanError, match=message):
            FallbackReplanResult(**values)  # type: ignore[arg-type]

    reused = RoutingDecision(
        decision_id=result.previous_decision_id,
        security_binding=result.replacement_decision.security_binding,
        router_policy_id=result.replacement_decision.router_policy_id,
        router_policy_version=result.replacement_decision.router_policy_version,
        selected_substrates=result.replacement_decision.selected_substrates,
        reason_codes=result.replacement_decision.reason_codes,
        reasoning_budget=result.replacement_decision.reasoning_budget,
        created_at=result.replacement_decision.created_at,
        expires_at=result.replacement_decision.expires_at,
    )
    values = _result_values(result)
    values["replacement_decision"] = reused
    with pytest.raises(FallbackReplanError, match="fresh identity"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]

    wrong_selection = RoutingDecision(
        decision_id=RoutingDecisionId("different-new-route"),
        security_binding=result.replacement_decision.security_binding,
        router_policy_id=result.replacement_decision.router_policy_id,
        router_policy_version=result.replacement_decision.router_policy_version,
        selected_substrates=(SubstrateId("other-substrate"),),
        reason_codes=result.replacement_decision.reason_codes,
        reasoning_budget=result.replacement_decision.reasoning_budget,
        created_at=result.replacement_decision.created_at,
        expires_at=result.replacement_decision.expires_at,
    )
    values = _result_values(result)
    values["replacement_decision"] = wrong_selection
    with pytest.raises(FallbackReplanError, match="selected fallback substrates"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]

    wrong_budget_id = RoutingReasoningBudgetUsage(
        decision_id=RoutingDecisionId("other-budget-route"),
        usage=result.replacement_budget_state.usage,
    )
    values = _result_values(result)
    values["replacement_budget_state"] = wrong_budget_id
    with pytest.raises(FallbackReplanError, match="bind to replacement decision"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]

    different_budget = ReasoningBudget(
        policy_name="NORMAL",
        max_candidates=7,
        max_branch_depth=4,
        max_steps=16,
        max_model_tokens=4096,
        max_tool_calls=2,
        max_retrieval_calls=4,
        max_verifier_passes=3,
    )
    wrong_budget = RoutingReasoningBudgetUsage(
        decision_id=result.replacement_decision.decision_id,
        usage=ReasoningBudgetUsage(budget=different_budget),
    )
    values = _result_values(result)
    values["replacement_budget_state"] = wrong_budget
    with pytest.raises(FallbackReplanError, match="replacement budget must match"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]


def test_no_valid_route_result_rejects_selected_or_replacement_state() -> None:
    no_route = run_replan(
        fallback_policy=make_fallback_policy(allowed_owner_refs=("other/owner",)),
    )
    assert no_route.status is FallbackReplanStatus.NO_VALID_ROUTE

    selected = _successful_result().candidate_selection
    values = _result_values(no_route)
    values["candidate_selection"] = selected
    with pytest.raises(FallbackReplanError, match="must not contain selected"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]

    successful = _successful_result()
    values = _result_values(no_route)
    values["replacement_decision"] = successful.replacement_decision
    with pytest.raises(FallbackReplanError, match="replacement decision"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]

    values = _result_values(no_route)
    values["replacement_budget_state"] = successful.replacement_budget_state
    with pytest.raises(FallbackReplanError, match="replacement budget state"):
        FallbackReplanResult(**values)  # type: ignore[arg-type]


def test_request_continuity_rejects_binding_and_admission_time_anomalies() -> None:
    previous = make_request()
    binding = make_binding()
    current = make_request(security_binding=binding)
    other_binding = make_binding(
        authorization_context_id=AuthorizationContextId("other-auth"),
    )
    with pytest.raises(FallbackReplanError, match="match current_binding"):
        run_replan(
            previous_request=previous,
            current_request=current,
            current_binding=other_binding,
        )

    earlier = make_request(admitted_at=previous.admitted_at - timedelta(seconds=1))
    with pytest.raises(FallbackReplanError, match="move backward"):
        run_replan(previous_request=previous, current_request=earlier)

    future = make_request(admitted_at=NOW + timedelta(seconds=1))
    with pytest.raises(FallbackReplanError, match="future"):
        run_replan(previous_request=previous, current_request=future)


def test_budget_carry_rejects_request_decision_and_stop_condition_mismatches() -> None:
    previous = make_request()
    other_budget = ReasoningBudget(
        policy_name="NORMAL",
        max_candidates=7,
        max_branch_depth=4,
        max_steps=16,
        max_model_tokens=4096,
        max_tool_calls=2,
        max_retrieval_calls=4,
        max_verifier_passes=3,
    )
    decision = make_decision(previous)
    mismatched_decision = RoutingDecision(
        decision_id=decision.decision_id,
        security_binding=decision.security_binding,
        router_policy_id=decision.router_policy_id,
        router_policy_version=decision.router_policy_version,
        selected_substrates=decision.selected_substrates,
        reason_codes=decision.reason_codes,
        reasoning_budget=other_budget,
        created_at=decision.created_at,
        expires_at=decision.expires_at,
    )
    with pytest.raises(FallbackReplanError, match="request budget"):
        run_replan(
            previous_request=previous,
            previous_decision=mismatched_decision,
            previous_budget_state=RoutingReasoningBudgetUsage(
                decision_id=mismatched_decision.decision_id,
                usage=ReasoningBudgetUsage(budget=other_budget),
            ),
        )

    previous_with_stop = make_request(
        reasoning_budget=ReasoningBudget(
            policy_name="NORMAL",
            max_candidates=8,
            max_branch_depth=4,
            max_steps=16,
            max_model_tokens=4096,
            max_tool_calls=2,
            max_retrieval_calls=4,
            max_verifier_passes=3,
            stop_conditions=("quality_floor",),
        )
    )
    stop_decision = make_decision(previous_with_stop)
    current_without_stop = make_request()
    with pytest.raises(FallbackReplanError, match="stop conditions"):
        run_replan(
            previous_request=previous_with_stop,
            current_request=current_without_stop,
            previous_decision=stop_decision,
            previous_budget_state=make_budget_state(stop_decision),
        )


def test_termination_binding_rejects_wrong_types_and_identifiers() -> None:
    request = make_request()
    decision = make_decision(request)
    budget_state = make_budget_state(decision)
    snapshot = make_snapshot(make_primary_descriptor(), make_fallback_descriptor())
    policy = make_policy(max_selected_substrates=2)
    fallback = make_fallback_policy()

    def call(requirement: object) -> None:
        replan_fallback_route(
            request,
            request,
            decision,
            budget_state,
            snapshot,
            policy,
            fallback,
            cast(TerminationRequirement, requirement),
            trigger=FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE,
            unavailable_substrates=(PRIMARY_ID,),
            current_binding=request.security_binding,
            new_decision_id=FALLBACK_DECISION_ID,
            observed_at=NOW,
            replacement_expires_at=NOW + timedelta(minutes=2),
        )

    with pytest.raises(FallbackReplanError, match="termination_requirement"):
        call("termination")

    base = make_inactive_termination(request, decision)
    cases = (
        ("request_id", RequestId("other-request"), "request_id"),
        ("routing_decision_id", RoutingDecisionId("other-route"), "previous routing"),
        ("correlation_id", CorrelationId("other-correlation"), "correlation_id"),
        ("evaluated_at", NOW - timedelta(seconds=1), "replanning time"),
    )
    for field_name, value, message in cases:
        object.__setattr__(base, field_name, value)
        with pytest.raises(FallbackReplanError, match=message):
            call(base)
        object.__setattr__(
            base,
            field_name,
            {
                "request_id": request.request_id,
                "routing_decision_id": decision.decision_id,
                "correlation_id": request.correlation_id,
                "evaluated_at": NOW,
            }[field_name],
        )


def test_replan_rejects_invalid_public_argument_types_and_times() -> None:
    request = make_request()
    decision = make_decision(request)
    budget_state = make_budget_state(decision)
    snapshot = make_snapshot(make_primary_descriptor(), make_fallback_descriptor())
    candidate_policy = make_policy(max_selected_substrates=2)
    fallback_policy = make_fallback_policy()
    termination = make_inactive_termination(request, decision)

    base: list[object] = [
        request,
        request,
        decision,
        budget_state,
        snapshot,
        candidate_policy,
        fallback_policy,
        termination,
    ]
    names = (
        "previous_request",
        "current_request",
        "previous_decision",
        "previous_budget_state",
        "snapshot",
        "candidate_policy",
        "fallback_policy",
    )
    for index, name in enumerate(names):
        args = list(base)
        args[index] = "invalid"
        with pytest.raises(FallbackReplanError, match=name):
            replan_fallback_route(
                *args,  # type: ignore[arg-type]
                trigger=FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE,
                unavailable_substrates=(PRIMARY_ID,),
                current_binding=request.security_binding,
                new_decision_id=FALLBACK_DECISION_ID,
                observed_at=NOW,
                replacement_expires_at=NOW + timedelta(minutes=2),
            )

    with pytest.raises(FallbackReplanError, match="trigger"):
        replan_fallback_route(
            *base,  # type: ignore[arg-type]
            trigger="PRIMARY_ROUTE_UNAVAILABLE",  # type: ignore[arg-type]
            unavailable_substrates=(PRIMARY_ID,),
            current_binding=request.security_binding,
            new_decision_id=FALLBACK_DECISION_ID,
            observed_at=NOW,
            replacement_expires_at=NOW + timedelta(minutes=2),
        )

    with pytest.raises(FallbackReplanError, match="not allowed"):
        replan_fallback_route(
            *base,  # type: ignore[arg-type]
            trigger=FallbackTrigger.UNCERTAINTY_ESCALATION,
            unavailable_substrates=(),
            current_binding=request.security_binding,
            new_decision_id=FALLBACK_DECISION_ID,
            observed_at=NOW,
            replacement_expires_at=NOW + timedelta(minutes=2),
        )

    with pytest.raises(FallbackReplanError, match="current_binding"):
        replan_fallback_route(
            *base,  # type: ignore[arg-type]
            trigger=FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE,
            unavailable_substrates=(PRIMARY_ID,),
            current_binding="binding",  # type: ignore[arg-type]
            new_decision_id=FALLBACK_DECISION_ID,
            observed_at=NOW,
            replacement_expires_at=NOW + timedelta(minutes=2),
        )

    with pytest.raises(FallbackReplanError, match="new_decision_id"):
        replan_fallback_route(
            *base,  # type: ignore[arg-type]
            trigger=FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE,
            unavailable_substrates=(PRIMARY_ID,),
            current_binding=request.security_binding,
            new_decision_id="route",  # type: ignore[arg-type]
            observed_at=NOW,
            replacement_expires_at=NOW + timedelta(minutes=2),
        )

    with pytest.raises(FallbackReplanError, match="observed_at must be a datetime"):
        replan_fallback_route(
            *base,  # type: ignore[arg-type]
            trigger=FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE,
            unavailable_substrates=(PRIMARY_ID,),
            current_binding=request.security_binding,
            new_decision_id=FALLBACK_DECISION_ID,
            observed_at="now",  # type: ignore[arg-type]
            replacement_expires_at=NOW + timedelta(minutes=2),
        )

    with pytest.raises(FallbackReplanError, match="replacement_expires_at"):
        run_replan(replacement_expires_at=NOW)


def test_replan_rejects_previous_binding_and_admission_anomalies() -> None:
    previous = make_request()
    mismatched_binding = make_binding(
        authorization_context_id=AuthorizationContextId("mismatch-auth"),
    )
    decision = make_decision(previous)
    object.__setattr__(decision, "security_binding", mismatched_binding)
    with pytest.raises(FallbackReplanError, match="previous decision security binding"):
        run_replan(previous_request=previous, previous_decision=decision)

    future = make_request(admitted_at=NOW + timedelta(seconds=1))
    future_decision = make_decision(future)
    with pytest.raises(FallbackReplanError, match="previous request admission"):
        run_replan(
            previous_request=future,
            current_request=future,
            previous_decision=future_decision,
            previous_budget_state=make_budget_state(future_decision),
        )


def test_replan_rejects_invalid_unavailable_collection() -> None:
    with pytest.raises(FallbackReplanError, match="unavailable_substrates must be a tuple"):
        run_replan(unavailable_substrates=cast(tuple[SubstrateId, ...], [PRIMARY_ID]))

    with pytest.raises(FallbackReplanError, match="only SubstrateId"):
        run_replan(unavailable_substrates=cast(tuple[SubstrateId, ...], ("primary",)))

    with pytest.raises(FallbackReplanError, match="duplicates"):
        run_replan(unavailable_substrates=(PRIMARY_ID, PRIMARY_ID))


def test_fallback_filters_kind_network_and_degraded_constraints() -> None:
    tool = make_fallback_descriptor(
        substrate_id=SubstrateId("tool:fallback"),
        substrate_kind=SubstrateKind.TOOL,
    )
    networked = make_fallback_descriptor(
        substrate_id=SubstrateId("model:networked"),
        network_requirements=("internet",),
    )
    degraded = make_fallback_descriptor(
        substrate_id=SubstrateId("model:degraded"),
        availability_state=SubstrateAvailabilityState.DEGRADED,
    )
    snapshot = make_snapshot(
        make_primary_descriptor(),
        tool,
        networked,
        degraded,
    )
    result = run_replan(
        snapshot=snapshot,
        candidate_policy=make_policy(
            allowed_substrate_kinds=(SubstrateKind.NATIVE_MODEL, SubstrateKind.TOOL),
            allowed_network_requirements=("none", "internet"),
            allow_degraded=True,
            max_selected_substrates=4,
        ),
        fallback_policy=make_fallback_policy(
            allowed_substrate_kinds=(SubstrateKind.NATIVE_MODEL,),
            allowed_network_requirements=("none",),
            allow_degraded=False,
            max_selected_substrates=4,
        ),
    )
    assert result.status is FallbackReplanStatus.NO_VALID_ROUTE


def test_route_execution_failure_maps_to_primary_unavailable_reason() -> None:
    result = run_replan(trigger=FallbackTrigger.ROUTE_EXECUTION_FAILURE)
    assert result.replacement_decision is not None
    assert RoutingDecisionReasonCode.PRIMARY_ROUTE_UNAVAILABLE in (
        result.replacement_decision.reason_codes
    )
