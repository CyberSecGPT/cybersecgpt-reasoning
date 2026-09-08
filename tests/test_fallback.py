"""Tests for deterministic P5 fallback replanning."""

from dataclasses import FrozenInstanceError
from datetime import timedelta
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
    CandidateSelectionPolicy,
    FallbackReplanError,
    FallbackReplanPolicy,
    FallbackReplanResult,
    FallbackReplanStatus,
    FallbackTrigger,
    ReasoningBudget,
    ReasoningBudgetDelta,
    RoutingDecision,
    RoutingDecisionInvalidReason,
    RoutingDecisionReasonCode,
    RoutingReasoningBudgetUsage,
    SubstrateAvailabilityState,
    SubstrateKind,
    TerminationRequirement,
    begin_routing_reasoning_budget,
    consume_routing_reasoning_budget,
    replan_fallback_route,
)
from tests.test_candidates import (
    NOW,
    make_binding,
    make_budget,
    make_descriptor,
    make_policy,
    make_request,
    make_resource,
    make_snapshot,
)

PRIMARY_ID = SubstrateId("model:native-primary")
FALLBACK_ID = SubstrateId("model:native-fallback")
OWNER = "CyberSecGPT/cybersecgpt-inference"


def make_primary_descriptor(**overrides: object):
    values: dict[str, object] = {
        "substrate_id": PRIMARY_ID,
        "resource_profile": make_resource(min_compute_units=1),
    }
    values.update(overrides)
    return make_descriptor(**values)


def make_fallback_descriptor(**overrides: object):
    values: dict[str, object] = {
        "substrate_id": FALLBACK_ID,
        "resource_profile": make_resource(min_compute_units=2),
    }
    values.update(overrides)
    return make_descriptor(**values)


def make_decision(
    request: BrainRequest,
    *,
    decision_id: RoutingDecisionId = RoutingDecisionId("route-primary"),
    selected_substrates: tuple[SubstrateId, ...] = (PRIMARY_ID,),
    created_at=NOW - timedelta(minutes=1),
    expires_at=NOW + timedelta(minutes=4),
) -> RoutingDecision:
    return RoutingDecision(
        decision_id=decision_id,
        security_binding=request.security_binding,
        router_policy_id="router.default",
        router_policy_version="1.0.0",
        selected_substrates=selected_substrates,
        reason_codes=(RoutingDecisionReasonCode.CAPABILITY_MATCH,),
        reasoning_budget=request.reasoning_budget,
        created_at=created_at,
        expires_at=expires_at,
    )


def make_budget_state(
    decision: RoutingDecision,
    *,
    steps: int = 2,
    model_tokens: int = 100,
) -> RoutingReasoningBudgetUsage:
    return consume_routing_reasoning_budget(
        decision,
        begin_routing_reasoning_budget(decision),
        ReasoningBudgetDelta(steps=steps, model_tokens=model_tokens),
    )


def make_termination_requirement(
    request: BrainRequest,
    decision: RoutingDecision,
    *,
    required: bool = False,
) -> TerminationRequirement:
    return TerminationRequirement(
        request_id=request.request_id,
        routing_decision_id=decision.decision_id,
        correlation_id=request.correlation_id,
        evaluated_at=NOW,
        required=required,
        reason=None if not required else cast(object, "CANCELLATION"),
        triggered_at=None,
    )


def make_inactive_termination(
    request: BrainRequest,
    decision: RoutingDecision,
) -> TerminationRequirement:
    return TerminationRequirement(
        request_id=request.request_id,
        routing_decision_id=decision.decision_id,
        correlation_id=request.correlation_id,
        evaluated_at=NOW,
        required=False,
        reason=None,
        triggered_at=None,
    )


def make_fallback_policy(**overrides: object) -> FallbackReplanPolicy:
    values: dict[str, object] = {
        "fallback_policy_id": "fallback.native-core",
        "fallback_policy_version": "1.0.0",
        "allowed_triggers": tuple(FallbackTrigger),
        "allowed_owner_refs": (OWNER,),
        "allowed_substrate_kinds": (SubstrateKind.NATIVE_MODEL,),
        "allowed_network_requirements": ("none",),
        "allow_degraded": False,
        "max_selected_substrates": 1,
        "allow_previous_substrate_reuse": False,
    }
    values.update(overrides)
    return FallbackReplanPolicy(**values)  # type: ignore[arg-type]


def run_replan(
    *,
    previous_request: BrainRequest | None = None,
    current_request: BrainRequest | None = None,
    previous_decision: RoutingDecision | None = None,
    previous_budget_state: RoutingReasoningBudgetUsage | None = None,
    snapshot=None,
    candidate_policy: CandidateSelectionPolicy | None = None,
    fallback_policy: FallbackReplanPolicy | None = None,
    termination_requirement: TerminationRequirement | None = None,
    trigger: FallbackTrigger = FallbackTrigger.PRIMARY_ROUTE_UNAVAILABLE,
    unavailable_substrates: tuple[SubstrateId, ...] = (PRIMARY_ID,),
    current_binding: RoutingSecurityBinding | None = None,
    new_decision_id: RoutingDecisionId = RoutingDecisionId("route-fallback"),
    replacement_expires_at=NOW + timedelta(minutes=2),
) -> FallbackReplanResult:
    previous = previous_request or make_request()
    current = current_request or previous
    decision = previous_decision or make_decision(previous)
    budget_state = previous_budget_state or make_budget_state(decision)
    actual_snapshot = snapshot or make_snapshot(
        make_primary_descriptor(),
        make_fallback_descriptor(),
    )
    policy = candidate_policy or make_policy(max_selected_substrates=2)
    fallback = fallback_policy or make_fallback_policy()
    termination = termination_requirement or make_inactive_termination(
        current,
        decision,
    )
    binding = current_binding or current.security_binding
    return replan_fallback_route(
        previous,
        current,
        decision,
        budget_state,
        actual_snapshot,
        policy,
        fallback,
        termination,
        trigger=trigger,
        unavailable_substrates=unavailable_substrates,
        current_binding=binding,
        new_decision_id=new_decision_id,
        observed_at=NOW,
        replacement_expires_at=replacement_expires_at,
    )


def test_fallback_selects_fresh_route_and_carries_consumed_budget() -> None:
    result = run_replan()

    assert result.status is FallbackReplanStatus.ROUTE_SELECTED
    assert result.previous_decision_id == RoutingDecisionId("route-primary")
    assert result.unavailable_substrates == (PRIMARY_ID,)
    assert result.candidate_selection.selected_substrates == (FALLBACK_ID,)
    assert result.replacement_decision is not None
    assert result.replacement_decision.decision_id == RoutingDecisionId("route-fallback")
    assert result.replacement_decision.selected_substrates == (FALLBACK_ID,)
    assert (
        RoutingDecisionReasonCode.PRIMARY_ROUTE_UNAVAILABLE
        in result.replacement_decision.reason_codes
    )
    assert result.replacement_budget_state is not None
    assert result.replacement_budget_state.decision_id == RoutingDecisionId(
        "route-fallback"
    )
    assert result.replacement_budget_state.usage.steps == 2
    assert result.replacement_budget_state.usage.model_tokens == 100
    assert result.replacement_budget_state.usage.budget == make_budget()

    with pytest.raises(FrozenInstanceError):
        result.status = FallbackReplanStatus.NO_VALID_ROUTE  # type: ignore[misc]


def test_fallback_policy_prevents_implicit_network_or_owner_broadening() -> None:
    remote = make_descriptor(
        substrate_id=SubstrateId("model:remote"),
        owner="external/provider",
        network_requirements=("internet",),
        offline_capable=False,
        resource_profile=make_resource(min_compute_units=1),
    )
    local = make_fallback_descriptor(
        resource_profile=make_resource(min_compute_units=3),
    )
    snapshot = make_snapshot(make_primary_descriptor(), remote, local)
    candidate_policy = make_policy(
        allowed_network_requirements=("none", "internet"),
        max_selected_substrates=3,
    )

    result = run_replan(snapshot=snapshot, candidate_policy=candidate_policy)

    assert result.candidate_selection.selected_substrates == (FALLBACK_ID,)
    assert SubstrateId("model:remote") not in result.candidate_selection.selected_substrates


def test_fallback_returns_explicit_no_valid_route_without_relaxation() -> None:
    result = run_replan(
        fallback_policy=make_fallback_policy(allowed_owner_refs=("other/owner",)),
    )

    assert result.status is FallbackReplanStatus.NO_VALID_ROUTE
    assert result.candidate_selection.selected_substrates == ()
    assert result.replacement_decision is None
    assert result.replacement_budget_state is None


def test_stale_decision_replans_under_fresh_policy_revision_and_snapshot() -> None:
    previous = make_request()
    decision = make_decision(
        previous,
        expires_at=NOW + timedelta(minutes=4),
    )
    current_binding = make_binding(
        security_policy_revision_id=SecurityPolicyRevisionId("security-rev-8"),
        capability_snapshot_id=CapabilitySnapshotId("capabilities-selection-2"),
    )
    current = make_request(security_binding=current_binding)
    snapshot = make_snapshot(
        make_primary_descriptor(),
        snapshot_id=current_binding.capability_snapshot_id,
    )
    candidate_policy = make_policy(
        security_policy_revision_id=current_binding.security_policy_revision_id,
        authorization_context_id=current_binding.authorization_context_id,
        provider_network_policy=current_binding.provider_network_policy,
        max_selected_substrates=1,
    )
    termination = make_inactive_termination(current, decision)

    result = run_replan(
        previous_request=previous,
        current_request=current,
        previous_decision=decision,
        previous_budget_state=make_budget_state(decision),
        snapshot=snapshot,
        candidate_policy=candidate_policy,
        fallback_policy=make_fallback_policy(allow_previous_substrate_reuse=True),
        termination_requirement=termination,
        trigger=FallbackTrigger.STALE_ROUTING_DECISION,
        unavailable_substrates=(),
        current_binding=current_binding,
    )

    assert result.status is FallbackReplanStatus.ROUTE_SELECTED
    assert result.previous_validation.valid is False
    assert RoutingDecisionInvalidReason.SECURITY_POLICY_REVISION_MISMATCH in (
        result.previous_validation.invalid_reasons
    )
    assert RoutingDecisionInvalidReason.CAPABILITY_SNAPSHOT_MISMATCH in (
        result.previous_validation.invalid_reasons
    )
    assert result.replacement_decision is not None
    assert result.replacement_decision.security_binding == current_binding
    assert (
        RoutingDecisionReasonCode.STALE_DECISION_REJECTED
        in result.replacement_decision.reason_codes
    )


def test_stale_trigger_rejects_still_valid_previous_decision() -> None:
    with pytest.raises(FallbackReplanError, match="invalid previous"):
        run_replan(
            trigger=FallbackTrigger.STALE_ROUTING_DECISION,
            unavailable_substrates=(),
            fallback_policy=make_fallback_policy(allow_previous_substrate_reuse=True),
        )


def test_fallback_rejects_active_termination_state() -> None:
    request = make_request()
    decision = make_decision(request)
    termination = TerminationRequirement(
        request_id=request.request_id,
        routing_decision_id=decision.decision_id,
        correlation_id=request.correlation_id,
        evaluated_at=NOW,
        required=True,
        reason=cast(object, __import__("cybersecgpt.reasoning", fromlist=["TerminationReason"]).TerminationReason.CANCELLATION),
        triggered_at=NOW - timedelta(seconds=1),
    )
    with pytest.raises(FallbackReplanError, match="forbidden after cancellation"):
        run_replan(
            previous_request=request,
            current_request=request,
            previous_decision=decision,
            previous_budget_state=make_budget_state(decision),
            termination_requirement=termination,
        )


@pytest.mark.parametrize(
    "fallback_policy,candidate_policy,message",
    [
        (
            make_fallback_policy(allowed_substrate_kinds=(SubstrateKind.TOOL,)),
            make_policy(allowed_substrate_kinds=(SubstrateKind.NATIVE_MODEL,)),
            "subset of candidate policy",
        ),
        (
            make_fallback_policy(allowed_network_requirements=("internet",)),
            make_policy(allowed_network_requirements=("none",)),
            "network requirements",
        ),
        (
            make_fallback_policy(allow_degraded=True),
            make_policy(allow_degraded=False),
            "degraded routes",
        ),
        (
            make_fallback_policy(max_selected_substrates=2),
            make_policy(max_selected_substrates=1),
            "max_selected_substrates",
        ),
    ],
)
def test_fallback_policy_cannot_widen_candidate_policy(
    fallback_policy: FallbackReplanPolicy,
    candidate_policy: CandidateSelectionPolicy,
    message: str,
) -> None:
    with pytest.raises(FallbackReplanError, match=message):
        run_replan(
            fallback_policy=fallback_policy,
            candidate_policy=candidate_policy,
        )


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"task_type": "different"}, "task_type"),
        ({"domain": "cyber"}, "domain"),
        ({"task_complexity": "deep"}, "task_complexity"),
        ({"safety_impact": "high"}, "safety_impact"),
        ({"source_data_classification": "claimed"}, "source_data_classification"),
        ({"identity_context_ref": "identity:2"}, "identity_context_ref"),
        ({"input_json": "{\"a\":1}"}, "input_json"),
        ({"max_latency_ms": 1001}, "max_latency_ms"),
        ({"max_compute_units": 9}, "max_compute_units"),
        ({"max_memory_bytes": 8193}, "max_memory_bytes"),
    ],
)
def test_fallback_rejects_request_identity_or_ceiling_changes(
    overrides: dict[str, object],
    message: str,
) -> None:
    previous = make_request()
    current = make_request(**overrides)
    with pytest.raises(FallbackReplanError, match=message):
        run_replan(previous_request=previous, current_request=current)


def test_fallback_rejects_request_and_correlation_identity_changes() -> None:
    previous = make_request()
    changed_request_binding = make_binding(request_id=RequestId("request-other"))
    changed_request = make_request(security_binding=changed_request_binding)
    with pytest.raises(FallbackReplanError, match="request identity"):
        run_replan(previous_request=previous, current_request=changed_request)

    changed_correlation = make_request(correlation_id=CorrelationId("other-correlation"))
    with pytest.raises(FallbackReplanError, match="correlation identity"):
        run_replan(previous_request=previous, current_request=changed_correlation)


def test_fallback_rejects_weakened_quality_and_deadline_requirements() -> None:
    previous_accuracy = make_request(required_accuracy=0.8)
    current_accuracy = make_request(required_accuracy=0.7)
    with pytest.raises(FallbackReplanError, match="required_accuracy"):
        run_replan(
            previous_request=previous_accuracy,
            current_request=current_accuracy,
        )

    previous_determinism = make_request(required_determinism=True)
    with pytest.raises(FallbackReplanError, match="determinism"):
        run_replan(
            previous_request=previous_determinism,
            current_request=make_request(required_determinism=False),
        )

    previous_explainability = make_request(required_explainability=True)
    with pytest.raises(FallbackReplanError, match="explainability"):
        run_replan(
            previous_request=previous_explainability,
            current_request=make_request(required_explainability=False),
        )

    previous_verification = make_request(
        verification_requirements=("evidence", "independent"),
    )
    with pytest.raises(FallbackReplanError, match="verification requirements"):
        run_replan(
            previous_request=previous_verification,
            current_request=make_request(verification_requirements=("evidence",)),
        )

    previous_deadline = make_request(deadline=NOW + timedelta(minutes=4))
    with pytest.raises(FallbackReplanError, match="deadline"):
        run_replan(
            previous_request=previous_deadline,
            current_request=make_request(deadline=NOW + timedelta(minutes=5)),
        )


def test_fallback_allows_stricter_quality_and_resource_requirements() -> None:
    previous = make_request(required_accuracy=0.7)
    current = make_request(
        required_accuracy=0.8,
        max_latency_ms=900,
        max_compute_units=7,
        max_memory_bytes=7000,
        required_determinism=True,
        required_explainability=True,
        verification_requirements=("evidence", "explainability"),
        deadline=NOW + timedelta(minutes=4),
    )
    result = run_replan(
        previous_request=previous,
        current_request=current,
        snapshot=make_snapshot(
            make_primary_descriptor(),
            make_fallback_descriptor(
                determinism_profile="seeded",
                verification_profile=("evidence", "explainability"),
            ),
        ),
        candidate_policy=make_policy(
            deterministic_profiles=("seeded",),
            explainability_profile="explainability",
            max_selected_substrates=2,
        ),
    )
    assert result.status is FallbackReplanStatus.NO_VALID_ROUTE


def test_fallback_rejects_security_boundary_relaxation_or_substitution() -> None:
    previous = make_request()

    cases = (
        (
            make_binding(
                authorization_context_id=AuthorizationContextId("auth-other"),
            ),
            "authorization context",
        ),
        (
            make_binding(effective_data_classification="public"),
            "effective data classification",
        ),
        (
            make_binding(provider_network_policy="internet-allowed"),
            "provider/network policy",
        ),
    )
    for binding, message in cases:
        current = make_request(security_binding=binding)
        with pytest.raises(FallbackReplanError, match=message):
            run_replan(
                previous_request=previous,
                current_request=current,
                current_binding=binding,
            )

    offline_previous_binding = make_binding(offline_required=True)
    offline_previous = make_request(security_binding=offline_previous_binding)
    relaxed_binding = make_binding(offline_required=False)
    relaxed = make_request(security_binding=relaxed_binding)
    with pytest.raises(FallbackReplanError, match="offline requirement"):
        run_replan(
            previous_request=offline_previous,
            current_request=relaxed,
            current_binding=relaxed_binding,
        )


def test_fallback_rejects_budget_reset_enlargement_and_consumed_underflow() -> None:
    previous = make_request()
    decision = make_decision(previous)
    usage = make_budget_state(decision, steps=3)

    enlarged_budget = ReasoningBudget(
        policy_name="NORMAL",
        max_candidates=9,
        max_branch_depth=4,
        max_steps=16,
        max_model_tokens=4096,
        max_tool_calls=2,
        max_retrieval_calls=4,
        max_verifier_passes=3,
    )
    with pytest.raises(FallbackReplanError, match="max_candidates"):
        run_replan(
            previous_request=previous,
            current_request=make_request(reasoning_budget=enlarged_budget),
            previous_decision=decision,
            previous_budget_state=usage,
        )

    renamed_budget = ReasoningBudget(
        policy_name="DEEP",
        max_candidates=8,
        max_branch_depth=4,
        max_steps=16,
        max_model_tokens=4096,
        max_tool_calls=2,
        max_retrieval_calls=4,
        max_verifier_passes=3,
    )
    with pytest.raises(FallbackReplanError, match="policy name"):
        run_replan(
            previous_request=previous,
            current_request=make_request(reasoning_budget=renamed_budget),
            previous_decision=decision,
            previous_budget_state=usage,
        )

    too_small_budget = ReasoningBudget(
        policy_name="NORMAL",
        max_candidates=8,
        max_branch_depth=4,
        max_steps=2,
        max_model_tokens=4096,
        max_tool_calls=2,
        max_retrieval_calls=4,
        max_verifier_passes=3,
    )
    with pytest.raises(FallbackReplanError, match="already consumed"):
        run_replan(
            previous_request=previous,
            current_request=make_request(reasoning_budget=too_small_budget),
            previous_decision=decision,
            previous_budget_state=usage,
        )


def test_fallback_rejects_budget_binding_mismatches() -> None:
    previous = make_request()
    decision = make_decision(previous)
    other_decision = make_decision(
        previous,
        decision_id=RoutingDecisionId("route-other"),
    )
    with pytest.raises(FallbackReplanError, match="previous routing decision"):
        run_replan(
            previous_request=previous,
            previous_decision=decision,
            previous_budget_state=make_budget_state(other_decision),
        )

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
    forged_state = RoutingReasoningBudgetUsage(
        decision_id=decision.decision_id,
        usage=cast(object, __import__("cybersecgpt.reasoning", fromlist=["ReasoningBudgetUsage"]).ReasoningBudgetUsage(budget=other_budget)),
    )
    with pytest.raises(FallbackReplanError, match="usage must match"):
        run_replan(
            previous_request=previous,
            previous_decision=decision,
            previous_budget_state=forged_state,
        )


def test_fallback_rejects_new_decision_deadline_extension_and_identity_reuse() -> None:
    with pytest.raises(FallbackReplanError, match="fresh identity"):
        run_replan(new_decision_id=RoutingDecisionId("route-primary"))

    with pytest.raises(FallbackReplanError, match="outlive"):
        run_replan(replacement_expires_at=NOW + timedelta(minutes=6))


def test_failure_trigger_requires_unavailable_substrate_identity() -> None:
    with pytest.raises(FallbackReplanError, match="unavailable substrate"):
        run_replan(unavailable_substrates=())


def test_previous_route_reuse_requires_explicit_fallback_policy() -> None:
    request = make_request()
    decision = make_decision(request)
    snapshot = make_snapshot(make_primary_descriptor())

    blocked = run_replan(
        previous_request=request,
        current_request=request,
        previous_decision=decision,
        previous_budget_state=make_budget_state(decision),
        snapshot=snapshot,
        trigger=FallbackTrigger.VERIFICATION_ESCALATION,
        unavailable_substrates=(),
        fallback_policy=make_fallback_policy(
            allowed_triggers=(FallbackTrigger.VERIFICATION_ESCALATION,),
        ),
    )
    assert blocked.status is FallbackReplanStatus.NO_VALID_ROUTE

    allowed = run_replan(
        previous_request=request,
        current_request=request,
        previous_decision=decision,
        previous_budget_state=make_budget_state(decision),
        snapshot=snapshot,
        trigger=FallbackTrigger.VERIFICATION_ESCALATION,
        unavailable_substrates=(),
        fallback_policy=make_fallback_policy(
            allowed_triggers=(FallbackTrigger.VERIFICATION_ESCALATION,),
            allow_previous_substrate_reuse=True,
        ),
    )
    assert allowed.status is FallbackReplanStatus.ROUTE_SELECTED
    assert allowed.replacement_decision is not None
    assert (
        RoutingDecisionReasonCode.VERIFICATION_ESCALATION
        in allowed.replacement_decision.reason_codes
    )


def test_uncertainty_escalation_reason_is_explicit() -> None:
    result = run_replan(
        trigger=FallbackTrigger.UNCERTAINTY_ESCALATION,
        unavailable_substrates=(),
    )
    assert result.replacement_decision is not None
    assert (
        RoutingDecisionReasonCode.UNCERTAINTY_ESCALATION
        in result.replacement_decision.reason_codes
    )


def test_degraded_fallback_requires_both_candidate_and_fallback_permission() -> None:
    degraded = make_fallback_descriptor(
        availability_state=SubstrateAvailabilityState.DEGRADED,
    )
    snapshot = make_snapshot(make_primary_descriptor(), degraded)

    blocked = run_replan(snapshot=snapshot)
    assert blocked.status is FallbackReplanStatus.NO_VALID_ROUTE

    allowed = run_replan(
        snapshot=snapshot,
        fallback_policy=make_fallback_policy(allow_degraded=True),
    )
    assert allowed.status is FallbackReplanStatus.ROUTE_SELECTED
