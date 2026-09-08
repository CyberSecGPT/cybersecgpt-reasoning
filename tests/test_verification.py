"""Tests for deterministic P5 verifier orchestration."""

from dataclasses import FrozenInstanceError
from datetime import timedelta

import pytest
from cybersecgpt.foundation import SubstrateId

from cybersecgpt.reasoning import (
    CandidateSelectionPolicy,
    ReasoningBudget,
    ReasoningState,
    SubstrateKind,
    TerminationReason,
    TerminationRequirement,
    VerificationAssertionStatus,
    VerificationEvidenceReference,
    VerificationIndependenceRequirement,
    VerificationOrchestrationError,
    VerificationPolicy,
    VerificationStatus,
    VerifierObservation,
    begin_reasoning_lifecycle,
    begin_verification_orchestration,
    finalize_verification,
    record_verifier_observation,
    transition_reasoning_state,
)
from tests.test_candidates import (
    NOW,
    make_descriptor,
    make_policy,
    make_request,
    make_resource,
    make_snapshot,
)
from tests.test_fallback import make_decision

PRODUCER_ID = SubstrateId("model:producer")
VERIFIER_A = SubstrateId("verifier:a")
VERIFIER_B = SubstrateId("verifier:b")


def make_verifier(
    substrate_id: SubstrateId,
    *,
    owner: str,
    version: str = "1.0.0",
    determinism_profile: str = "strict",
):
    return make_descriptor(
        substrate_id=substrate_id,
        substrate_version=version,
        substrate_kind=SubstrateKind.VERIFIER,
        owner=owner,
        capabilities=("verify.assertion",),
        determinism_profile=determinism_profile,
        verification_profile=("evidence", "independent"),
        resource_profile=make_resource(min_compute_units=1, max_latency_ms=200),
    )


def make_verification_request(**overrides: object):
    values: dict[str, object] = {
        "verification_requirements": ("evidence", "independent"),
    }
    values.update(overrides)
    return make_request(**values)


def make_verification_policy(**overrides: object) -> VerificationPolicy:
    values: dict[str, object] = {
        "policy_id": "verification.default",
        "policy_version": "1.0.0",
        "required_assertions": ("claim.correct",),
        "required_evidence_classes": ("citation",),
        "required_verifier_classes": ("evidence",),
        "independence_requirement": VerificationIndependenceRequirement.NONE,
        "minimum_supporting_verifiers": 1,
        "max_verifier_passes": 3,
        "human_review_required": False,
        "deadline": NOW + timedelta(minutes=3),
    }
    values.update(overrides)
    return VerificationPolicy(**values)  # type: ignore[arg-type]


def make_verifier_policy(**overrides: object) -> CandidateSelectionPolicy:
    values: dict[str, object] = {
        "required_capabilities": ("verify.assertion",),
        "allowed_substrate_kinds": (SubstrateKind.VERIFIER,),
        "allowed_network_requirements": ("none",),
        "deterministic_profiles": ("strict", "seeded"),
        "allow_degraded": False,
        "max_selected_substrates": 2,
    }
    values.update(overrides)
    return make_policy(**values)


def make_evidence() -> tuple[VerificationEvidenceReference, ...]:
    return (
        VerificationEvidenceReference(
            evidence_ref="evidence:claim:1",
            evidence_class="citation",
            provenance_ref="source://fixture/1",
        ),
    )


def make_lifecycle(request, decision):
    lifecycle = begin_reasoning_lifecycle(
        decision,
        correlation_id=request.correlation_id,
    )
    lifecycle = transition_reasoning_state(
        decision,
        lifecycle,
        state=ReasoningState.PLANNING,
        cause="plan",
    )
    return transition_reasoning_state(
        decision,
        lifecycle,
        state=ReasoningState.VERIFYING,
        cause="verify",
    )


def make_termination(request, decision, at, *, reason=None) -> TerminationRequirement:
    required = reason is not None
    return TerminationRequirement(
        request_id=request.request_id,
        routing_decision_id=decision.decision_id,
        correlation_id=request.correlation_id,
        evaluated_at=at,
        required=required,
        reason=reason,
        triggered_at=at if required else None,
    )


def make_state(
    *,
    request=None,
    verification_policy: VerificationPolicy | None = None,
    selection_policy: CandidateSelectionPolicy | None = None,
    producer_owner: str = "CyberSecGPT/cybersecgpt-inference",
    verifier_a_owner: str = "CyberSecGPT/cybersecgpt-verifier-a",
    verifier_b_owner: str = "CyberSecGPT/cybersecgpt-verifier-b",
    verifier_a_profile: str = "strict",
):
    actual_request = request or make_verification_request()
    producer = make_descriptor(
        substrate_id=PRODUCER_ID,
        owner=producer_owner,
    )
    verifier_a = make_verifier(
        VERIFIER_A,
        owner=verifier_a_owner,
        determinism_profile=verifier_a_profile,
    )
    verifier_b = make_verifier(VERIFIER_B, owner=verifier_b_owner)
    snapshot = make_snapshot(producer, verifier_a, verifier_b)
    decision = make_decision(actual_request, selected_substrates=(PRODUCER_ID,))
    lifecycle = make_lifecycle(actual_request, decision)
    policy = verification_policy or make_verification_policy()
    state = begin_verification_orchestration(
        actual_request,
        decision,
        lifecycle,
        snapshot,
        selection_policy or make_verifier_policy(),
        policy,
        make_evidence(),
        make_termination(actual_request, decision, NOW),
        current_binding=actual_request.security_binding,
        subject_ref="result:1",
        subject_producer_substrate_id=PRODUCER_ID,
        started_at=NOW,
    )
    return actual_request, decision, snapshot, state


def observation(
    verifier_id: SubstrateId = VERIFIER_A,
    *,
    status: VerificationAssertionStatus = VerificationAssertionStatus.SUPPORTED,
    at=NOW + timedelta(seconds=1),
    evidence_refs: tuple[str, ...] = ("evidence:claim:1",),
    contradictions: tuple[str, ...] = (),
    limitations: tuple[str, ...] = (),
    method_version: str = "1.0.0",
) -> VerifierObservation:
    return VerifierObservation(
        verifier_id=verifier_id,
        method_version=method_version,
        assertion_id="claim.correct",
        status=status,
        evidence_refs=evidence_refs,
        contradictions=contradictions,
        limitations=limitations,
        observed_at=at,
    )


def record(state_tuple, item: VerifierObservation):
    request, decision, snapshot, state = state_tuple
    updated = record_verifier_observation(
        state,
        request,
        decision,
        snapshot,
        item,
        make_termination(request, decision, item.observed_at),
        current_binding=request.security_binding,
    )
    return request, decision, snapshot, updated


def finish(state_tuple, *, at=NOW + timedelta(seconds=2), reason=None):
    request, decision, snapshot, state = state_tuple
    return finalize_verification(
        state,
        request,
        decision,
        snapshot,
        make_termination(request, decision, at, reason=reason),
        current_binding=request.security_binding,
        finished_at=at,
    )


def test_supported_verification_is_explicit_and_consumes_verifier_budget() -> None:
    initial = make_state()
    assert initial[3].selected_verifiers == (VERIFIER_A, VERIFIER_B)

    recorded = record(initial, observation(limitations=("limitation:bounded",)))
    result = finish(recorded)

    assert result.status is VerificationStatus.SUPPORTED
    assert result.assertion_results[0].status is VerificationAssertionStatus.SUPPORTED
    assert result.verifier_identities == (VERIFIER_A,)
    assert result.evidence_refs == ("evidence:claim:1",)
    assert result.method_versions == ("verifier:a@1.0.0",)
    assert result.limitations == ("limitation:bounded",)
    assert result.budget_state.usage.verifier_passes == 1
    assert recorded[3].lifecycle.sequence == initial[3].lifecycle.sequence + 1
    assert recorded[3].lifecycle.state is ReasoningState.VERIFYING
    assert result.provenance[0] == "verification-policy:verification.default@1.0.0"

    with pytest.raises(FrozenInstanceError):
        result.status = VerificationStatus.UNSUPPORTED  # type: ignore[misc]


def test_contradiction_can_never_be_reported_as_supported() -> None:
    item = observation(
        status=VerificationAssertionStatus.CONTRADICTORY,
        contradictions=("contradiction:evidence:2",),
    )
    result = finish(record(make_state(), item))

    assert result.status is VerificationStatus.CONTRADICTORY
    assert (
        result.assertion_results[0].status is VerificationAssertionStatus.CONTRADICTORY
    )
    assert result.contradictions == ("contradiction:evidence:2",)


def test_unsupported_error_and_insufficient_evidence_remain_fail_closed() -> None:
    unsupported = finish(
        record(
            make_state(),
            observation(status=VerificationAssertionStatus.UNSUPPORTED),
        )
    )
    assert unsupported.status is VerificationStatus.UNSUPPORTED

    errored = finish(
        record(
            make_state(),
            observation(status=VerificationAssertionStatus.VERIFICATION_ERROR),
        )
    )
    assert errored.status is VerificationStatus.VERIFICATION_ERROR

    insufficient = finish(make_state())
    assert insufficient.status is VerificationStatus.INSUFFICIENT_EVIDENCE
    assert (
        insufficient.assertion_results[0].status
        is VerificationAssertionStatus.INSUFFICIENT_EVIDENCE
    )


def test_human_review_requirement_blocks_automatic_supported_status() -> None:
    policy = make_verification_policy(human_review_required=True)
    result = finish(record(make_state(verification_policy=policy), observation()))
    assert result.status is VerificationStatus.POLICY_BLOCKED


def test_distinct_owner_and_deterministic_independence_are_enforced() -> None:
    policy = make_verification_policy(
        independence_requirement=(
            VerificationIndependenceRequirement.DETERMINISTIC_AND_DISTINCT_OWNER
        ),
        minimum_supporting_verifiers=2,
    )
    state_tuple = make_state(verification_policy=policy)
    state_tuple = record(state_tuple, observation(VERIFIER_A))
    state_tuple = record(
        state_tuple,
        observation(VERIFIER_B, at=NOW + timedelta(seconds=2)),
    )
    result = finish(state_tuple, at=NOW + timedelta(seconds=3))
    assert result.status is VerificationStatus.SUPPORTED

    same_owner = make_state(
        verification_policy=policy,
        verifier_a_owner="same-owner",
        verifier_b_owner="same-owner",
    )
    same_owner = record(same_owner, observation(VERIFIER_A))
    same_owner = record(
        same_owner,
        observation(VERIFIER_B, at=NOW + timedelta(seconds=2)),
    )
    assert finish(same_owner, at=NOW + timedelta(seconds=3)).status is (
        VerificationStatus.INSUFFICIENT_EVIDENCE
    )


def test_subject_producer_is_never_selected_as_its_own_verifier() -> None:
    request = make_verification_request()
    producer_verifier = make_verifier(
        PRODUCER_ID,
        owner="CyberSecGPT/same",
    )
    other = make_verifier(VERIFIER_A, owner="CyberSecGPT/other")
    snapshot = make_snapshot(producer_verifier, other)
    decision = make_decision(request, selected_substrates=(PRODUCER_ID,))
    state = begin_verification_orchestration(
        request,
        decision,
        make_lifecycle(request, decision),
        snapshot,
        make_verifier_policy(),
        make_verification_policy(),
        make_evidence(),
        make_termination(request, decision, NOW),
        current_binding=request.security_binding,
        subject_ref="result:self-check",
        subject_producer_substrate_id=PRODUCER_ID,
        started_at=NOW,
    )
    assert state.selected_verifiers == (VERIFIER_A,)


def test_observation_rejects_unknown_evidence_method_and_duplicate_pair() -> None:
    state_tuple = make_state()
    with pytest.raises(VerificationOrchestrationError, match="outside"):
        record(state_tuple, observation(evidence_refs=("evidence:unknown",)))
    with pytest.raises(VerificationOrchestrationError, match="method_version"):
        record(state_tuple, observation(method_version="2.0.0"))

    state_tuple = record(state_tuple, observation())
    with pytest.raises(VerificationOrchestrationError, match="duplicate"):
        record(
            state_tuple,
            observation(at=NOW + timedelta(seconds=2)),
        )


def test_policy_pass_ceiling_and_reasoning_budget_are_not_reset() -> None:
    policy = make_verification_policy(max_verifier_passes=1)
    state_tuple = record(make_state(verification_policy=policy), observation())
    with pytest.raises(VerificationOrchestrationError, match="ceiling"):
        record(
            state_tuple,
            observation(VERIFIER_B, at=NOW + timedelta(seconds=2)),
        )

    small_budget = ReasoningBudget(
        policy_name="NORMAL",
        max_candidates=8,
        max_branch_depth=4,
        max_steps=16,
        max_model_tokens=4096,
        max_tool_calls=2,
        max_retrieval_calls=4,
        max_verifier_passes=1,
    )
    request = make_verification_request(reasoning_budget=small_budget)
    with pytest.raises(VerificationOrchestrationError, match="cannot exceed"):
        make_state(
            request=request,
            verification_policy=make_verification_policy(max_verifier_passes=2),
        )


def test_termination_and_deadline_never_become_supported() -> None:
    recorded = record(make_state(), observation())
    cancelled = finish(
        recorded,
        reason=TerminationReason.CANCELLATION,
    )
    assert cancelled.status is VerificationStatus.CANCELLED

    deadline = finish(
        recorded,
        reason=TerminationReason.DEADLINE,
    )
    assert deadline.status is VerificationStatus.DEADLINE

    policy = make_verification_policy(deadline=NOW + timedelta(seconds=2))
    state_tuple = record(make_state(verification_policy=policy), observation())
    assert finish(state_tuple, at=NOW + timedelta(seconds=2)).status is (
        VerificationStatus.DEADLINE
    )


def test_begin_fails_closed_for_non_verifier_policy_and_active_termination() -> None:
    request = make_verification_request()
    producer = make_descriptor(substrate_id=PRODUCER_ID)
    verifier = make_verifier(VERIFIER_A, owner="CyberSecGPT/verifier")
    snapshot = make_snapshot(producer, verifier)
    decision = make_decision(request, selected_substrates=(PRODUCER_ID,))
    lifecycle = make_lifecycle(request, decision)

    with pytest.raises(VerificationOrchestrationError, match="only VERIFIER"):
        begin_verification_orchestration(
            request,
            decision,
            lifecycle,
            snapshot,
            make_policy(),
            make_verification_policy(),
            make_evidence(),
            make_termination(request, decision, NOW),
            current_binding=request.security_binding,
            subject_ref="result:1",
            subject_producer_substrate_id=PRODUCER_ID,
            started_at=NOW,
        )

    with pytest.raises(VerificationOrchestrationError, match="cannot begin"):
        begin_verification_orchestration(
            request,
            decision,
            lifecycle,
            snapshot,
            make_verifier_policy(),
            make_verification_policy(),
            make_evidence(),
            make_termination(
                request,
                decision,
                NOW,
                reason=TerminationReason.CANCELLATION,
            ),
            current_binding=request.security_binding,
            subject_ref="result:1",
            subject_producer_substrate_id=PRODUCER_ID,
            started_at=NOW,
        )
