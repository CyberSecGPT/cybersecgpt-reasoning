"""Validation coverage for deterministic P5 verifier orchestration."""

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cybersecgpt.foundation import (
    CorrelationId,
    RequestId,
    RoutingDecisionId,
    SubstrateId,
)

from cybersecgpt.reasoning import (
    ReasoningState,
    VerificationAssertionResult,
    VerificationAssertionStatus,
    VerificationIndependenceRequirement,
    VerificationOrchestrationError,
    VerificationOrchestrationState,
    VerificationResult,
    VerificationStatus,
)
from cybersecgpt.reasoning import verification as verification_module
from tests.test_verification import (
    VERIFIER_A,
    finish,
    make_evidence,
    make_state,
    make_verification_policy,
    observation,
    record,
)


def _corrupt(value, **updates):
    corrupted = copy.copy(value)
    for field_name, field_value in updates.items():
        object.__setattr__(corrupted, field_name, field_value)
    return corrupted


def _valid_result() -> VerificationResult:
    return finish(record(make_state(), observation()))


def _valid_assertion() -> VerificationAssertionResult:
    return _valid_result().assertion_results[0]


def test_scalar_validators_cover_all_fail_closed_branches() -> None:
    with pytest.raises(VerificationOrchestrationError, match="must be a string"):
        verification_module._require_text(1, field_name="value")
    for value in ("", " spaced "):
        with pytest.raises(VerificationOrchestrationError, match="non-empty"):
            verification_module._require_text(value, field_name="value")
    with pytest.raises(VerificationOrchestrationError, match="at most"):
        verification_module._require_text("x" * 513, field_name="value")
    with pytest.raises(VerificationOrchestrationError, match="machine-evaluable"):
        verification_module._require_token("bad token", field_name="token")

    with pytest.raises(VerificationOrchestrationError, match="must be a tuple"):
        verification_module._require_tokens([], field_name="tokens", allow_empty=True)
    with pytest.raises(VerificationOrchestrationError, match="must not be empty"):
        verification_module._require_tokens((), field_name="tokens", allow_empty=False)
    with pytest.raises(VerificationOrchestrationError, match="duplicates"):
        verification_module._require_tokens(
            ("same", "same"), field_name="tokens", allow_empty=True
        )
    assert (
        verification_module._require_tokens((), field_name="tokens", allow_empty=True)
        == ()
    )

    with pytest.raises(VerificationOrchestrationError, match="must be a tuple"):
        verification_module._require_references([], field_name="refs", allow_empty=True)
    with pytest.raises(VerificationOrchestrationError, match="must not be empty"):
        verification_module._require_references(
            (), field_name="refs", allow_empty=False
        )
    with pytest.raises(VerificationOrchestrationError, match="duplicates"):
        verification_module._require_references(
            ("same", "same"), field_name="refs", allow_empty=True
        )
    assert (
        verification_module._require_references((), field_name="refs", allow_empty=True)
        == ()
    )

    for value in ("1", True, 0, -1):
        with pytest.raises(VerificationOrchestrationError, match="positive integer"):
            verification_module._require_positive_int(value, field_name="count")
    assert verification_module._require_positive_int(1, field_name="count") == 1

    with pytest.raises(VerificationOrchestrationError, match="must be a datetime"):
        verification_module._require_utc_datetime("now", field_name="at")
    with pytest.raises(VerificationOrchestrationError, match="timezone-aware UTC"):
        verification_module._require_utc_datetime(datetime(2026, 9, 8), field_name="at")
    non_utc = datetime(
        2026,
        9,
        8,
        tzinfo=timezone(timedelta(hours=1)),
    )
    with pytest.raises(VerificationOrchestrationError, match="timezone-aware UTC"):
        verification_module._require_utc_datetime(non_utc, field_name="at")


def test_verification_policy_rejects_invalid_control_fields() -> None:
    policy = make_verification_policy()
    assert policy.independence_requirement is VerificationIndependenceRequirement.NONE
    with pytest.raises(
        VerificationOrchestrationError,
        match="independence_requirement",
    ):
        replace(policy, independence_requirement="bad")
    with pytest.raises(
        VerificationOrchestrationError,
        match="human_review_required",
    ):
        replace(policy, human_review_required="yes")
    with pytest.raises(VerificationOrchestrationError, match="timezone-aware UTC"):
        replace(policy, deadline=datetime(2026, 9, 8))
    with pytest.raises(VerificationOrchestrationError, match="positive integer"):
        replace(policy, minimum_supporting_verifiers=0)
    with pytest.raises(VerificationOrchestrationError, match="positive integer"):
        replace(policy, max_verifier_passes=True)


def test_verifier_observation_rejects_invalid_fields() -> None:
    valid = observation()
    with pytest.raises(VerificationOrchestrationError, match="verifier_id"):
        replace(valid, verifier_id="bad")
    with pytest.raises(VerificationOrchestrationError, match="status"):
        replace(valid, status="bad")
    with pytest.raises(
        VerificationOrchestrationError,
        match="contradiction references",
    ):
        replace(
            valid,
            status=VerificationAssertionStatus.CONTRADICTORY,
            contradictions=(),
        )


def test_assertion_result_rejects_invalid_supporting_verifier_state() -> None:
    valid = _valid_assertion()
    with pytest.raises(VerificationOrchestrationError, match="status"):
        replace(valid, status="bad")
    with pytest.raises(VerificationOrchestrationError, match="must be a tuple"):
        replace(valid, supporting_verifiers=[])
    with pytest.raises(VerificationOrchestrationError, match="SubstrateId"):
        replace(valid, supporting_verifiers=("bad",))
    with pytest.raises(VerificationOrchestrationError, match="duplicates"):
        replace(valid, supporting_verifiers=(VERIFIER_A, VERIFIER_A))


def test_orchestration_state_rejects_invalid_field_types_and_duplicates() -> None:
    state = make_state()[3]
    evidence = make_evidence()[0]
    observed = observation()
    cases = (
        ({"request_id": "bad"}, "request_id"),
        ({"routing_decision_id": "bad"}, "routing_decision_id"),
        ({"correlation_id": "bad"}, "correlation_id"),
        ({"subject_producer_substrate_id": "bad"}, "subject_producer"),
        ({"policy": "bad"}, "policy"),
        ({"selected_verifiers": []}, "selected_verifiers"),
        ({"selected_verifiers": ("bad",)}, "SubstrateId"),
        ({"selected_verifiers": (VERIFIER_A, VERIFIER_A)}, "duplicates"),
        ({"evidence_catalog": []}, "evidence_catalog"),
        ({"evidence_catalog": ("bad",)}, "VerificationEvidenceReference"),
        ({"evidence_catalog": (evidence, evidence)}, "duplicate evidence"),
        ({"observations": []}, "observations"),
        ({"observations": ("bad",)}, "VerifierObservation"),
        ({"observations": (observed, observed)}, "duplicate verifier/assertion"),
        ({"lifecycle": "bad"}, "lifecycle"),
    )
    for updates, message in cases:
        with pytest.raises(VerificationOrchestrationError, match=message):
            replace(state, **updates)


def test_orchestration_state_rejects_lifecycle_binding_mismatches() -> None:
    state = make_state()[3]
    wrong_route = _corrupt(
        state.lifecycle,
        routing_decision_id=RoutingDecisionId("route:other"),
    )
    with pytest.raises(VerificationOrchestrationError, match="routing decision"):
        replace(state, lifecycle=wrong_route)

    wrong_correlation = _corrupt(
        state.lifecycle,
        correlation_id=CorrelationId("correlation:other"),
    )
    with pytest.raises(VerificationOrchestrationError, match="correlation"):
        replace(state, lifecycle=wrong_correlation)

    planning = _corrupt(state.lifecycle, state=ReasoningState.PLANNING)
    with pytest.raises(VerificationOrchestrationError, match="VERIFYING"):
        replace(state, lifecycle=planning)


def test_verification_result_rejects_invalid_field_types_and_duplicates() -> None:
    result = _valid_result()
    cases = (
        ({"request_id": "bad"}, "request_id"),
        ({"routing_decision_id": "bad"}, "routing_decision_id"),
        ({"correlation_id": "bad"}, "correlation_id"),
        ({"status": "bad"}, "status"),
        ({"assertion_results": []}, "assertion_results"),
        ({"assertion_results": ("bad",)}, "VerificationAssertionResult"),
        ({"verifier_identities": []}, "verifier_identities"),
        ({"verifier_identities": ("bad",)}, "SubstrateId"),
        ({"verifier_identities": (VERIFIER_A, VERIFIER_A)}, "duplicates"),
        ({"budget_state": "bad"}, "budget_state"),
        ({"provenance": ()}, "must not be empty"),
    )
    for updates, message in cases:
        with pytest.raises(VerificationOrchestrationError, match=message):
            replace(result, **updates)


def test_verification_result_rejects_cross_bound_budget_and_false_support() -> None:
    result = _valid_result()
    assertion = result.assertion_results[0]
    wrong_budget = _corrupt(
        result.budget_state,
        decision_id=RoutingDecisionId("route:other"),
    )
    with pytest.raises(VerificationOrchestrationError, match="bind"):
        replace(result, budget_state=wrong_budget)
    with pytest.raises(VerificationOrchestrationError, match="earlier"):
        replace(result, finished_at=result.started_at - timedelta(seconds=1))
    with pytest.raises(VerificationOrchestrationError, match="every assertion"):
        replace(result, assertion_results=())

    unsupported = replace(
        assertion,
        status=VerificationAssertionStatus.UNSUPPORTED,
    )
    with pytest.raises(VerificationOrchestrationError, match="every assertion"):
        replace(result, assertion_results=(unsupported,))


def test_resource_limit_status_is_valid_explicit_result_metadata() -> None:
    result = _valid_result()
    limited = replace(result, status=VerificationStatus.RESOURCE_LIMIT)
    assert limited.status is VerificationStatus.RESOURCE_LIMIT


def test_orchestration_state_type_is_public_and_frozen() -> None:
    state = make_state()[3]
    assert isinstance(state, VerificationOrchestrationState)
    assert isinstance(state.request_id, RequestId)
    assert isinstance(state.selected_verifiers[0], SubstrateId)
