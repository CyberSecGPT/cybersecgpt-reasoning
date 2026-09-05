"""Tests for normalized P5 Native Brain request admission."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from typing import cast

import pytest
from cybersecgpt.foundation import (
    AuthorizationContextId,
    CapabilitySnapshotId,
    CorrelationId,
    RequestId,
    RoutingSecurityBinding,
    SecurityPolicyRevisionId,
)

from cybersecgpt.reasoning import (
    BrainRequest,
    BrainRequestError,
    ReasoningBudget,
    admit_brain_request,
)

ADMITTED_AT = datetime(2026, 9, 5, 14, 0, tzinfo=UTC)
DEADLINE = ADMITTED_AT + timedelta(seconds=30)
REQUEST_ID = RequestId("request-1")
CORRELATION_ID = CorrelationId("correlation-1")


def make_budget() -> ReasoningBudget:
    return ReasoningBudget(
        policy_name="NORMAL",
        max_candidates=4,
        max_branch_depth=3,
        max_steps=8,
        max_model_tokens=1024,
        max_tool_calls=2,
        max_retrieval_calls=3,
        max_verifier_passes=2,
        stop_conditions=("deadline", "cancelled"),
    )


def make_binding(*, request_id: RequestId = REQUEST_ID) -> RoutingSecurityBinding:
    return RoutingSecurityBinding(
        request_id=request_id,
        authorization_context_id=AuthorizationContextId("authorization-1"),
        security_policy_revision_id=SecurityPolicyRevisionId("policy-7"),
        effective_data_classification="restricted",
        provider_network_policy="native-only",
        offline_required=True,
        capability_snapshot_id=CapabilitySnapshotId("capabilities-4"),
    )


def make_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "request_id": REQUEST_ID,
        "correlation_id": CORRELATION_ID,
        "security_binding": make_binding(),
        "task_type": "security.analysis",
        "domain": "cyber",
        "task_complexity": "normal",
        "safety_impact": "moderate",
        "source_data_classification": "user-claimed-public",
        "identity_context_ref": None,
        "max_latency_ms": 5000,
        "max_compute_units": 20,
        "max_memory_bytes": 268435456,
        "reasoning_budget": make_budget(),
        "required_accuracy": 0.95,
        "required_determinism": True,
        "required_explainability": True,
        "verification_requirements": ("evidence", "independent-verifier"),
        "admitted_at": ADMITTED_AT,
        "deadline": DEADLINE,
        "input_json": '{"query": "inspect"}',
    }
    values.update(overrides)
    return values


def construct_request(**overrides: object) -> BrainRequest:
    return BrainRequest(**make_values(**overrides))  # type: ignore[arg-type]


def test_admission_normalizes_immutable_input_and_keeps_claim_separate() -> None:
    input_value = {"query": "inspect", "targets": ["fixture-a"]}
    request = admit_brain_request(
        request_id=REQUEST_ID,
        correlation_id=CORRELATION_ID,
        security_binding=make_binding(),
        task_type="security.analysis",
        domain="cyber",
        task_complexity="normal",
        safety_impact="moderate",
        source_data_classification="user-claimed-public",
        identity_context_ref="identity-ref-1",
        max_latency_ms=5000,
        max_compute_units=20,
        max_memory_bytes=268435456,
        reasoning_budget=make_budget(),
        required_accuracy=0.95,
        required_determinism=True,
        required_explainability=True,
        verification_requirements=("evidence", "independent-verifier"),
        admitted_at=ADMITTED_AT,
        deadline=DEADLINE,
        input_value=input_value,
    )

    assert request.request_id == REQUEST_ID
    assert request.correlation_id == CORRELATION_ID
    assert request.security_binding.effective_data_classification == "restricted"
    assert request.source_data_classification == "user-claimed-public"
    assert request.identity_context_ref == "identity-ref-1"
    assert request.input_json == '{"query": "inspect", "targets": ["fixture-a"]}'

    input_value["query"] = "mutated"
    assert request.input_json == '{"query": "inspect", "targets": ["fixture-a"]}'

    with pytest.raises(FrozenInstanceError):
        request.task_type = "changed"  # type: ignore[misc]


def test_request_allows_absent_optional_accuracy_and_classification_metadata() -> None:
    request = construct_request(
        source_data_classification=None,
        required_accuracy=None,
        deadline=None,
    )

    assert request.source_data_classification is None
    assert request.required_accuracy is None
    assert request.deadline is None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"request_id": "request-1"}, "request_id"),
        ({"correlation_id": "correlation-1"}, "correlation_id"),
        ({"security_binding": "binding"}, "security_binding"),
        (
            {"security_binding": make_binding(request_id=RequestId("request-2"))},
            "must match",
        ),
        ({"task_type": 7}, "task_type"),
        ({"domain": ""}, "domain"),
        ({"task_complexity": "not valid"}, "machine-evaluable token"),
        ({"source_data_classification": 7}, "source_data_classification"),
        ({"identity_context_ref": " identity"}, "identity_context_ref"),
        ({"max_latency_ms": True}, "max_latency_ms"),
        ({"max_compute_units": -1}, "max_compute_units"),
        ({"max_memory_bytes": "many"}, "max_memory_bytes"),
        ({"reasoning_budget": "budget"}, "reasoning_budget"),
        ({"required_accuracy": 1}, "required_accuracy"),
        ({"required_accuracy": 1.1}, "between 0.0 and 1.0"),
        ({"required_determinism": 1}, "required_determinism"),
        ({"required_explainability": "yes"}, "required_explainability"),
        ({"verification_requirements": ["evidence"]}, "must be a tuple"),
        (
            {"verification_requirements": ("evidence", "evidence")},
            "must not contain duplicates",
        ),
        ({"admitted_at": "now"}, "admitted_at"),
        (
            {"admitted_at": datetime(2026, 9, 5, 14, 0)},
            "timezone-aware UTC",
        ),
        (
            {
                "deadline": datetime(
                    2026,
                    9,
                    5,
                    16,
                    0,
                    tzinfo=timezone(timedelta(hours=2)),
                )
            },
            "timezone-aware UTC",
        ),
        ({"deadline": ADMITTED_AT}, "later than admitted_at"),
        ({"input_json": 7}, "input_json"),
        ({"input_json": "not-json"}, "valid JSON"),
        ({"input_json": '{"b":2,"a":1}'}, "canonical"),
    ],
)
def test_brain_request_rejects_invalid_admission_state(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(BrainRequestError, match=message):
        construct_request(**overrides)


def test_verification_requirement_items_must_be_machine_tokens() -> None:
    with pytest.raises(BrainRequestError, match="machine-evaluable token"):
        construct_request(verification_requirements=("needs review",))


def test_admit_brain_request_wraps_unserializable_input() -> None:
    with pytest.raises(BrainRequestError, match="JSON-compatible"):
        admit_brain_request(
            request_id=REQUEST_ID,
            correlation_id=CORRELATION_ID,
            security_binding=make_binding(),
            task_type="security.analysis",
            domain="cyber",
            task_complexity="normal",
            safety_impact="moderate",
            source_data_classification=None,
            identity_context_ref=None,
            max_latency_ms=5000,
            max_compute_units=20,
            max_memory_bytes=268435456,
            reasoning_budget=make_budget(),
            required_accuracy=None,
            required_determinism=True,
            required_explainability=True,
            verification_requirements=(),
            admitted_at=ADMITTED_AT,
            deadline=None,
            input_value=object(),
        )


def test_direct_request_rejects_non_string_safety_impact() -> None:
    with pytest.raises(BrainRequestError, match="safety_impact"):
        construct_request(safety_impact=cast(str, 7))
