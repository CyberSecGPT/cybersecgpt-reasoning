"""Tests for P5 structured routing decisions and freshness validation."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from typing import cast

import pytest

from cybersecgpt.foundation import (
    AuthorizationContextId,
    CapabilitySnapshotId,
    RequestId,
    RoutingDecisionId,
    RoutingSecurityBinding,
    SecurityPolicyRevisionId,
    SubstrateId,
)
from cybersecgpt.reasoning import (
    RoutingDecision,
    RoutingDecisionError,
    RoutingDecisionInvalidReason,
    RoutingDecisionReasonCode,
    RoutingDecisionValidation,
    RoutingDecisionValidationError,
    validate_routing_decision,
)

CREATED_AT = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
EXPIRES_AT = CREATED_AT + timedelta(minutes=5)


def make_binding(**overrides: object) -> RoutingSecurityBinding:
    values: dict[str, object] = {
        "request_id": RequestId("request-1"),
        "authorization_context_id": AuthorizationContextId("authorization-1"),
        "security_policy_revision_id": SecurityPolicyRevisionId("policy-7"),
        "effective_data_classification": "restricted",
        "provider_network_policy": "native-only",
        "offline_required": True,
        "capability_snapshot_id": CapabilitySnapshotId("capabilities-4"),
    }
    values.update(overrides)
    return RoutingSecurityBinding(**values)  # type: ignore[arg-type]


def make_decision(**overrides: object) -> RoutingDecision:
    values: dict[str, object] = {
        "decision_id": RoutingDecisionId("route-1"),
        "security_binding": make_binding(),
        "router_policy_id": "native-core-router",
        "router_policy_version": "p5-v1",
        "selected_substrates": (SubstrateId("native-general"),),
        "reason_codes": (RoutingDecisionReasonCode.CAPABILITY_MATCH,),
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
    }
    values.update(overrides)
    return RoutingDecision(**values)  # type: ignore[arg-type]


def test_valid_routing_decision_and_validation() -> None:
    decision = make_decision()
    result = validate_routing_decision(
        decision,
        current_binding=decision.security_binding,
        now=CREATED_AT + timedelta(seconds=1),
    )

    assert result.decision_id == decision.decision_id
    assert result.validated_at == CREATED_AT + timedelta(seconds=1)
    assert result.valid is True
    assert result.invalid_reasons == ()


def test_routing_decision_is_immutable() -> None:
    decision = make_decision()

    with pytest.raises(FrozenInstanceError):
        decision.router_policy_id = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    [
        ("decision_id", "route-1", "decision_id"),
        ("security_binding", "binding", "security_binding"),
        ("router_policy_id", "", "router_policy_id"),
        ("router_policy_id", " router", "router_policy_id"),
        ("router_policy_version", "", "router_policy_version"),
        ("selected_substrates", [SubstrateId("one")], "selected_substrates"),
        ("selected_substrates", (), "selected_substrates"),
        ("selected_substrates", (RequestId("wrong"),), "selected_substrates"),
        (
            "selected_substrates",
            (SubstrateId("one"), SubstrateId("one")),
            "duplicates",
        ),
        ("reason_codes", [RoutingDecisionReasonCode.CAPABILITY_MATCH], "reason_codes"),
        ("reason_codes", (), "reason_codes"),
        ("reason_codes", ("CAPABILITY_MATCH",), "reason_codes"),
        (
            "reason_codes",
            (
                RoutingDecisionReasonCode.CAPABILITY_MATCH,
                RoutingDecisionReasonCode.CAPABILITY_MATCH,
            ),
            "duplicates",
        ),
        ("created_at", "now", "created_at"),
        ("created_at", datetime(2026, 9, 5, 12, 0), "created_at"),
        (
            "created_at",
            datetime(2026, 9, 5, 12, 0, tzinfo=timezone(timedelta(hours=1))),
            "created_at",
        ),
        ("expires_at", datetime(2026, 9, 5, 12, 5), "expires_at"),
        ("expires_at", CREATED_AT, "later than"),
        ("expires_at", CREATED_AT - timedelta(seconds=1), "later than"),
    ],
)
def test_routing_decision_rejects_invalid_fields(
    field_name: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises(RoutingDecisionError, match=message):
        make_decision(**{field_name: value})


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"request_id": RequestId("request-2")}, RoutingDecisionInvalidReason.REQUEST_MISMATCH),
        (
            {"authorization_context_id": AuthorizationContextId("authorization-2")},
            RoutingDecisionInvalidReason.AUTHORIZATION_CONTEXT_MISMATCH,
        ),
        (
            {"security_policy_revision_id": SecurityPolicyRevisionId("policy-8")},
            RoutingDecisionInvalidReason.SECURITY_POLICY_REVISION_MISMATCH,
        ),
        (
            {"effective_data_classification": "secret"},
            RoutingDecisionInvalidReason.EFFECTIVE_DATA_CLASSIFICATION_MISMATCH,
        ),
        (
            {"provider_network_policy": "local-network"},
            RoutingDecisionInvalidReason.PROVIDER_NETWORK_POLICY_MISMATCH,
        ),
        (
            {"offline_required": False},
            RoutingDecisionInvalidReason.OFFLINE_REQUIREMENT_MISMATCH,
        ),
        (
            {"capability_snapshot_id": CapabilitySnapshotId("capabilities-5")},
            RoutingDecisionInvalidReason.CAPABILITY_SNAPSHOT_MISMATCH,
        ),
    ],
)
def test_validation_rejects_each_binding_mismatch(
    override: dict[str, object],
    expected: RoutingDecisionInvalidReason,
) -> None:
    decision = make_decision()
    current = make_binding(**override)

    result = validate_routing_decision(
        decision,
        current_binding=current,
        now=CREATED_AT + timedelta(seconds=1),
    )

    assert result.valid is False
    assert result.invalid_reasons == (expected,)


def test_validation_reports_multiple_mismatches_in_stable_order() -> None:
    decision = make_decision()
    current = make_binding(
        request_id=RequestId("request-2"),
        provider_network_policy="local-network",
        capability_snapshot_id=CapabilitySnapshotId("capabilities-5"),
    )

    result = validate_routing_decision(
        decision,
        current_binding=current,
        now=EXPIRES_AT,
    )

    assert result.invalid_reasons == (
        RoutingDecisionInvalidReason.EXPIRED,
        RoutingDecisionInvalidReason.REQUEST_MISMATCH,
        RoutingDecisionInvalidReason.PROVIDER_NETWORK_POLICY_MISMATCH,
        RoutingDecisionInvalidReason.CAPABILITY_SNAPSHOT_MISMATCH,
    )


@pytest.mark.parametrize("now", [EXPIRES_AT, EXPIRES_AT + timedelta(seconds=1)])
def test_validation_rejects_expired_decision(now: datetime) -> None:
    decision = make_decision()

    result = validate_routing_decision(
        decision,
        current_binding=decision.security_binding,
        now=now,
    )

    assert result.invalid_reasons == (RoutingDecisionInvalidReason.EXPIRED,)


def test_validation_rejects_not_yet_valid_decision() -> None:
    decision = make_decision()

    result = validate_routing_decision(
        decision,
        current_binding=decision.security_binding,
        now=CREATED_AT - timedelta(microseconds=1),
    )

    assert result.invalid_reasons == (RoutingDecisionInvalidReason.NOT_YET_VALID,)


@pytest.mark.parametrize(
    ("decision", "binding", "now", "message"),
    [
        ("decision", make_binding(), CREATED_AT, "decision"),
        (make_decision(), "binding", CREATED_AT, "current_binding"),
        (make_decision(), make_binding(), "now", "now"),
        (make_decision(), make_binding(), datetime(2026, 9, 5, 12, 0), "now"),
        (
            make_decision(),
            make_binding(),
            datetime(2026, 9, 5, 12, 0, tzinfo=timezone(timedelta(hours=1))),
            "now",
        ),
    ],
)
def test_validator_rejects_invalid_inputs(
    decision: object,
    binding: object,
    now: object,
    message: str,
) -> None:
    with pytest.raises(RoutingDecisionValidationError, match=message):
        validate_routing_decision(
            cast(RoutingDecision, decision),
            current_binding=cast(RoutingSecurityBinding, binding),
            now=cast(datetime, now),
        )


def test_validation_result_is_immutable() -> None:
    result = RoutingDecisionValidation(
        decision_id=RoutingDecisionId("route-1"),
        validated_at=CREATED_AT,
        valid=True,
        invalid_reasons=(),
    )

    with pytest.raises(FrozenInstanceError):
        result.valid = False  # type: ignore[misc]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"decision_id": "route-1"}, "decision_id"),
        ({"validated_at": "now"}, "validated_at"),
        ({"validated_at": datetime(2026, 9, 5, 12, 0)}, "validated_at"),
        ({"valid": 1}, "valid"),
        ({"invalid_reasons": []}, "invalid_reasons"),
        ({"invalid_reasons": ("EXPIRED",), "valid": False}, "invalid_reasons"),
        (
            {
                "invalid_reasons": (
                    RoutingDecisionInvalidReason.EXPIRED,
                    RoutingDecisionInvalidReason.EXPIRED,
                ),
                "valid": False,
            },
            "duplicates",
        ),
        (
            {
                "invalid_reasons": (RoutingDecisionInvalidReason.EXPIRED,),
                "valid": True,
            },
            "exactly when",
        ),
        ({"invalid_reasons": (), "valid": False}, "exactly when"),
    ],
)
def test_validation_result_rejects_invalid_fields(
    overrides: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "decision_id": RoutingDecisionId("route-1"),
        "validated_at": CREATED_AT,
        "valid": True,
        "invalid_reasons": (),
    }
    values.update(overrides)

    with pytest.raises(RoutingDecisionValidationError, match=message):
        RoutingDecisionValidation(**values)  # type: ignore[arg-type]
