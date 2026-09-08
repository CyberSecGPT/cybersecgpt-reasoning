"""Coverage-focused negative tests for P5 termination control."""

from datetime import datetime
from typing import cast

import pytest
from cybersecgpt.foundation import SubstrateId

from cybersecgpt.reasoning import (
    TerminationPropagationError,
    TerminationPropagationStatus,
    TerminationReason,
    TerminationRequirement,
    TerminationTarget,
    TerminationTargetKind,
    begin_termination_propagation,
    evaluate_termination_propagation,
)
from tests.test_termination import (
    CORRELATION_ID,
    DECISION_ID,
    NOW,
    REQUEST_ID,
    make_decision,
    make_lifecycle,
    make_propagation,
    make_request,
    make_requirement,
)


def test_target_rejects_non_string_machine_token() -> None:
    with pytest.raises(TerminationPropagationError, match="target_ref must be a string"):
        TerminationTarget(
            target_ref=cast(str, 1),
            substrate_id=SubstrateId("model:native-general"),
            target_kind=TerminationTargetKind.MODEL,
            side_effect_capable=False,
            cleanup_required=False,
        )


def test_requirement_rejects_naive_datetime() -> None:
    with pytest.raises(TerminationPropagationError, match="timezone-aware UTC"):
        TerminationRequirement(
            request_id=REQUEST_ID,
            routing_decision_id=DECISION_ID,
            correlation_id=CORRELATION_ID,
            evaluated_at=datetime(2026, 9, 7, 12, 0),
            required=False,
            reason=None,
            triggered_at=None,
        )


def test_begin_propagation_defensively_rejects_missing_trigger_time() -> None:
    decision = make_decision()
    request = make_request(decision)
    lifecycle = make_lifecycle(decision)
    valid = make_requirement(decision, request, lifecycle)

    forged = object.__new__(TerminationRequirement)
    object.__setattr__(forged, "request_id", valid.request_id)
    object.__setattr__(forged, "routing_decision_id", valid.routing_decision_id)
    object.__setattr__(forged, "correlation_id", valid.correlation_id)
    object.__setattr__(forged, "evaluated_at", valid.evaluated_at)
    object.__setattr__(forged, "required", True)
    object.__setattr__(forged, "reason", TerminationReason.CANCELLATION)
    object.__setattr__(forged, "triggered_at", None)

    with pytest.raises(TerminationPropagationError, match="must have triggered_at"):
        begin_termination_propagation(
            request,
            decision,
            lifecycle,
            forged,
            targets=(),
            propagation_deadline=NOW.replace(microsecond=1),
        )


def test_unacknowledged_active_target_is_pending_before_deadline() -> None:
    propagation = make_propagation()
    evaluation = evaluate_termination_propagation(
        propagation,
        observed_at=NOW,
    )

    assert evaluation.status is TerminationPropagationStatus.PENDING
    assert evaluation.deadline_exceeded is False
    assert evaluation.pending_target_refs == ("model.active-1",)
