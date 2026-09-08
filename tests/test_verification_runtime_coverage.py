"""Runtime boundary coverage for deterministic P5 verifier orchestration."""

import copy
from dataclasses import replace
from datetime import timedelta

import pytest
from cybersecgpt.foundation import (
    CapabilitySnapshotId,
    CorrelationId,
    RequestId,
    RoutingDecisionId,
    SubstrateId,
)

from cybersecgpt.reasoning import (
    ReasoningState,
    SubstrateKind,
    TerminationReason,
    VerificationAssertionStatus,
    VerificationIndependenceRequirement,
    VerificationOrchestrationError,
    VerificationOrchestrationState,
    VerificationStatus,
    begin_verification_orchestration,
    finalize_verification,
    record_verifier_observation,
)
from cybersecgpt.reasoning import verification as verification_module
from tests.test_candidates import NOW, make_descriptor, make_snapshot
from tests.test_fallback import make_decision
from tests.test_verification import (
    PRODUCER_ID,
    VERIFIER_A,
    VERIFIER_B,
    finish,
    make_evidence,
    make_lifecycle,
    make_state,
    make_termination,
    make_verification_policy,
    make_verification_request,
    make_verifier,
    make_verifier_policy,
    observation,
    record,
)


def _corrupt(value, **updates):
    corrupted = copy.copy(value)
    for field_name, field_value in updates.items():
        object.__setattr__(corrupted, field_name, field_value)
    return corrupted


def test_common_binding_validation_rejects_every_stale_binding() -> None:
    request, decision, snapshot, state = make_state()
    binding = request.security_binding
    observed_at = NOW + timedelta(seconds=1)

    other_binding = replace(binding, provider_network_policy="other")
    other_decision = replace(decision, security_binding=other_binding)
    with pytest.raises(VerificationOrchestrationError, match="admitted request"):
        verification_module._validate_common_bindings(
            request,
            other_decision,
            state.lifecycle,
            snapshot,
            binding,
            observed_at=observed_at,
        )
    with pytest.raises(VerificationOrchestrationError, match="current_binding"):
        verification_module._validate_common_bindings(
            request,
            decision,
            state.lifecycle,
            snapshot,
            other_binding,
            observed_at=observed_at,
        )

    wrong_route = _corrupt(
        state.lifecycle,
        routing_decision_id=RoutingDecisionId("route:other"),
    )
    with pytest.raises(VerificationOrchestrationError, match="lifecycle routing"):
        verification_module._validate_common_bindings(
            request,
            decision,
            wrong_route,
            snapshot,
            binding,
            observed_at=observed_at,
        )

    wrong_correlation = _corrupt(
        state.lifecycle,
        correlation_id=CorrelationId("correlation:other"),
    )
    with pytest.raises(VerificationOrchestrationError, match="lifecycle correlation"):
        verification_module._validate_common_bindings(
            request,
            decision,
            wrong_correlation,
            snapshot,
            binding,
            observed_at=observed_at,
        )

    planning = _corrupt(state.lifecycle, state=ReasoningState.PLANNING)
    with pytest.raises(VerificationOrchestrationError, match="VERIFYING"):
        verification_module._validate_common_bindings(
            request,
            decision,
            planning,
            snapshot,
            binding,
            observed_at=observed_at,
        )

    wrong_snapshot = _corrupt(
        snapshot,
        snapshot_id=CapabilitySnapshotId("snapshot:other"),
    )
    with pytest.raises(VerificationOrchestrationError, match="capability snapshot"):
        verification_module._validate_common_bindings(
            request,
            decision,
            state.lifecycle,
            wrong_snapshot,
            binding,
            observed_at=observed_at,
        )

    expired = replace(decision, expires_at=NOW + timedelta(milliseconds=1))
    with pytest.raises(VerificationOrchestrationError, match="current routing"):
        verification_module._validate_common_bindings(
            request,
            expired,
            state.lifecycle,
            snapshot,
            binding,
            observed_at=observed_at,
        )


def test_termination_validation_rejects_cross_bound_metadata() -> None:
    request, decision, _, _ = make_state()
    requirement = make_termination(request, decision, NOW)
    with pytest.raises(VerificationOrchestrationError, match="TerminationRequirement"):
        verification_module._validate_termination_requirement(
            "bad",
            request=request,
            decision=decision,
            observed_at=NOW,
        )

    cases = (
        (replace(requirement, request_id=RequestId("request:other")), "request_id"),
        (
            replace(
                requirement,
                routing_decision_id=RoutingDecisionId("route:other"),
            ),
            "routing decision",
        ),
        (
            replace(
                requirement,
                correlation_id=CorrelationId("correlation:other"),
            ),
            "correlation_id",
        ),
        (
            replace(requirement, evaluated_at=NOW + timedelta(seconds=1)),
            "observation time",
        ),
    )
    for value, message in cases:
        with pytest.raises(VerificationOrchestrationError, match=message):
            verification_module._validate_termination_requirement(
                value,
                request=request,
                decision=decision,
                observed_at=NOW,
            )


def test_effective_deadline_supports_no_deadline_state() -> None:
    request = make_verification_request(deadline=None)
    policy = make_verification_policy(deadline=None)
    assert verification_module._effective_deadline(request, policy) is None


def test_selection_rejects_unadmitted_verifier_class() -> None:
    policy = make_verification_policy(required_verifier_classes=("not-admitted",))
    with pytest.raises(VerificationOrchestrationError, match="admitted request"):
        make_state(verification_policy=policy)


def test_selection_filters_nondeterministic_and_same_owner_verifiers() -> None:
    deterministic = make_verification_policy(
        independence_requirement=VerificationIndependenceRequirement.DETERMINISTIC
    )
    deterministic_state = make_state(
        verification_policy=deterministic,
        verifier_a_profile="nondeterministic",
    )[3]
    assert deterministic_state.selected_verifiers == (VERIFIER_B,)

    distinct_owner = make_verification_policy(
        independence_requirement=VerificationIndependenceRequirement.DISTINCT_OWNER
    )
    distinct_state = make_state(
        verification_policy=distinct_owner,
        producer_owner="shared-owner",
        verifier_a_owner="shared-owner",
    )[3]
    assert distinct_state.selected_verifiers == (VERIFIER_B,)


def _begin_inputs():
    request = make_verification_request()
    producer = make_descriptor(substrate_id=PRODUCER_ID)
    verifier = make_verifier(VERIFIER_A, owner="CyberSecGPT/verifier")
    snapshot = make_snapshot(producer, verifier)
    decision = make_decision(request, selected_substrates=(PRODUCER_ID,))
    return {
        "request": request,
        "decision": decision,
        "lifecycle": make_lifecycle(request, decision),
        "snapshot": snapshot,
        "selection_policy": make_verifier_policy(max_selected_substrates=1),
        "verification_policy": make_verification_policy(),
        "evidence_catalog": make_evidence(),
        "termination_requirement": make_termination(request, decision, NOW),
        "current_binding": request.security_binding,
        "subject_ref": "result:coverage",
        "subject_producer_substrate_id": PRODUCER_ID,
        "started_at": NOW,
    }


def _call_begin(**updates):
    values = _begin_inputs()
    values.update(updates)
    return begin_verification_orchestration(**values)


def test_begin_validates_every_external_input_type() -> None:
    cases = (
        ("request", "bad", "BrainRequest"),
        ("decision", "bad", "RoutingDecision"),
        ("lifecycle", "bad", "ReasoningLifecycleSnapshot"),
        ("snapshot", "bad", "CapabilitySnapshot"),
        ("selection_policy", "bad", "CandidateSelectionPolicy"),
        ("verification_policy", "bad", "VerificationPolicy"),
        ("current_binding", "bad", "RoutingSecurityBinding"),
        ("subject_producer_substrate_id", "bad", "SubstrateId or None"),
    )
    for field_name, value, message in cases:
        with pytest.raises(VerificationOrchestrationError, match=message):
            _call_begin(**{field_name: value})


def test_begin_rejects_deadline_and_invalid_evidence_catalog() -> None:
    with pytest.raises(VerificationOrchestrationError, match="deadline"):
        _call_begin(
            verification_policy=make_verification_policy(deadline=NOW),
        )
    with pytest.raises(VerificationOrchestrationError, match="evidence_catalog"):
        _call_begin(evidence_catalog=[])
    with pytest.raises(VerificationOrchestrationError, match="VerificationEvidence"):
        _call_begin(evidence_catalog=("bad",))

    evidence = make_evidence()[0]
    with pytest.raises(VerificationOrchestrationError, match="duplicate evidence"):
        _call_begin(evidence_catalog=(evidence, evidence))


def test_begin_allows_absent_subject_producer_identity() -> None:
    state = _call_begin(subject_producer_substrate_id=None)
    assert state.subject_producer_substrate_id is None
    assert state.selected_verifiers == (VERIFIER_A,)


def test_record_rejects_invalid_state_and_observation_types() -> None:
    request, decision, snapshot, state = make_state()
    item = observation()
    termination = make_termination(request, decision, item.observed_at)

    with pytest.raises(VerificationOrchestrationError, match="OrchestrationState"):
        record_verifier_observation(
            "bad",
            request,
            decision,
            snapshot,
            item,
            termination,
            current_binding=request.security_binding,
        )
    with pytest.raises(VerificationOrchestrationError, match="VerifierObservation"):
        record_verifier_observation(
            state,
            request,
            decision,
            snapshot,
            "bad",
            make_termination(request, decision, NOW),
            current_binding=request.security_binding,
        )


def test_record_rejects_cross_bound_or_terminated_state() -> None:
    request, decision, snapshot, state = make_state()
    item = observation()
    termination = make_termination(request, decision, item.observed_at)
    cases = (
        ({"request_id": RequestId("request:other")}, "state request_id"),
        (
            {"routing_decision_id": RoutingDecisionId("route:other")},
            "state routing_decision_id",
        ),
        (
            {"correlation_id": CorrelationId("correlation:other")},
            "state correlation_id",
        ),
    )
    for updates, message in cases:
        corrupted = _corrupt(state, **updates)
        with pytest.raises(VerificationOrchestrationError, match=message):
            record_verifier_observation(
                corrupted,
                request,
                decision,
                snapshot,
                item,
                termination,
                current_binding=request.security_binding,
            )

    cancelled = make_termination(
        request,
        decision,
        item.observed_at,
        reason=TerminationReason.CANCELLATION,
    )
    with pytest.raises(VerificationOrchestrationError, match="after termination"):
        record_verifier_observation(
            state,
            request,
            decision,
            snapshot,
            item,
            cancelled,
            current_binding=request.security_binding,
        )


def test_record_rejects_time_selection_and_assertion_mismatches() -> None:
    request, decision, snapshot, state = make_state()
    early = observation(at=NOW - timedelta(seconds=1))
    with pytest.raises(VerificationOrchestrationError, match="predate"):
        record_verifier_observation(
            state,
            request,
            decision,
            snapshot,
            early,
            make_termination(request, decision, early.observed_at),
            current_binding=request.security_binding,
        )

    deadline_tuple = make_state(
        verification_policy=make_verification_policy(
            deadline=NOW + timedelta(seconds=1)
        )
    )
    deadline_item = observation(at=NOW + timedelta(seconds=1))
    deadline_termination = make_termination(
        deadline_tuple[0],
        deadline_tuple[1],
        deadline_item.observed_at,
    )
    with pytest.raises(VerificationOrchestrationError, match="after deadline"):
        record_verifier_observation(
            deadline_tuple[3],
            deadline_tuple[0],
            deadline_tuple[1],
            deadline_tuple[2],
            deadline_item,
            deadline_termination,
            current_binding=deadline_tuple[0].security_binding,
        )

    item = observation()
    unselected = replace(item, verifier_id=SubstrateId("verifier:unselected"))
    with pytest.raises(VerificationOrchestrationError, match="not selected"):
        record_verifier_observation(
            state,
            request,
            decision,
            snapshot,
            unselected,
            make_termination(request, decision, unselected.observed_at),
            current_binding=request.security_binding,
        )

    wrong_assertion = replace(item, assertion_id="claim.other")
    with pytest.raises(VerificationOrchestrationError, match="not required"):
        record_verifier_observation(
            state,
            request,
            decision,
            snapshot,
            wrong_assertion,
            make_termination(request, decision, wrong_assertion.observed_at),
            current_binding=request.security_binding,
        )


def test_record_rejects_removed_and_reclassified_verifier() -> None:
    request, decision, _, state = make_state()
    item = observation()
    termination = make_termination(request, decision, item.observed_at)

    without_a = make_snapshot(
        make_verifier(VERIFIER_B, owner="CyberSecGPT/verifier-b")
    )
    with pytest.raises(VerificationOrchestrationError, match="current validated"):
        record_verifier_observation(
            state,
            request,
            decision,
            without_a,
            item,
            termination,
            current_binding=request.security_binding,
        )

    reclassified = make_descriptor(
        substrate_id=VERIFIER_A,
        substrate_kind=SubstrateKind.NATIVE_MODEL,
        owner="CyberSecGPT/reclassified",
        capabilities=("verify.assertion",),
        verification_profile=("evidence", "independent"),
    )
    reclassified_snapshot = make_snapshot(reclassified)
    with pytest.raises(VerificationOrchestrationError, match="current validated"):
        record_verifier_observation(
            state,
            request,
            decision,
            reclassified_snapshot,
            item,
            termination,
            current_binding=request.security_binding,
        )


def test_aggregation_requires_required_evidence_class() -> None:
    result = finish(record(make_state(), observation(evidence_refs=())))
    assert result.status is VerificationStatus.INSUFFICIENT_EVIDENCE


def test_aggregation_skips_unadmitted_evidence_in_corrupted_internal_state() -> None:
    policy = make_verification_policy(
        independence_requirement=VerificationIndependenceRequirement.DISTINCT_OWNER
    )
    request, decision, snapshot, state = make_state(verification_policy=policy)
    unknown = observation(evidence_refs=("evidence:not-catalogued",))
    corrupted = _corrupt(state, observations=(unknown,))
    result = finalize_verification(
        corrupted,
        request,
        decision,
        snapshot,
        make_termination(request, decision, NOW + timedelta(seconds=2)),
        current_binding=request.security_binding,
        finished_at=NOW + timedelta(seconds=2),
    )
    assert result.status is VerificationStatus.INSUFFICIENT_EVIDENCE


def test_nondeterministic_support_fails_deterministic_final_check() -> None:
    request = make_verification_request()
    policy = make_verification_policy(
        independence_requirement=VerificationIndependenceRequirement.DETERMINISTIC
    )
    producer = make_descriptor(substrate_id=PRODUCER_ID)
    verifier = make_verifier(
        VERIFIER_A,
        owner="CyberSecGPT/verifier",
        determinism_profile="nondeterministic",
    )
    snapshot = make_snapshot(producer, verifier)
    decision = make_decision(request, selected_substrates=(PRODUCER_ID,))
    state = VerificationOrchestrationState(
        request_id=request.request_id,
        routing_decision_id=decision.decision_id,
        correlation_id=request.correlation_id,
        subject_ref="result:nondeterministic",
        subject_producer_substrate_id=PRODUCER_ID,
        policy=policy,
        selected_verifiers=(VERIFIER_A,),
        evidence_catalog=make_evidence(),
        observations=(observation(),),
        lifecycle=make_lifecycle(request, decision),
        started_at=NOW,
    )
    result = finalize_verification(
        state,
        request,
        decision,
        snapshot,
        make_termination(request, decision, NOW + timedelta(seconds=2)),
        current_binding=request.security_binding,
        finished_at=NOW + timedelta(seconds=2),
    )
    assert result.status is VerificationStatus.INSUFFICIENT_EVIDENCE


def test_finalize_rejects_invalid_state_and_earlier_finish() -> None:
    request, decision, snapshot, state = make_state()
    finished_at = NOW + timedelta(seconds=1)
    requirement = make_termination(request, decision, finished_at)
    with pytest.raises(VerificationOrchestrationError, match="OrchestrationState"):
        finalize_verification(
            "bad",
            request,
            decision,
            snapshot,
            requirement,
            current_binding=request.security_binding,
            finished_at=finished_at,
        )
    with pytest.raises(VerificationOrchestrationError, match="earlier"):
        finalize_verification(
            state,
            request,
            decision,
            snapshot,
            make_termination(request, decision, NOW - timedelta(seconds=1)),
            current_binding=request.security_binding,
            finished_at=NOW - timedelta(seconds=1),
        )


def test_finalize_rejects_cross_bound_or_stale_state_ids() -> None:
    request, decision, snapshot, state = make_state()
    finished_at = NOW + timedelta(seconds=1)
    requirement = make_termination(request, decision, finished_at)
    cases = (
        ({"request_id": RequestId("request:other")}, "state request_id"),
        (
            {"routing_decision_id": RoutingDecisionId("route:other")},
            "state routing_decision_id",
        ),
        (
            {"correlation_id": CorrelationId("correlation:other")},
            "state correlation_id",
        ),
    )
    for updates, message in cases:
        corrupted = _corrupt(state, **updates)
        with pytest.raises(VerificationOrchestrationError, match=message):
            finalize_verification(
                corrupted,
                request,
                decision,
                snapshot,
                requirement,
                current_binding=request.security_binding,
                finished_at=finished_at,
            )
