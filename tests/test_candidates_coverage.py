"""Coverage of defensive P5 candidate-selection branches."""

from datetime import UTC, datetime, timedelta

import pytest
from cybersecgpt.foundation import (
    AuthorizationContextId,
    CapabilitySnapshotId,
    CorrelationId,
    RequestId,
    RoutingSecurityBinding,
    SecurityPolicyRevisionId,
    SubstrateId,
)

import cybersecgpt.reasoning.candidates as candidate_module
from cybersecgpt.reasoning import (
    BrainRequest,
    CandidateEvaluation,
    CandidateRejectionReason,
    CandidateSelectionError,
    CandidateSelectionPolicy,
    CandidateSelectionResult,
    ReasoningBudget,
    RoutingDecisionReasonCode,
    SubstrateAvailabilityState,
    SubstrateDescriptor,
    SubstrateKind,
    SubstrateProvenance,
    SubstrateResourceProfile,
    SubstrateValidationEvidence,
    ValidatedSubstrate,
)

NOW = datetime(2026, 9, 7, 10, 0, tzinfo=UTC)
REQUEST_ID = RequestId("request-coverage")
SNAPSHOT_ID = CapabilitySnapshotId("snapshot-coverage")
AUTH_ID = AuthorizationContextId("auth-coverage")
SECURITY_REVISION_ID = SecurityPolicyRevisionId("security-coverage")


def make_binding() -> RoutingSecurityBinding:
    return RoutingSecurityBinding(
        request_id=REQUEST_ID,
        authorization_context_id=AUTH_ID,
        security_policy_revision_id=SECURITY_REVISION_ID,
        effective_data_classification="restricted",
        provider_network_policy="native-controlled",
        offline_required=False,
        capability_snapshot_id=SNAPSHOT_ID,
    )


def make_budget() -> ReasoningBudget:
    return ReasoningBudget(
        policy_name="NORMAL",
        max_candidates=4,
        max_branch_depth=2,
        max_steps=8,
        max_model_tokens=1024,
        max_tool_calls=1,
        max_retrieval_calls=1,
        max_verifier_passes=1,
    )


def make_request() -> BrainRequest:
    return BrainRequest(
        request_id=REQUEST_ID,
        correlation_id=CorrelationId("correlation-coverage"),
        security_binding=make_binding(),
        task_type="reasoning",
        domain="general",
        task_complexity="normal",
        safety_impact="low",
        source_data_classification=None,
        identity_context_ref=None,
        max_latency_ms=1000,
        max_compute_units=4,
        max_memory_bytes=4096,
        reasoning_budget=make_budget(),
        required_accuracy=None,
        required_determinism=False,
        required_explainability=False,
        verification_requirements=(),
        admitted_at=NOW - timedelta(seconds=1),
        deadline=None,
        input_json="{}",
    )


def make_policy(*, max_selected_substrates: int = 1) -> CandidateSelectionPolicy:
    return CandidateSelectionPolicy(
        router_policy_id="router.coverage",
        router_policy_version="1.0.0",
        security_policy_revision_id=SECURITY_REVISION_ID,
        authorization_context_id=AUTH_ID,
        provider_network_policy="native-controlled",
        required_capabilities=("general.reasoning",),
        allowed_substrate_kinds=(SubstrateKind.NATIVE_MODEL,),
        allowed_network_requirements=("none",),
        satisfied_authorization_requirements=(),
        deterministic_profiles=("seeded",),
        allow_degraded=False,
        max_selected_substrates=max_selected_substrates,
        explainability_profile=None,
    )


def make_evaluation(
    substrate_id: str,
    *,
    eligible: bool = True,
) -> CandidateEvaluation:
    reasons = ()
    if not eligible:
        reasons = (CandidateRejectionReason.CAPABILITY_MISMATCH,)
    return CandidateEvaluation(
        substrate_id=SubstrateId(substrate_id),
        eligible=eligible,
        rejection_reasons=reasons,
    )


def make_result(**overrides: object) -> CandidateSelectionResult:
    eligible = make_evaluation("model:a")
    values: dict[str, object] = {
        "request_id": REQUEST_ID,
        "capability_snapshot_id": SNAPSHOT_ID,
        "policy": make_policy(),
        "observed_at": NOW,
        "evaluations": (eligible,),
        "selected_substrates": (eligible.substrate_id,),
        "reason_codes": (RoutingDecisionReasonCode.CAPABILITY_MATCH,),
    }
    values.update(overrides)
    return CandidateSelectionResult(**values)  # type: ignore[arg-type]


def test_result_rejects_invalid_identity_policy_time_and_container_types() -> None:
    with pytest.raises(CandidateSelectionError, match="request_id"):
        make_result(request_id="request")
    with pytest.raises(CandidateSelectionError, match="capability_snapshot_id"):
        make_result(capability_snapshot_id="snapshot")
    with pytest.raises(CandidateSelectionError, match="policy"):
        make_result(policy="policy")
    with pytest.raises(CandidateSelectionError, match="timezone-aware UTC"):
        make_result(observed_at=datetime(2026, 9, 7, 10, 0))
    with pytest.raises(CandidateSelectionError, match="evaluations must be a tuple"):
        make_result(evaluations=[])
    with pytest.raises(CandidateSelectionError, match="CandidateEvaluation"):
        make_result(evaluations=("evaluation",))
    with pytest.raises(
        CandidateSelectionError,
        match="selected_substrates must be a tuple",
    ):
        make_result(selected_substrates=[])
    with pytest.raises(CandidateSelectionError, match="SubstrateId"):
        make_result(selected_substrates=("model:a",))
    with pytest.raises(CandidateSelectionError, match="reason_codes must be a tuple"):
        make_result(reason_codes=[])
    with pytest.raises(CandidateSelectionError, match="RoutingDecisionReasonCode"):
        make_result(reason_codes=("CAPABILITY_MATCH",))


def test_result_rejects_duplicate_unsorted_and_inconsistent_selection_state() -> None:
    eligible_a = make_evaluation("model:a")
    eligible_b = make_evaluation("model:b")
    ineligible_a = make_evaluation("model:a", eligible=False)

    with pytest.raises(CandidateSelectionError, match="duplicate IDs"):
        make_result(evaluations=(eligible_a, eligible_a))
    with pytest.raises(CandidateSelectionError, match="sorted by substrate_id"):
        make_result(evaluations=(eligible_b, eligible_a))
    with pytest.raises(CandidateSelectionError, match="must not contain duplicates"):
        make_result(
            selected_substrates=(
                eligible_a.substrate_id,
                eligible_a.substrate_id,
            )
        )
    with pytest.raises(
        CandidateSelectionError,
        match="exceeds max_selected_substrates",
    ):
        make_result(
            evaluations=(eligible_a, eligible_b),
            selected_substrates=(eligible_a.substrate_id, eligible_b.substrate_id),
        )
    with pytest.raises(CandidateSelectionError, match="only eligible substrates"):
        make_result(
            evaluations=(ineligible_a,),
            selected_substrates=(ineligible_a.substrate_id,),
        )
    with pytest.raises(
        CandidateSelectionError,
        match="reason_codes must not contain duplicates",
    ):
        make_result(
            reason_codes=(
                RoutingDecisionReasonCode.CAPABILITY_MATCH,
                RoutingDecisionReasonCode.CAPABILITY_MATCH,
            )
        )
    with pytest.raises(CandidateSelectionError, match="CAPABILITY_MATCH"):
        make_result(reason_codes=())


def make_descriptor(*, max_latency_ms: int | None = 500) -> SubstrateDescriptor:
    return SubstrateDescriptor(
        substrate_id=SubstrateId("model:coverage"),
        substrate_version="1.0.0",
        substrate_kind=SubstrateKind.NATIVE_MODEL,
        owner="CyberSecGPT/cybersecgpt-inference",
        capabilities=("general.reasoning",),
        offline_capable=True,
        network_requirements=("none",),
        determinism_profile="seeded",
        data_handling_profile=("restricted",),
        resource_profile=SubstrateResourceProfile(
            min_compute_units=1,
            max_compute_units=4,
            min_memory_bytes=1024,
            max_memory_bytes=4096,
            max_latency_ms=max_latency_ms,
        ),
        authorization_requirements=(),
        verification_profile=(),
        availability_state=SubstrateAvailabilityState.AVAILABLE,
        provenance=SubstrateProvenance(
            source_ref="registry://coverage/model",
            build_ref="build-coverage",
            artifact_ref="artifact:coverage:model",
            integrity_ref="sha256:coverage",
        ),
    )


def make_validation(*, future: bool = False) -> SubstrateValidationEvidence:
    validated_at = NOW + timedelta(seconds=1) if future else NOW - timedelta(seconds=1)
    return SubstrateValidationEvidence(
        authority_ref="registry-validator:coverage",
        evidence_refs=("evidence:coverage",),
        trusted_source_verified=True,
        identity_verified=True,
        version_verified=True,
        integrity_verified=True,
        compatibility_verified=True,
        policy_constraints_checked=True,
        validated_at=validated_at,
        valid_until=validated_at + timedelta(minutes=1),
    )


def test_private_selector_guards_cover_future_validation_and_unbounded_rank() -> None:
    future_substrate = ValidatedSubstrate(
        descriptor=make_descriptor(),
        validation=make_validation(future=True),
    )
    evaluation = candidate_module._evaluate_candidate(  # noqa: SLF001
        make_request(),
        make_policy(),
        future_substrate,
        observed_at=NOW,
    )
    assert evaluation.rejection_reasons == (
        CandidateRejectionReason.VALIDATION_NOT_YET_VALID,
    )

    unbounded = ValidatedSubstrate(
        descriptor=make_descriptor(max_latency_ms=None),
        validation=make_validation(),
    )
    with pytest.raises(CandidateSelectionError, match="unbounded latency"):
        candidate_module._rank_key(unbounded)  # noqa: SLF001


def test_reason_codes_can_omit_verification_and_deadline_restrictions() -> None:
    request = make_request()
    eligible = make_evaluation("model:a")
    codes = candidate_module._reason_codes(  # noqa: SLF001
        request,
        (eligible,),
        (eligible.substrate_id,),
    )
    assert codes == (RoutingDecisionReasonCode.CAPABILITY_MATCH,)
