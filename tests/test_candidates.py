"""Tests for deterministic P5 substrate candidate selection."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import cast

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

from cybersecgpt.reasoning import (
    BrainRequest,
    CandidateEvaluation,
    CandidateRejectionReason,
    CandidateSelectionError,
    CandidateSelectionPolicy,
    CandidateSelectionResult,
    CapabilitySnapshot,
    ReasoningBudget,
    RoutingDecisionReasonCode,
    SubstrateAvailabilityState,
    SubstrateDescriptor,
    SubstrateKind,
    SubstrateProvenance,
    SubstrateResourceProfile,
    SubstrateValidationEvidence,
    build_capability_snapshot,
    select_candidate_substrates,
)

NOW = datetime(2026, 9, 7, 9, 0, tzinfo=UTC)
SNAPSHOT_ID = CapabilitySnapshotId("capabilities-selection-1")


def make_binding(**overrides: object) -> RoutingSecurityBinding:
    values: dict[str, object] = {
        "request_id": RequestId("request-selection-1"),
        "authorization_context_id": AuthorizationContextId("auth-selection-1"),
        "security_policy_revision_id": SecurityPolicyRevisionId("security-rev-7"),
        "effective_data_classification": "restricted",
        "provider_network_policy": "native-controlled",
        "offline_required": False,
        "capability_snapshot_id": SNAPSHOT_ID,
    }
    values.update(overrides)
    return RoutingSecurityBinding(**values)  # type: ignore[arg-type]


def make_budget() -> ReasoningBudget:
    return ReasoningBudget(
        policy_name="NORMAL",
        max_candidates=8,
        max_branch_depth=4,
        max_steps=16,
        max_model_tokens=4096,
        max_tool_calls=2,
        max_retrieval_calls=4,
        max_verifier_passes=3,
    )


def make_request(**overrides: object) -> BrainRequest:
    binding = cast(
        RoutingSecurityBinding,
        overrides.pop("security_binding", make_binding()),
    )
    values: dict[str, object] = {
        "request_id": binding.request_id,
        "correlation_id": CorrelationId("correlation-selection-1"),
        "security_binding": binding,
        "task_type": "reasoning",
        "domain": "general",
        "task_complexity": "normal",
        "safety_impact": "low",
        "source_data_classification": None,
        "identity_context_ref": None,
        "max_latency_ms": 1000,
        "max_compute_units": 8,
        "max_memory_bytes": 8192,
        "reasoning_budget": make_budget(),
        "required_accuracy": None,
        "required_determinism": False,
        "required_explainability": False,
        "verification_requirements": ("evidence",),
        "admitted_at": NOW - timedelta(minutes=1),
        "deadline": NOW + timedelta(minutes=5),
        "input_json": "{}",
    }
    values.update(overrides)
    return BrainRequest(**values)  # type: ignore[arg-type]


def make_resource(**overrides: object) -> SubstrateResourceProfile:
    values: dict[str, object] = {
        "min_compute_units": 1,
        "max_compute_units": 8,
        "min_memory_bytes": 1024,
        "max_memory_bytes": 8192,
        "max_latency_ms": 500,
    }
    values.update(overrides)
    return SubstrateResourceProfile(**values)  # type: ignore[arg-type]


def make_descriptor(**overrides: object) -> SubstrateDescriptor:
    values: dict[str, object] = {
        "substrate_id": SubstrateId("model:native-general"),
        "substrate_version": "1.0.0",
        "substrate_kind": SubstrateKind.NATIVE_MODEL,
        "owner": "CyberSecGPT/cybersecgpt-inference",
        "capabilities": ("general.reasoning",),
        "offline_capable": True,
        "network_requirements": ("none",),
        "determinism_profile": "seeded",
        "data_handling_profile": ("restricted",),
        "resource_profile": make_resource(),
        "authorization_requirements": (),
        "verification_profile": ("evidence", "explainability"),
        "availability_state": SubstrateAvailabilityState.AVAILABLE,
        "provenance": SubstrateProvenance(
            source_ref="registry://candidate/model",
            build_ref="build-1",
            artifact_ref="artifact:model:1",
            integrity_ref="sha256:abc",
        ),
    }
    values.update(overrides)
    return SubstrateDescriptor(**values)  # type: ignore[arg-type]


def make_validation(**overrides: object) -> SubstrateValidationEvidence:
    values: dict[str, object] = {
        "authority_ref": "registry-validator:v1",
        "evidence_refs": ("evidence:substrate:1",),
        "trusted_source_verified": True,
        "identity_verified": True,
        "version_verified": True,
        "integrity_verified": True,
        "compatibility_verified": True,
        "policy_constraints_checked": True,
        "validated_at": NOW - timedelta(minutes=2),
        "valid_until": NOW + timedelta(minutes=10),
    }
    values.update(overrides)
    return SubstrateValidationEvidence(**values)  # type: ignore[arg-type]


def make_snapshot(
    *descriptors: SubstrateDescriptor,
    validations: tuple[SubstrateValidationEvidence, ...] | None = None,
    snapshot_id: CapabilitySnapshotId = SNAPSHOT_ID,
) -> CapabilitySnapshot:
    if not descriptors:
        descriptors = (make_descriptor(),)
    evidence = validations or tuple(make_validation() for _ in descriptors)
    return build_capability_snapshot(
        snapshot_id=snapshot_id,
        created_at=NOW - timedelta(seconds=30),
        discovered=tuple(zip(descriptors, evidence, strict=True)),
    )


def make_policy(**overrides: object) -> CandidateSelectionPolicy:
    binding = make_binding()
    values: dict[str, object] = {
        "router_policy_id": "router.default",
        "router_policy_version": "1.0.0",
        "security_policy_revision_id": binding.security_policy_revision_id,
        "authorization_context_id": binding.authorization_context_id,
        "provider_network_policy": binding.provider_network_policy,
        "required_capabilities": ("general.reasoning",),
        "allowed_substrate_kinds": (SubstrateKind.NATIVE_MODEL,),
        "allowed_network_requirements": ("none", "local"),
        "satisfied_authorization_requirements": (),
        "deterministic_profiles": ("seeded", "strict"),
        "allow_degraded": True,
        "max_selected_substrates": 2,
        "explainability_profile": "explainability",
    }
    values.update(overrides)
    return CandidateSelectionPolicy(**values)  # type: ignore[arg-type]


def select(
    *,
    request: BrainRequest | None = None,
    snapshot: CapabilitySnapshot | None = None,
    policy: CandidateSelectionPolicy | None = None,
    current_binding: RoutingSecurityBinding | None = None,
    observed_at: datetime = NOW,
) -> CandidateSelectionResult:
    actual_request = request or make_request()
    return select_candidate_substrates(
        actual_request,
        snapshot or make_snapshot(),
        policy or make_policy(),
        current_binding=current_binding or actual_request.security_binding,
        observed_at=observed_at,
    )


def test_selector_prefers_available_smaller_competent_route_deterministically() -> None:
    large = make_descriptor(
        substrate_id=SubstrateId("model:a-large"),
        resource_profile=make_resource(
            min_compute_units=4,
            min_memory_bytes=4096,
            max_latency_ms=800,
        ),
    )
    small = make_descriptor(
        substrate_id=SubstrateId("model:z-small"),
        resource_profile=make_resource(
            min_compute_units=1,
            min_memory_bytes=1024,
            max_latency_ms=300,
        ),
    )
    degraded = make_descriptor(
        substrate_id=SubstrateId("model:degraded-tiny"),
        availability_state=SubstrateAvailabilityState.DEGRADED,
        resource_profile=make_resource(
            min_compute_units=0,
            min_memory_bytes=0,
            max_latency_ms=100,
        ),
    )

    result = select(snapshot=make_snapshot(large, small, degraded))

    assert result.selected_substrates == (
        SubstrateId("model:z-small"),
        SubstrateId("model:a-large"),
    )
    assert result.reason_codes == (
        RoutingDecisionReasonCode.CAPABILITY_MATCH,
        RoutingDecisionReasonCode.LOWER_RESOURCE_ROUTE_SUFFICIENT,
        RoutingDecisionReasonCode.VERIFICATION_ESCALATION,
        RoutingDecisionReasonCode.DEADLINE_RESTRICTION,
    )
    assert [item.substrate_id.value for item in result.evaluations] == [
        "model:a-large",
        "model:degraded-tiny",
        "model:z-small",
    ]
    assert all(item.eligible for item in result.evaluations)

    with pytest.raises(FrozenInstanceError):
        result.observed_at = NOW + timedelta(seconds=1)  # type: ignore[misc]


def test_selector_emits_offline_determinism_and_policy_reason_codes() -> None:
    binding = make_binding(offline_required=True)
    request = make_request(
        security_binding=binding,
        required_determinism=True,
        required_explainability=True,
    )
    blocked = make_descriptor(
        substrate_id=SubstrateId("tool:blocked"),
        substrate_kind=SubstrateKind.TOOL,
        network_requirements=("internet",),
        data_handling_profile=("public",),
        authorization_requirements=("privileged",),
    )

    result = select(
        request=request,
        current_binding=binding,
        snapshot=make_snapshot(blocked),
    )

    assert result.selected_substrates == ()
    assert result.reason_codes == (
        RoutingDecisionReasonCode.OFFLINE_REQUIRED,
        RoutingDecisionReasonCode.DETERMINISTIC_ROUTE_REQUIRED,
        RoutingDecisionReasonCode.SECURITY_POLICY_RESTRICTION,
        RoutingDecisionReasonCode.DATA_CLASSIFICATION_RESTRICTION,
        RoutingDecisionReasonCode.VERIFICATION_ESCALATION,
        RoutingDecisionReasonCode.DEADLINE_RESTRICTION,
    )


def test_selector_rejects_each_capability_and_resource_mismatch() -> None:
    candidates = (
        make_descriptor(
            substrate_id=SubstrateId("model:capability"),
            capabilities=("other",),
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:offline"),
            offline_capable=False,
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:compute"),
            resource_profile=make_resource(
                min_compute_units=9,
                max_compute_units=9,
            ),
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:memory"),
            resource_profile=make_resource(
                min_memory_bytes=9000,
                max_memory_bytes=9000,
            ),
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:latency-unknown"),
            resource_profile=make_resource(max_latency_ms=None),
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:latency-high"),
            resource_profile=make_resource(max_latency_ms=1001),
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:verification"),
            verification_profile=(),
        ),
    )
    binding = make_binding(offline_required=True)
    request = make_request(security_binding=binding)
    result = select(
        request=request,
        current_binding=binding,
        snapshot=make_snapshot(*candidates),
    )
    reasons = {
        item.substrate_id.value: set(item.rejection_reasons)
        for item in result.evaluations
    }

    assert CandidateRejectionReason.CAPABILITY_MISMATCH in reasons["model:capability"]
    assert CandidateRejectionReason.OFFLINE_UNSUPPORTED in reasons["model:offline"]
    assert CandidateRejectionReason.COMPUTE_BUDGET_EXCEEDED in reasons["model:compute"]
    assert CandidateRejectionReason.MEMORY_BUDGET_EXCEEDED in reasons["model:memory"]
    assert CandidateRejectionReason.LATENCY_BUDGET_UNPROVEN in reasons[
        "model:latency-unknown"
    ]
    assert CandidateRejectionReason.LATENCY_BUDGET_EXCEEDED in reasons[
        "model:latency-high"
    ]
    assert CandidateRejectionReason.VERIFICATION_REQUIREMENT_UNSUPPORTED in reasons[
        "model:verification"
    ]


def test_selector_handles_availability_and_quality_constraints() -> None:
    candidates = (
        make_descriptor(
            substrate_id=SubstrateId("model:degraded"),
            availability_state=SubstrateAvailabilityState.DEGRADED,
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:unavailable"),
            availability_state=SubstrateAvailabilityState.UNAVAILABLE,
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:revoked"),
            availability_state=SubstrateAvailabilityState.REVOKED,
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:incompatible"),
            availability_state=SubstrateAvailabilityState.INCOMPATIBLE,
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:nondeterministic"),
            determinism_profile="best_effort",
        ),
        make_descriptor(
            substrate_id=SubstrateId("model:no-explain"),
            verification_profile=("evidence",),
        ),
    )
    request = make_request(
        required_determinism=True,
        required_explainability=True,
        required_accuracy=0.9,
    )
    result = select(
        request=request,
        policy=make_policy(allow_degraded=False),
        snapshot=make_snapshot(*candidates),
    )
    reasons = {
        item.substrate_id.value: set(item.rejection_reasons)
        for item in result.evaluations
    }

    assert CandidateRejectionReason.DEGRADED_NOT_ALLOWED in reasons["model:degraded"]
    assert CandidateRejectionReason.UNAVAILABLE in reasons["model:unavailable"]
    assert CandidateRejectionReason.REVOKED in reasons["model:revoked"]
    assert CandidateRejectionReason.INCOMPATIBLE in reasons["model:incompatible"]
    assert CandidateRejectionReason.DETERMINISM_UNSUPPORTED in reasons[
        "model:nondeterministic"
    ]
    assert CandidateRejectionReason.EXPLAINABILITY_UNSUPPORTED in reasons[
        "model:no-explain"
    ]
    assert all(
        CandidateRejectionReason.ACCURACY_REQUIREMENT_UNSUPPORTED
        in item.rejection_reasons
        for item in result.evaluations
    )


def test_selector_rejects_stale_validation_evidence() -> None:
    validation = make_validation(valid_until=NOW + timedelta(seconds=1))
    snapshot = make_snapshot(make_descriptor(), validations=(validation,))

    result = select(
        snapshot=snapshot,
        observed_at=NOW + timedelta(seconds=1),
    )

    assert result.selected_substrates == ()
    assert result.evaluations[0].rejection_reasons == (
        CandidateRejectionReason.VALIDATION_STALE,
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"router_policy_id": ""}, "router_policy_id"),
        ({"router_policy_version": 1}, "router_policy_version"),
        ({"security_policy_revision_id": "rev"}, "security_policy_revision_id"),
        ({"authorization_context_id": "auth"}, "authorization_context_id"),
        ({"provider_network_policy": " policy"}, "provider_network_policy"),
        ({"required_capabilities": []}, "required_capabilities must be a tuple"),
        ({"required_capabilities": ()}, "required_capabilities must not be empty"),
        (
            {"required_capabilities": ("general.reasoning", "general.reasoning")},
            "required_capabilities must not contain duplicates",
        ),
        ({"required_capabilities": ("bad capability",)}, "machine-evaluable token"),
        ({"allowed_substrate_kinds": []}, "allowed_substrate_kinds must be a tuple"),
        ({"allowed_substrate_kinds": ()}, "allowed_substrate_kinds must not be empty"),
        ({"allowed_substrate_kinds": ("NATIVE_MODEL",)}, "SubstrateKind"),
        (
            {
                "allowed_substrate_kinds": (
                    SubstrateKind.NATIVE_MODEL,
                    SubstrateKind.NATIVE_MODEL,
                )
            },
            "allowed_substrate_kinds must not contain duplicates",
        ),
        ({"allowed_network_requirements": ["none"]}, "must be a tuple"),
        (
            {"satisfied_authorization_requirements": ("bad requirement",)},
            "machine-evaluable token",
        ),
        ({"deterministic_profiles": ("seeded", "seeded")}, "duplicates"),
        ({"allow_degraded": 1}, "allow_degraded"),
        ({"max_selected_substrates": 0}, "positive integer"),
        ({"max_selected_substrates": True}, "positive integer"),
        ({"explainability_profile": "bad profile"}, "machine-evaluable token"),
    ],
)
def test_policy_rejects_invalid_structure(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(CandidateSelectionError, match=message):
        make_policy(**overrides)


def test_policy_allows_empty_optional_constraints() -> None:
    policy = make_policy(
        allowed_network_requirements=(),
        satisfied_authorization_requirements=(),
        deterministic_profiles=(),
        explainability_profile=None,
    )
    assert policy.allowed_network_requirements == ()
    assert policy.explainability_profile is None


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"substrate_id": "model:a"}, "substrate_id"),
        ({"eligible": 1}, "eligible"),
        ({"rejection_reasons": []}, "rejection_reasons must be a tuple"),
        ({"rejection_reasons": ("CAPABILITY_MISMATCH",)}, "CandidateRejectionReason"),
        (
            {
                "rejection_reasons": (
                    CandidateRejectionReason.CAPABILITY_MISMATCH,
                    CandidateRejectionReason.CAPABILITY_MISMATCH,
                )
            },
            "duplicates",
        ),
        (
            {
                "eligible": True,
                "rejection_reasons": (CandidateRejectionReason.CAPABILITY_MISMATCH,),
            },
            "eligible must be true exactly",
        ),
        ({"eligible": False, "rejection_reasons": ()}, "eligible must be true exactly"),
    ],
)
def test_candidate_evaluation_rejects_inconsistent_state(
    kwargs: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "substrate_id": SubstrateId("model:a"),
        "eligible": True,
        "rejection_reasons": (),
    }
    values.update(kwargs)
    with pytest.raises(CandidateSelectionError, match=message):
        CandidateEvaluation(**values)  # type: ignore[arg-type]


def test_selector_rejects_binding_snapshot_policy_and_deadline_mismatches() -> None:
    snapshot = make_snapshot()

    with pytest.raises(CandidateSelectionError, match="current_binding must match"):
        select(current_binding=make_binding(request_id=RequestId("other")))
    with pytest.raises(CandidateSelectionError, match="capability snapshot"):
        select(snapshot=make_snapshot(snapshot_id=CapabilitySnapshotId("other")))
    with pytest.raises(CandidateSelectionError, match="snapshot is not yet valid"):
        select(snapshot=snapshot, observed_at=NOW - timedelta(minutes=1))
    with pytest.raises(CandidateSelectionError, match="security revision"):
        select(
            policy=make_policy(
                security_policy_revision_id=SecurityPolicyRevisionId("other")
            )
        )
    with pytest.raises(CandidateSelectionError, match="authorization context"):
        select(
            policy=make_policy(authorization_context_id=AuthorizationContextId("other"))
        )
    with pytest.raises(CandidateSelectionError, match="provider/network"):
        select(policy=make_policy(provider_network_policy="other"))
    with pytest.raises(CandidateSelectionError, match="deadline has been reached"):
        select(
            request=make_request(deadline=NOW),
            observed_at=NOW,
        )


@pytest.mark.parametrize(
    ("request", "snapshot", "policy", "binding", "observed_at", "message"),
    [
        ("request", make_snapshot(), make_policy(), make_binding(), NOW, "request"),
        (make_request(), "snapshot", make_policy(), make_binding(), NOW, "snapshot"),
        (make_request(), make_snapshot(), "policy", make_binding(), NOW, "policy"),
        (
            make_request(),
            make_snapshot(),
            make_policy(),
            "binding",
            NOW,
            "current_binding",
        ),
        (
            make_request(),
            make_snapshot(),
            make_policy(),
            make_binding(),
            cast(datetime, "now"),
            "observed_at",
        ),
    ],
)
def test_selector_rejects_invalid_component_types(
    request: object,
    snapshot: object,
    policy: object,
    binding: object,
    observed_at: datetime,
    message: str,
) -> None:
    with pytest.raises(CandidateSelectionError, match=message):
        select_candidate_substrates(
            cast(BrainRequest, request),
            cast(CapabilitySnapshot, snapshot),
            cast(CandidateSelectionPolicy, policy),
            current_binding=cast(RoutingSecurityBinding, binding),
            observed_at=observed_at,
        )


def test_selector_requires_explicit_explainability_profile_when_requested() -> None:
    result = select(
        request=make_request(required_explainability=True),
        policy=make_policy(explainability_profile=None),
    )
    assert result.selected_substrates == ()
    assert result.evaluations[0].rejection_reasons == (
        CandidateRejectionReason.EXPLAINABILITY_UNSUPPORTED,
    )
