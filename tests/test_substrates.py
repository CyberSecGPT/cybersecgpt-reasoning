"""Tests for validated P5 intelligence-substrate discovery contracts."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from typing import cast

import pytest
from cybersecgpt.foundation import CapabilitySnapshotId, SubstrateId

from cybersecgpt.reasoning import (
    CapabilitySnapshot,
    SubstrateAvailabilityState,
    SubstrateDescriptor,
    SubstrateDiscoveryError,
    SubstrateKind,
    SubstrateProvenance,
    SubstrateResourceProfile,
    SubstrateValidationEvidence,
    ValidatedSubstrate,
    build_capability_snapshot,
    validate_substrate_descriptor,
)

VALIDATED_AT = datetime(2026, 9, 5, 15, 0, tzinfo=UTC)
OBSERVED_AT = VALIDATED_AT + timedelta(minutes=1)
VALID_UNTIL = VALIDATED_AT + timedelta(minutes=10)


def make_resource(**overrides: object) -> SubstrateResourceProfile:
    values: dict[str, object] = {
        "min_compute_units": 1,
        "max_compute_units": 8,
        "min_memory_bytes": 1024,
        "max_memory_bytes": 1048576,
        "max_latency_ms": 5000,
    }
    values.update(overrides)
    return SubstrateResourceProfile(**values)  # type: ignore[arg-type]


def make_provenance(**overrides: object) -> SubstrateProvenance:
    values: dict[str, object] = {
        "source_ref": "registry://native-brain/model-general",
        "build_ref": "build-42",
        "artifact_ref": "artifact:model-general:1.0.0",
        "integrity_ref": "sha256:0123456789abcdef",
    }
    values.update(overrides)
    return SubstrateProvenance(**values)  # type: ignore[arg-type]


def make_descriptor(**overrides: object) -> SubstrateDescriptor:
    values: dict[str, object] = {
        "substrate_id": SubstrateId("model:native-general"),
        "substrate_version": "1.0.0",
        "substrate_kind": SubstrateKind.NATIVE_MODEL,
        "owner": "CyberSecGPT/cybersecgpt-inference",
        "capabilities": ("general.reasoning", "cyber.analysis"),
        "offline_capable": True,
        "network_requirements": ("none",),
        "determinism_profile": "seeded",
        "data_handling_profile": ("public", "restricted"),
        "resource_profile": make_resource(),
        "authorization_requirements": (),
        "verification_profile": ("evidence",),
        "availability_state": SubstrateAvailabilityState.AVAILABLE,
        "provenance": make_provenance(),
    }
    values.update(overrides)
    return SubstrateDescriptor(**values)  # type: ignore[arg-type]


def make_validation(**overrides: object) -> SubstrateValidationEvidence:
    values: dict[str, object] = {
        "authority_ref": "registry-validator:v1",
        "evidence_refs": ("evidence:descriptor:42", "evidence:policy:7"),
        "trusted_source_verified": True,
        "identity_verified": True,
        "version_verified": True,
        "integrity_verified": True,
        "compatibility_verified": True,
        "policy_constraints_checked": True,
        "validated_at": VALIDATED_AT,
        "valid_until": VALID_UNTIL,
    }
    values.update(overrides)
    return SubstrateValidationEvidence(**values)  # type: ignore[arg-type]


def test_validate_descriptor_and_build_deterministic_snapshot() -> None:
    model = make_descriptor()
    retrieval = make_descriptor(
        substrate_id=SubstrateId("retrieval:local-index"),
        substrate_kind=SubstrateKind.RETRIEVAL,
        owner="CyberSecGPT/cybersecgpt-retrieval",
        capabilities=("knowledge.lookup",),
        availability_state=SubstrateAvailabilityState.DEGRADED,
    )

    validated = validate_substrate_descriptor(
        model,
        make_validation(),
        observed_at=OBSERVED_AT,
    )
    snapshot = build_capability_snapshot(
        snapshot_id=CapabilitySnapshotId("capabilities-5"),
        created_at=OBSERVED_AT,
        discovered=(
            (retrieval, make_validation()),
            (model, make_validation()),
        ),
    )

    assert validated.descriptor == model
    assert validated.validation.trusted_source_verified is True
    assert [item.descriptor.substrate_id.value for item in snapshot.substrates] == [
        "model:native-general",
        "retrieval:local-index",
    ]
    assert snapshot.substrates[1].descriptor.availability_state is (
        SubstrateAvailabilityState.DEGRADED
    )

    with pytest.raises(FrozenInstanceError):
        snapshot.created_at = VALIDATED_AT  # type: ignore[misc]


def test_empty_discovery_builds_explicit_empty_snapshot() -> None:
    snapshot = build_capability_snapshot(
        snapshot_id=CapabilitySnapshotId("capabilities-empty"),
        created_at=OBSERVED_AT,
        discovered=(),
    )

    assert snapshot.substrates == ()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"min_compute_units": True}, "min_compute_units"),
        ({"max_compute_units": -1}, "max_compute_units"),
        ({"min_memory_bytes": "small"}, "min_memory_bytes"),
        ({"max_memory_bytes": -1}, "max_memory_bytes"),
        (
            {"min_compute_units": 5, "max_compute_units": 4},
            "max_compute_units must be greater",
        ),
        (
            {"min_memory_bytes": 2048, "max_memory_bytes": 1024},
            "max_memory_bytes must be greater",
        ),
        ({"max_latency_ms": -1}, "max_latency_ms"),
    ],
)
def test_resource_profile_rejects_invalid_bounds(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(SubstrateDiscoveryError, match=message):
        make_resource(**overrides)


def test_resource_profile_allows_unspecified_latency() -> None:
    assert make_resource(max_latency_ms=None).max_latency_ms is None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"source_ref": 7}, "source_ref"),
        ({"build_ref": ""}, "build_ref"),
        ({"artifact_ref": " artifact"}, "artifact_ref"),
        ({"integrity_ref": "x" * 513}, "integrity_ref"),
    ],
)
def test_provenance_rejects_invalid_references(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(SubstrateDiscoveryError, match=message):
        make_provenance(**overrides)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"substrate_id": "model:native-general"}, "substrate_id"),
        ({"substrate_id": SubstrateId("model/native")}, "machine-evaluable token"),
        ({"substrate_id": SubstrateId("model-native")}, "namespaced identifier"),
        ({"substrate_version": "v" * 129}, "substrate_version"),
        ({"substrate_kind": "NATIVE_MODEL"}, "substrate_kind"),
        ({"owner": ""}, "owner"),
        ({"capabilities": ["cyber.analysis"]}, "capabilities must be a tuple"),
        ({"capabilities": ()}, "capabilities must not be empty"),
        (
            {"capabilities": ("cyber.analysis", "cyber.analysis")},
            "capabilities must not contain duplicates",
        ),
        ({"capabilities": ("bad capability",)}, "machine-evaluable token"),
        ({"offline_capable": 1}, "offline_capable"),
        ({"network_requirements": ()}, "network_requirements must not be empty"),
        ({"determinism_profile": "not valid"}, "machine-evaluable token"),
        ({"data_handling_profile": ()}, "data_handling_profile must not be empty"),
        ({"resource_profile": "resource"}, "resource_profile"),
        (
            {"authorization_requirements": ["grant"]},
            "authorization_requirements must be a tuple",
        ),
        (
            {"verification_profile": ("evidence", "evidence")},
            "verification_profile must not contain duplicates",
        ),
        ({"availability_state": "AVAILABLE"}, "availability_state"),
        ({"provenance": "provenance"}, "provenance"),
    ],
)
def test_descriptor_rejects_invalid_metadata(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(SubstrateDiscoveryError, match=message):
        make_descriptor(**overrides)


def test_descriptor_supports_all_approved_routable_kinds() -> None:
    assert tuple(SubstrateKind) == (
        SubstrateKind.NATIVE_MODEL,
        SubstrateKind.RETRIEVAL,
        SubstrateKind.CLASSICAL_ML,
        SubstrateKind.DOMAIN_RULE,
        SubstrateKind.SYMBOLIC,
        SubstrateKind.GRAPH,
        SubstrateKind.TOOL,
        SubstrateKind.MEMORY,
        SubstrateKind.VERIFIER,
        SubstrateKind.OTHER_APPROVED,
    )
    assert tuple(SubstrateAvailabilityState) == (
        SubstrateAvailabilityState.AVAILABLE,
        SubstrateAvailabilityState.DEGRADED,
        SubstrateAvailabilityState.UNAVAILABLE,
        SubstrateAvailabilityState.REVOKED,
        SubstrateAvailabilityState.INCOMPATIBLE,
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"authority_ref": ""}, "authority_ref"),
        ({"evidence_refs": ["evidence:1"]}, "evidence_refs must be a tuple"),
        ({"evidence_refs": ()}, "evidence_refs must not be empty"),
        (
            {"evidence_refs": ("evidence:1", "evidence:1")},
            "evidence_refs must not contain duplicates",
        ),
        ({"evidence_refs": (cast(str, 7),)}, "evidence_refs item"),
        ({"trusted_source_verified": 1}, "trusted_source_verified"),
        ({"validated_at": "now"}, "validated_at"),
        ({"validated_at": datetime(2026, 9, 5, 15, 0)}, "timezone-aware UTC"),
        (
            {
                "valid_until": datetime(
                    2026,
                    9,
                    5,
                    17,
                    0,
                    tzinfo=timezone(timedelta(hours=2)),
                )
            },
            "timezone-aware UTC",
        ),
        ({"valid_until": VALIDATED_AT}, "later than validated_at"),
    ],
)
def test_validation_evidence_rejects_invalid_structure(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(SubstrateDiscoveryError, match=message):
        make_validation(**overrides)


@pytest.mark.parametrize(
    "failed_field",
    [
        "trusted_source_verified",
        "identity_verified",
        "version_verified",
        "integrity_verified",
        "compatibility_verified",
        "policy_constraints_checked",
    ],
)
def test_incomplete_validation_never_makes_descriptor_routable(
    failed_field: str,
) -> None:
    evidence = make_validation(**{failed_field: False})

    with pytest.raises(SubstrateDiscoveryError, match=failed_field):
        ValidatedSubstrate(descriptor=make_descriptor(), validation=evidence)


def test_validated_substrate_rejects_wrong_component_types() -> None:
    with pytest.raises(SubstrateDiscoveryError, match="descriptor"):
        ValidatedSubstrate(
            descriptor=cast(SubstrateDescriptor, "descriptor"),
            validation=make_validation(),
        )

    with pytest.raises(SubstrateDiscoveryError, match="validation"):
        ValidatedSubstrate(
            descriptor=make_descriptor(),
            validation=cast(SubstrateValidationEvidence, "validation"),
        )


@pytest.mark.parametrize(
    ("descriptor", "validation", "observed_at", "message"),
    [
        (cast(SubstrateDescriptor, "descriptor"), make_validation(), OBSERVED_AT, "descriptor"),
        (
            make_descriptor(),
            cast(SubstrateValidationEvidence, "validation"),
            OBSERVED_AT,
            "validation",
        ),
        (make_descriptor(), make_validation(), cast(datetime, "now"), "observed_at"),
        (
            make_descriptor(),
            make_validation(),
            VALIDATED_AT - timedelta(seconds=1),
            "not yet valid",
        ),
        (make_descriptor(), make_validation(), VALID_UNTIL, "stale"),
    ],
)
def test_validate_descriptor_rejects_invalid_or_stale_inputs(
    descriptor: SubstrateDescriptor,
    validation: SubstrateValidationEvidence,
    observed_at: datetime,
    message: str,
) -> None:
    with pytest.raises(SubstrateDiscoveryError, match=message):
        validate_substrate_descriptor(
            descriptor,
            validation,
            observed_at=observed_at,
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"snapshot_id": "capabilities-5"}, "snapshot_id"),
        ({"created_at": datetime(2026, 9, 5, 15, 1)}, "timezone-aware UTC"),
        ({"substrates": []}, "substrates must be a tuple"),
        ({"substrates": ("substrate",)}, "ValidatedSubstrate"),
    ],
)
def test_capability_snapshot_rejects_invalid_structure(
    overrides: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "snapshot_id": CapabilitySnapshotId("capabilities-5"),
        "created_at": OBSERVED_AT,
        "substrates": (),
    }
    values.update(overrides)
    with pytest.raises(SubstrateDiscoveryError, match=message):
        CapabilitySnapshot(**values)  # type: ignore[arg-type]


def test_capability_snapshot_rejects_duplicate_and_unsorted_ids() -> None:
    first = validate_substrate_descriptor(
        make_descriptor(substrate_id=SubstrateId("model:a")),
        make_validation(),
        observed_at=OBSERVED_AT,
    )
    duplicate = validate_substrate_descriptor(
        make_descriptor(substrate_id=SubstrateId("model:a"), substrate_version="2.0.0"),
        make_validation(),
        observed_at=OBSERVED_AT,
    )
    second = validate_substrate_descriptor(
        make_descriptor(substrate_id=SubstrateId("model:b")),
        make_validation(),
        observed_at=OBSERVED_AT,
    )

    with pytest.raises(SubstrateDiscoveryError, match="duplicate substrate_id"):
        CapabilitySnapshot(
            snapshot_id=CapabilitySnapshotId("capabilities-duplicate"),
            created_at=OBSERVED_AT,
            substrates=(first, duplicate),
        )

    with pytest.raises(SubstrateDiscoveryError, match="sorted by substrate_id"):
        CapabilitySnapshot(
            snapshot_id=CapabilitySnapshotId("capabilities-unsorted"),
            created_at=OBSERVED_AT,
            substrates=(second, first),
        )


def test_capability_snapshot_revalidates_evidence_freshness() -> None:
    validated = validate_substrate_descriptor(
        make_descriptor(),
        make_validation(),
        observed_at=OBSERVED_AT,
    )

    with pytest.raises(SubstrateDiscoveryError, match="stale"):
        CapabilitySnapshot(
            snapshot_id=CapabilitySnapshotId("capabilities-stale"),
            created_at=VALID_UNTIL,
            substrates=(validated,),
        )


def test_build_snapshot_rejects_malformed_discovery_inputs() -> None:
    with pytest.raises(SubstrateDiscoveryError, match="discovered must be a tuple"):
        build_capability_snapshot(
            snapshot_id=CapabilitySnapshotId("capabilities-list"),
            created_at=OBSERVED_AT,
            discovered=cast(
                tuple[tuple[SubstrateDescriptor, SubstrateValidationEvidence], ...],
                [],
            ),
        )

    with pytest.raises(SubstrateDiscoveryError, match="descriptor/validation pairs"):
        build_capability_snapshot(
            snapshot_id=CapabilitySnapshotId("capabilities-malformed"),
            created_at=OBSERVED_AT,
            discovered=cast(
                tuple[tuple[SubstrateDescriptor, SubstrateValidationEvidence], ...],
                ((make_descriptor(),),),
            ),
        )
