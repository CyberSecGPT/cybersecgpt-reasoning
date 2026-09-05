"""Validated P5 intelligence-substrate discovery contracts."""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from cybersecgpt.foundation import CapabilitySnapshotId, SubstrateId

from .errors import SubstrateDiscoveryError

__all__ = [
    "CapabilitySnapshot",
    "SubstrateAvailabilityState",
    "SubstrateDescriptor",
    "SubstrateKind",
    "SubstrateProvenance",
    "SubstrateResourceProfile",
    "SubstrateValidationEvidence",
    "ValidatedSubstrate",
    "build_capability_snapshot",
    "validate_substrate_descriptor",
]

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VALIDATION_CHECK_FIELDS = (
    "trusted_source_verified",
    "identity_verified",
    "version_verified",
    "integrity_verified",
    "compatibility_verified",
    "policy_constraints_checked",
)


def _require_text(value: object, *, field_name: str, max_length: int = 512) -> str:
    if not isinstance(value, str):
        raise SubstrateDiscoveryError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise SubstrateDiscoveryError(
            f"{field_name} must be non-empty and have no surrounding whitespace"
        )
    if len(value) > max_length:
        raise SubstrateDiscoveryError(
            f"{field_name} must be at most {max_length} characters"
        )
    return value


def _require_token(value: object, *, field_name: str) -> str:
    text = _require_text(value, field_name=field_name, max_length=128)
    if _TOKEN_PATTERN.fullmatch(text) is None:
        raise SubstrateDiscoveryError(
            f"{field_name} must be a machine-evaluable token of at most 128 characters"
        )
    return text


def _require_non_negative_int(value: object, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SubstrateDiscoveryError(f"{field_name} must be a non-negative integer")
    return value


def _require_bool(value: object, *, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise SubstrateDiscoveryError(f"{field_name} must be a bool")
    return value


def _require_utc_datetime(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise SubstrateDiscoveryError(f"{field_name} must be a datetime")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise SubstrateDiscoveryError(f"{field_name} must be timezone-aware UTC")
    return value


def _require_tokens(
    value: object,
    *,
    field_name: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise SubstrateDiscoveryError(f"{field_name} must be a tuple")
    tokens = tuple(
        _require_token(item, field_name=f"{field_name} item") for item in value
    )
    if not allow_empty and not tokens:
        raise SubstrateDiscoveryError(f"{field_name} must not be empty")
    if len(set(tokens)) != len(tokens):
        raise SubstrateDiscoveryError(f"{field_name} must not contain duplicates")
    return tokens


def _require_references(value: object, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise SubstrateDiscoveryError(f"{field_name} must be a tuple")
    references = tuple(
        _require_text(item, field_name=f"{field_name} item") for item in value
    )
    if not references:
        raise SubstrateDiscoveryError(f"{field_name} must not be empty")
    if len(set(references)) != len(references):
        raise SubstrateDiscoveryError(f"{field_name} must not contain duplicates")
    return references


class SubstrateKind(StrEnum):
    """Approved routable intelligence classes from the P5 conformance profile."""

    NATIVE_MODEL = "NATIVE_MODEL"
    RETRIEVAL = "RETRIEVAL"
    CLASSICAL_ML = "CLASSICAL_ML"
    DOMAIN_RULE = "DOMAIN_RULE"
    SYMBOLIC = "SYMBOLIC"
    GRAPH = "GRAPH"
    TOOL = "TOOL"
    MEMORY = "MEMORY"
    VERIFIER = "VERIFIER"
    OTHER_APPROVED = "OTHER_APPROVED"


class SubstrateAvailabilityState(StrEnum):
    """Machine-evaluable discovery availability states."""

    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    REVOKED = "REVOKED"
    INCOMPATIBLE = "INCOMPATIBLE"


@dataclass(frozen=True, slots=True)
class SubstrateResourceProfile:
    """Describe bounded resource requirements and supported ceilings."""

    min_compute_units: int
    max_compute_units: int
    min_memory_bytes: int
    max_memory_bytes: int
    max_latency_ms: int | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "min_compute_units",
            "max_compute_units",
            "min_memory_bytes",
            "max_memory_bytes",
        ):
            _require_non_negative_int(getattr(self, field_name), field_name=field_name)

        if self.max_compute_units < self.min_compute_units:
            raise SubstrateDiscoveryError(
                "max_compute_units must be greater than or equal to min_compute_units"
            )
        if self.max_memory_bytes < self.min_memory_bytes:
            raise SubstrateDiscoveryError(
                "max_memory_bytes must be greater than or equal to min_memory_bytes"
            )
        if self.max_latency_ms is not None:
            _require_non_negative_int(self.max_latency_ms, field_name="max_latency_ms")


@dataclass(frozen=True, slots=True)
class SubstrateProvenance:
    """Carry opaque source/build/artifact integrity references for one descriptor."""

    source_ref: str
    build_ref: str
    artifact_ref: str
    integrity_ref: str

    def __post_init__(self) -> None:
        _require_text(self.source_ref, field_name="source_ref")
        _require_text(self.build_ref, field_name="build_ref")
        _require_text(self.artifact_ref, field_name="artifact_ref")
        _require_text(self.integrity_ref, field_name="integrity_ref")


@dataclass(frozen=True, slots=True)
class SubstrateDescriptor:
    """Describe one candidate intelligence substrate without granting routability.

    A descriptor is self-description until separate validation evidence proves the
    trusted discovery checks required by the P5 threat model.
    """

    substrate_id: SubstrateId
    substrate_version: str
    substrate_kind: SubstrateKind
    owner: str
    capabilities: tuple[str, ...]
    offline_capable: bool
    network_requirements: tuple[str, ...]
    determinism_profile: str
    data_handling_profile: tuple[str, ...]
    resource_profile: SubstrateResourceProfile
    authorization_requirements: tuple[str, ...]
    verification_profile: tuple[str, ...]
    availability_state: SubstrateAvailabilityState
    provenance: SubstrateProvenance

    def __post_init__(self) -> None:
        if not isinstance(self.substrate_id, SubstrateId):
            raise SubstrateDiscoveryError("substrate_id must be a SubstrateId")
        _require_token(self.substrate_id.value, field_name="substrate_id")
        if ":" not in self.substrate_id.value:
            message = "substrate_id must be a namespaced identifier"
            raise SubstrateDiscoveryError(message)

        _require_text(
            self.substrate_version,
            field_name="substrate_version",
            max_length=128,
        )
        if not isinstance(self.substrate_kind, SubstrateKind):
            raise SubstrateDiscoveryError("substrate_kind must be a SubstrateKind")
        _require_text(self.owner, field_name="owner", max_length=256)
        _require_tokens(
            self.capabilities,
            field_name="capabilities",
            allow_empty=False,
        )
        _require_bool(self.offline_capable, field_name="offline_capable")
        _require_tokens(
            self.network_requirements,
            field_name="network_requirements",
            allow_empty=False,
        )
        _require_token(self.determinism_profile, field_name="determinism_profile")
        _require_tokens(
            self.data_handling_profile,
            field_name="data_handling_profile",
            allow_empty=False,
        )

        if not isinstance(self.resource_profile, SubstrateResourceProfile):
            raise SubstrateDiscoveryError(
                "resource_profile must be a SubstrateResourceProfile"
            )
        _require_tokens(
            self.authorization_requirements,
            field_name="authorization_requirements",
            allow_empty=True,
        )
        _require_tokens(
            self.verification_profile,
            field_name="verification_profile",
            allow_empty=True,
        )
        if not isinstance(self.availability_state, SubstrateAvailabilityState):
            raise SubstrateDiscoveryError(
                "availability_state must be a SubstrateAvailabilityState"
            )
        if not isinstance(self.provenance, SubstrateProvenance):
            raise SubstrateDiscoveryError("provenance must be a SubstrateProvenance")


@dataclass(frozen=True, slots=True)
class SubstrateValidationEvidence:
    """Record independent validation facts supplied by trusted boundary owners.

    The booleans record completed checks; they do not make Reasoning an
    authorization or policy authority. Evidence references remain opaque here.
    """

    authority_ref: str
    evidence_refs: tuple[str, ...]
    trusted_source_verified: bool
    identity_verified: bool
    version_verified: bool
    integrity_verified: bool
    compatibility_verified: bool
    policy_constraints_checked: bool
    validated_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        _require_text(self.authority_ref, field_name="authority_ref")
        _require_references(self.evidence_refs, field_name="evidence_refs")
        for field_name in _VALIDATION_CHECK_FIELDS:
            _require_bool(getattr(self, field_name), field_name=field_name)

        validated_at = _require_utc_datetime(
            self.validated_at,
            field_name="validated_at",
        )
        valid_until = _require_utc_datetime(
            self.valid_until,
            field_name="valid_until",
        )
        if valid_until <= validated_at:
            raise SubstrateDiscoveryError("valid_until must be later than validated_at")


@dataclass(frozen=True, slots=True)
class ValidatedSubstrate:
    """Bind a descriptor to validation evidence that passed all required checks."""

    descriptor: SubstrateDescriptor
    validation: SubstrateValidationEvidence

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, SubstrateDescriptor):
            raise SubstrateDiscoveryError("descriptor must be a SubstrateDescriptor")
        if not isinstance(self.validation, SubstrateValidationEvidence):
            raise SubstrateDiscoveryError(
                "validation must be a SubstrateValidationEvidence"
            )
        failed = tuple(
            field_name
            for field_name in _VALIDATION_CHECK_FIELDS
            if not getattr(self.validation, field_name)
        )
        if failed:
            raise SubstrateDiscoveryError(
                "substrate validation checks are incomplete: " + ", ".join(failed)
            )


def validate_substrate_descriptor(
    descriptor: SubstrateDescriptor,
    validation: SubstrateValidationEvidence,
    *,
    observed_at: datetime,
) -> ValidatedSubstrate:
    """Validate one descriptor/evidence pair for discovery at a specific UTC time."""
    if not isinstance(descriptor, SubstrateDescriptor):
        raise SubstrateDiscoveryError("descriptor must be a SubstrateDescriptor")
    if not isinstance(validation, SubstrateValidationEvidence):
        raise SubstrateDiscoveryError(
            "validation must be a SubstrateValidationEvidence"
        )
    current_time = _require_utc_datetime(observed_at, field_name="observed_at")
    validated = ValidatedSubstrate(descriptor=descriptor, validation=validation)
    if current_time < validation.validated_at:
        raise SubstrateDiscoveryError("validation evidence is not yet valid")
    if current_time >= validation.valid_until:
        raise SubstrateDiscoveryError("validation evidence is stale")
    return validated


@dataclass(frozen=True, slots=True)
class CapabilitySnapshot:
    """Store one immutable, deterministic set of validated substrate metadata."""

    snapshot_id: CapabilitySnapshotId
    created_at: datetime
    substrates: tuple[ValidatedSubstrate, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot_id, CapabilitySnapshotId):
            raise SubstrateDiscoveryError(
                "snapshot_id must be a CapabilitySnapshotId"
            )
        created_at = _require_utc_datetime(self.created_at, field_name="created_at")
        if not isinstance(self.substrates, tuple):
            raise SubstrateDiscoveryError("substrates must be a tuple")
        if not all(isinstance(item, ValidatedSubstrate) for item in self.substrates):
            raise SubstrateDiscoveryError(
                "substrates must contain only ValidatedSubstrate values"
            )

        substrate_ids = tuple(
            item.descriptor.substrate_id.value for item in self.substrates
        )
        if len(set(substrate_ids)) != len(substrate_ids):
            raise SubstrateDiscoveryError(
                "capability snapshot must not contain duplicate substrate_id values"
            )
        if substrate_ids != tuple(sorted(substrate_ids)):
            raise SubstrateDiscoveryError(
                "capability snapshot substrates must be sorted by substrate_id"
            )

        for item in self.substrates:
            validate_substrate_descriptor(
                item.descriptor,
                item.validation,
                observed_at=created_at,
            )


def build_capability_snapshot(
    *,
    snapshot_id: CapabilitySnapshotId,
    created_at: datetime,
    discovered: tuple[
        tuple[SubstrateDescriptor, SubstrateValidationEvidence],
        ...,
    ],
) -> CapabilitySnapshot:
    """Build a deterministic capability snapshot from separately validated inputs."""
    if not isinstance(discovered, tuple):
        raise SubstrateDiscoveryError("discovered must be a tuple")

    validated: list[ValidatedSubstrate] = []
    for item in discovered:
        if not isinstance(item, tuple) or len(item) != 2:
            raise SubstrateDiscoveryError(
                "discovered items must be descriptor/validation pairs"
            )
        descriptor, validation = item
        validated.append(
            validate_substrate_descriptor(
                descriptor,
                validation,
                observed_at=created_at,
            )
        )

    validated.sort(key=lambda item: item.descriptor.substrate_id.value)
    return CapabilitySnapshot(
        snapshot_id=snapshot_id,
        created_at=created_at,
        substrates=tuple(validated),
    )
