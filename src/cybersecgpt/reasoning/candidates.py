"""Deterministic P5 intelligence-substrate candidate selection."""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from cybersecgpt.foundation import (
    AuthorizationContextId,
    CapabilitySnapshotId,
    RequestId,
    RoutingSecurityBinding,
    SecurityPolicyRevisionId,
    SubstrateId,
)

from .errors import CandidateSelectionError
from .request import BrainRequest
from .routing import RoutingDecisionReasonCode
from .substrates import (
    CapabilitySnapshot,
    SubstrateAvailabilityState,
    SubstrateKind,
    ValidatedSubstrate,
)

__all__ = [
    "CandidateEvaluation",
    "CandidateRejectionReason",
    "CandidateSelectionPolicy",
    "CandidateSelectionResult",
    "select_candidate_substrates",
]

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class CandidateRejectionReason(StrEnum):
    """Machine-evaluable reasons a discovered substrate is not selectable."""

    VALIDATION_NOT_YET_VALID = "VALIDATION_NOT_YET_VALID"
    VALIDATION_STALE = "VALIDATION_STALE"
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    SUBSTRATE_KIND_RESTRICTED = "SUBSTRATE_KIND_RESTRICTED"
    DEGRADED_NOT_ALLOWED = "DEGRADED_NOT_ALLOWED"
    UNAVAILABLE = "UNAVAILABLE"
    REVOKED = "REVOKED"
    INCOMPATIBLE = "INCOMPATIBLE"
    OFFLINE_UNSUPPORTED = "OFFLINE_UNSUPPORTED"
    NETWORK_POLICY_RESTRICTION = "NETWORK_POLICY_RESTRICTION"
    DATA_CLASSIFICATION_RESTRICTION = "DATA_CLASSIFICATION_RESTRICTION"
    AUTHORIZATION_REQUIREMENT_UNSATISFIED = (
        "AUTHORIZATION_REQUIREMENT_UNSATISFIED"
    )
    COMPUTE_BUDGET_EXCEEDED = "COMPUTE_BUDGET_EXCEEDED"
    MEMORY_BUDGET_EXCEEDED = "MEMORY_BUDGET_EXCEEDED"
    LATENCY_BUDGET_UNPROVEN = "LATENCY_BUDGET_UNPROVEN"
    LATENCY_BUDGET_EXCEEDED = "LATENCY_BUDGET_EXCEEDED"
    DETERMINISM_UNSUPPORTED = "DETERMINISM_UNSUPPORTED"
    VERIFICATION_REQUIREMENT_UNSUPPORTED = "VERIFICATION_REQUIREMENT_UNSUPPORTED"
    EXPLAINABILITY_UNSUPPORTED = "EXPLAINABILITY_UNSUPPORTED"
    ACCURACY_REQUIREMENT_UNSUPPORTED = "ACCURACY_REQUIREMENT_UNSUPPORTED"


def _require_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise CandidateSelectionError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise CandidateSelectionError(
            f"{field_name} must be non-empty and have no surrounding whitespace"
        )
    return value


def _require_token(value: object, *, field_name: str) -> str:
    text = _require_text(value, field_name=field_name)
    if _TOKEN_PATTERN.fullmatch(text) is None:
        raise CandidateSelectionError(
            f"{field_name} must be a machine-evaluable token of at most 128 characters"
        )
    return text


def _require_tokens(
    value: object,
    *,
    field_name: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise CandidateSelectionError(f"{field_name} must be a tuple")
    values = tuple(_require_token(item, field_name=f"{field_name} item") for item in value)
    if not allow_empty and not values:
        raise CandidateSelectionError(f"{field_name} must not be empty")
    if len(set(values)) != len(values):
        raise CandidateSelectionError(f"{field_name} must not contain duplicates")
    return values


def _require_utc_datetime(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise CandidateSelectionError(f"{field_name} must be a datetime")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise CandidateSelectionError(f"{field_name} must be timezone-aware UTC")
    return value


@dataclass(frozen=True, slots=True)
class CandidateSelectionPolicy:
    """Bind deterministic router-selection constraints to current security state.

    This is router control metadata, not an authorization or security-policy grant.
    The authoritative owners must supply current policy-derived values.
    """

    router_policy_id: str
    router_policy_version: str
    security_policy_revision_id: SecurityPolicyRevisionId
    authorization_context_id: AuthorizationContextId
    provider_network_policy: str
    required_capabilities: tuple[str, ...]
    allowed_substrate_kinds: tuple[SubstrateKind, ...]
    allowed_network_requirements: tuple[str, ...]
    satisfied_authorization_requirements: tuple[str, ...]
    deterministic_profiles: tuple[str, ...]
    allow_degraded: bool
    max_selected_substrates: int
    explainability_profile: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.router_policy_id, field_name="router_policy_id")
        _require_text(self.router_policy_version, field_name="router_policy_version")
        if not isinstance(self.security_policy_revision_id, SecurityPolicyRevisionId):
            raise CandidateSelectionError(
                "security_policy_revision_id must be a SecurityPolicyRevisionId"
            )
        if not isinstance(self.authorization_context_id, AuthorizationContextId):
            raise CandidateSelectionError(
                "authorization_context_id must be an AuthorizationContextId"
            )
        _require_text(self.provider_network_policy, field_name="provider_network_policy")
        _require_tokens(
            self.required_capabilities,
            field_name="required_capabilities",
            allow_empty=False,
        )
        if not isinstance(self.allowed_substrate_kinds, tuple):
            raise CandidateSelectionError("allowed_substrate_kinds must be a tuple")
        if not self.allowed_substrate_kinds:
            raise CandidateSelectionError("allowed_substrate_kinds must not be empty")
        if not all(
            isinstance(kind, SubstrateKind) for kind in self.allowed_substrate_kinds
        ):
            raise CandidateSelectionError(
                "allowed_substrate_kinds must contain only SubstrateKind values"
            )
        if len(set(self.allowed_substrate_kinds)) != len(self.allowed_substrate_kinds):
            raise CandidateSelectionError(
                "allowed_substrate_kinds must not contain duplicates"
            )
        _require_tokens(
            self.allowed_network_requirements,
            field_name="allowed_network_requirements",
            allow_empty=True,
        )
        _require_tokens(
            self.satisfied_authorization_requirements,
            field_name="satisfied_authorization_requirements",
            allow_empty=True,
        )
        _require_tokens(
            self.deterministic_profiles,
            field_name="deterministic_profiles",
            allow_empty=True,
        )
        if not isinstance(self.allow_degraded, bool):
            raise CandidateSelectionError("allow_degraded must be a bool")
        if (
            not isinstance(self.max_selected_substrates, int)
            or isinstance(self.max_selected_substrates, bool)
            or self.max_selected_substrates <= 0
        ):
            raise CandidateSelectionError(
                "max_selected_substrates must be a positive integer"
            )
        if self.explainability_profile is not None:
            _require_token(
                self.explainability_profile,
                field_name="explainability_profile",
            )


@dataclass(frozen=True, slots=True)
class CandidateEvaluation:
    """Record deterministic eligibility for one validated substrate."""

    substrate_id: SubstrateId
    eligible: bool
    rejection_reasons: tuple[CandidateRejectionReason, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.substrate_id, SubstrateId):
            raise CandidateSelectionError("substrate_id must be a SubstrateId")
        if not isinstance(self.eligible, bool):
            raise CandidateSelectionError("eligible must be a bool")
        if not isinstance(self.rejection_reasons, tuple):
            raise CandidateSelectionError("rejection_reasons must be a tuple")
        if not all(
            isinstance(reason, CandidateRejectionReason)
            for reason in self.rejection_reasons
        ):
            raise CandidateSelectionError(
                "rejection_reasons must contain only CandidateRejectionReason values"
            )
        if len(set(self.rejection_reasons)) != len(self.rejection_reasons):
            raise CandidateSelectionError(
                "rejection_reasons must not contain duplicates"
            )
        if self.eligible == bool(self.rejection_reasons):
            raise CandidateSelectionError(
                "eligible must be true exactly when rejection_reasons is empty"
            )


@dataclass(frozen=True, slots=True)
class CandidateSelectionResult:
    """Store a deterministic candidate proposal without granting permission."""

    request_id: RequestId
    capability_snapshot_id: CapabilitySnapshotId
    policy: CandidateSelectionPolicy
    observed_at: datetime
    evaluations: tuple[CandidateEvaluation, ...]
    selected_substrates: tuple[SubstrateId, ...]
    reason_codes: tuple[RoutingDecisionReasonCode, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, RequestId):
            raise CandidateSelectionError("request_id must be a RequestId")
        if not isinstance(self.capability_snapshot_id, CapabilitySnapshotId):
            raise CandidateSelectionError(
                "capability_snapshot_id must be a CapabilitySnapshotId"
            )
        if not isinstance(self.policy, CandidateSelectionPolicy):
            raise CandidateSelectionError("policy must be a CandidateSelectionPolicy")
        _require_utc_datetime(self.observed_at, field_name="observed_at")
        if not isinstance(self.evaluations, tuple):
            raise CandidateSelectionError("evaluations must be a tuple")
        if not all(isinstance(item, CandidateEvaluation) for item in self.evaluations):
            raise CandidateSelectionError(
                "evaluations must contain only CandidateEvaluation values"
            )
        evaluation_ids = tuple(item.substrate_id for item in self.evaluations)
        if len(set(evaluation_ids)) != len(evaluation_ids):
            raise CandidateSelectionError("evaluations must not contain duplicate IDs")
        if evaluation_ids != tuple(
            sorted(evaluation_ids, key=lambda item: item.value)
        ):
            raise CandidateSelectionError("evaluations must be sorted by substrate_id")
        if not isinstance(self.selected_substrates, tuple):
            raise CandidateSelectionError("selected_substrates must be a tuple")
        if not all(
            isinstance(item, SubstrateId) for item in self.selected_substrates
        ):
            raise CandidateSelectionError(
                "selected_substrates must contain only SubstrateId values"
            )
        if len(set(self.selected_substrates)) != len(self.selected_substrates):
            raise CandidateSelectionError(
                "selected_substrates must not contain duplicates"
            )
        if len(self.selected_substrates) > self.policy.max_selected_substrates:
            raise CandidateSelectionError(
                "selected_substrates exceeds max_selected_substrates"
            )
        eligible_ids = {
            item.substrate_id for item in self.evaluations if item.eligible
        }
        if not set(self.selected_substrates).issubset(eligible_ids):
            raise CandidateSelectionError(
                "selected_substrates must contain only eligible substrates"
            )
        if not isinstance(self.reason_codes, tuple):
            raise CandidateSelectionError("reason_codes must be a tuple")
        if not all(
            isinstance(code, RoutingDecisionReasonCode) for code in self.reason_codes
        ):
            raise CandidateSelectionError(
                "reason_codes must contain only RoutingDecisionReasonCode values"
            )
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise CandidateSelectionError("reason_codes must not contain duplicates")
        has_capability_match = RoutingDecisionReasonCode.CAPABILITY_MATCH in self.reason_codes
        if has_capability_match != bool(self.selected_substrates):
            raise CandidateSelectionError(
                "CAPABILITY_MATCH must be present exactly when candidates are selected"
            )


def _append_unique(
    reasons: list[CandidateRejectionReason],
    reason: CandidateRejectionReason,
) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _evaluate_candidate(
    request: BrainRequest,
    policy: CandidateSelectionPolicy,
    substrate: ValidatedSubstrate,
    *,
    observed_at: datetime,
) -> CandidateEvaluation:
    descriptor = substrate.descriptor
    validation = substrate.validation
    reasons: list[CandidateRejectionReason] = []

    if observed_at < validation.validated_at:
        reasons.append(CandidateRejectionReason.VALIDATION_NOT_YET_VALID)
    if observed_at >= validation.valid_until:
        reasons.append(CandidateRejectionReason.VALIDATION_STALE)
    if not set(policy.required_capabilities).issubset(descriptor.capabilities):
        reasons.append(CandidateRejectionReason.CAPABILITY_MISMATCH)
    if descriptor.substrate_kind not in policy.allowed_substrate_kinds:
        reasons.append(CandidateRejectionReason.SUBSTRATE_KIND_RESTRICTED)

    availability = descriptor.availability_state
    if availability is SubstrateAvailabilityState.DEGRADED and not policy.allow_degraded:
        reasons.append(CandidateRejectionReason.DEGRADED_NOT_ALLOWED)
    elif availability is SubstrateAvailabilityState.UNAVAILABLE:
        reasons.append(CandidateRejectionReason.UNAVAILABLE)
    elif availability is SubstrateAvailabilityState.REVOKED:
        reasons.append(CandidateRejectionReason.REVOKED)
    elif availability is SubstrateAvailabilityState.INCOMPATIBLE:
        reasons.append(CandidateRejectionReason.INCOMPATIBLE)

    if request.security_binding.offline_required and not descriptor.offline_capable:
        reasons.append(CandidateRejectionReason.OFFLINE_UNSUPPORTED)
    if not set(descriptor.network_requirements).issubset(
        policy.allowed_network_requirements
    ):
        reasons.append(CandidateRejectionReason.NETWORK_POLICY_RESTRICTION)
    if (
        request.security_binding.effective_data_classification
        not in descriptor.data_handling_profile
    ):
        reasons.append(CandidateRejectionReason.DATA_CLASSIFICATION_RESTRICTION)
    if not set(descriptor.authorization_requirements).issubset(
        policy.satisfied_authorization_requirements
    ):
        reasons.append(
            CandidateRejectionReason.AUTHORIZATION_REQUIREMENT_UNSATISFIED
        )

    resources = descriptor.resource_profile
    if resources.min_compute_units > request.max_compute_units:
        reasons.append(CandidateRejectionReason.COMPUTE_BUDGET_EXCEEDED)
    if resources.min_memory_bytes > request.max_memory_bytes:
        reasons.append(CandidateRejectionReason.MEMORY_BUDGET_EXCEEDED)
    if resources.max_latency_ms is None:
        reasons.append(CandidateRejectionReason.LATENCY_BUDGET_UNPROVEN)
    elif resources.max_latency_ms > request.max_latency_ms:
        reasons.append(CandidateRejectionReason.LATENCY_BUDGET_EXCEEDED)

    if (
        request.required_determinism
        and descriptor.determinism_profile not in policy.deterministic_profiles
    ):
        reasons.append(CandidateRejectionReason.DETERMINISM_UNSUPPORTED)
    if not set(request.verification_requirements).issubset(
        descriptor.verification_profile
    ):
        reasons.append(
            CandidateRejectionReason.VERIFICATION_REQUIREMENT_UNSUPPORTED
        )
    if request.required_explainability:
        profile = policy.explainability_profile
        if profile is None or profile not in descriptor.verification_profile:
            reasons.append(CandidateRejectionReason.EXPLAINABILITY_UNSUPPORTED)
    if request.required_accuracy is not None:
        reasons.append(CandidateRejectionReason.ACCURACY_REQUIREMENT_UNSUPPORTED)

    return CandidateEvaluation(
        substrate_id=descriptor.substrate_id,
        eligible=not reasons,
        rejection_reasons=tuple(reasons),
    )


def _rank_key(substrate: ValidatedSubstrate) -> tuple[int, int, int, int, str]:
    descriptor = substrate.descriptor
    resources = descriptor.resource_profile
    latency = resources.max_latency_ms
    if latency is None:
        raise CandidateSelectionError(
            "eligible candidate cannot have an unbounded latency profile"
        )
    availability_penalty = int(
        descriptor.availability_state is SubstrateAvailabilityState.DEGRADED
    )
    return (
        availability_penalty,
        resources.min_compute_units,
        resources.min_memory_bytes,
        latency,
        descriptor.substrate_id.value,
    )


def _reason_codes(
    request: BrainRequest,
    evaluations: tuple[CandidateEvaluation, ...],
    selected: tuple[SubstrateId, ...],
) -> tuple[RoutingDecisionReasonCode, ...]:
    codes: list[RoutingDecisionReasonCode] = []
    rejected = {
        reason for evaluation in evaluations for reason in evaluation.rejection_reasons
    }
    if selected:
        codes.append(RoutingDecisionReasonCode.CAPABILITY_MATCH)
    if request.security_binding.offline_required:
        codes.append(RoutingDecisionReasonCode.OFFLINE_REQUIRED)
    if request.required_determinism:
        codes.append(RoutingDecisionReasonCode.DETERMINISTIC_ROUTE_REQUIRED)
    if rejected & {
        CandidateRejectionReason.SUBSTRATE_KIND_RESTRICTED,
        CandidateRejectionReason.NETWORK_POLICY_RESTRICTION,
        CandidateRejectionReason.AUTHORIZATION_REQUIREMENT_UNSATISFIED,
    }:
        codes.append(RoutingDecisionReasonCode.SECURITY_POLICY_RESTRICTION)
    if CandidateRejectionReason.DATA_CLASSIFICATION_RESTRICTION in rejected:
        codes.append(RoutingDecisionReasonCode.DATA_CLASSIFICATION_RESTRICTION)
    if len([item for item in evaluations if item.eligible]) > 1 and selected:
        codes.append(RoutingDecisionReasonCode.LOWER_RESOURCE_ROUTE_SUFFICIENT)
    if request.verification_requirements or request.required_explainability:
        codes.append(RoutingDecisionReasonCode.VERIFICATION_ESCALATION)
    if request.deadline is not None:
        codes.append(RoutingDecisionReasonCode.DEADLINE_RESTRICTION)
    return tuple(codes)


def select_candidate_substrates(
    request: BrainRequest,
    snapshot: CapabilitySnapshot,
    policy: CandidateSelectionPolicy,
    *,
    current_binding: RoutingSecurityBinding,
    observed_at: datetime,
) -> CandidateSelectionResult:
    """Filter and rank validated substrates deterministically.

    The result is a routing proposal only. It does not authenticate policy input,
    grant authorization, execute a substrate, or permit a side effect.
    """
    if not isinstance(request, BrainRequest):
        raise CandidateSelectionError("request must be a BrainRequest")
    if not isinstance(snapshot, CapabilitySnapshot):
        raise CandidateSelectionError("snapshot must be a CapabilitySnapshot")
    if not isinstance(policy, CandidateSelectionPolicy):
        raise CandidateSelectionError("policy must be a CandidateSelectionPolicy")
    if not isinstance(current_binding, RoutingSecurityBinding):
        raise CandidateSelectionError(
            "current_binding must be a RoutingSecurityBinding"
        )
    now = _require_utc_datetime(observed_at, field_name="observed_at")

    if current_binding != request.security_binding:
        raise CandidateSelectionError(
            "current_binding must match the request's admitted security binding"
        )
    if snapshot.snapshot_id != current_binding.capability_snapshot_id:
        raise CandidateSelectionError(
            "capability snapshot does not match the current security binding"
        )
    if snapshot.created_at > now:
        raise CandidateSelectionError("capability snapshot is not yet valid")
    if policy.security_policy_revision_id != current_binding.security_policy_revision_id:
        raise CandidateSelectionError(
            "candidate policy security revision does not match current binding"
        )
    if policy.authorization_context_id != current_binding.authorization_context_id:
        raise CandidateSelectionError(
            "candidate policy authorization context does not match current binding"
        )
    if policy.provider_network_policy != current_binding.provider_network_policy:
        raise CandidateSelectionError(
            "candidate policy provider/network class does not match current binding"
        )
    if request.deadline is not None and now >= request.deadline:
        raise CandidateSelectionError("request deadline has been reached")

    evaluations = tuple(
        _evaluate_candidate(request, policy, substrate, observed_at=now)
        for substrate in snapshot.substrates
    )
    by_id = {
        substrate.descriptor.substrate_id: substrate for substrate in snapshot.substrates
    }
    eligible = [
        by_id[evaluation.substrate_id]
        for evaluation in evaluations
        if evaluation.eligible
    ]
    eligible.sort(key=_rank_key)
    selected = tuple(
        substrate.descriptor.substrate_id
        for substrate in eligible[: policy.max_selected_substrates]
    )

    return CandidateSelectionResult(
        request_id=request.request_id,
        capability_snapshot_id=snapshot.snapshot_id,
        policy=policy,
        observed_at=now,
        evaluations=evaluations,
        selected_substrates=selected,
        reason_codes=_reason_codes(request, evaluations, selected),
    )
