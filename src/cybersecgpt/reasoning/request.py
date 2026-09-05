"""Normalized P5 Native Brain request admission contracts."""

from dataclasses import dataclass
from datetime import datetime, timedelta
import re

from cybersecgpt.foundation import (
    CorrelationId,
    FoundationError,
    RequestId,
    RoutingSecurityBinding,
    from_json,
    to_json,
)

from .budget import ReasoningBudget
from .errors import BrainRequestError

__all__ = ["BrainRequest", "admit_brain_request"]

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _require_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise BrainRequestError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise BrainRequestError(
            f"{field_name} must be non-empty and have no surrounding whitespace"
        )
    return value


def _require_token(value: object, *, field_name: str) -> str:
    text = _require_text(value, field_name=field_name)
    if _TOKEN_PATTERN.fullmatch(text) is None:
        raise BrainRequestError(
            f"{field_name} must be a machine-evaluable token of at most 128 characters"
        )
    return text


def _require_non_negative_int(value: object, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise BrainRequestError(f"{field_name} must be a non-negative integer")
    return value


def _require_utc_datetime(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise BrainRequestError(f"{field_name} must be a datetime")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise BrainRequestError(f"{field_name} must be timezone-aware UTC")
    return value


def _require_optional_text(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, field_name=field_name)


def _require_accuracy(value: object) -> float | None:
    if value is None:
        return None
    if not isinstance(value, float):
        raise BrainRequestError("required_accuracy must be a float or None")
    if not 0.0 <= value <= 1.0:
        raise BrainRequestError("required_accuracy must be between 0.0 and 1.0")
    return value


def _require_verification_requirements(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise BrainRequestError("verification_requirements must be a tuple")
    requirements = tuple(
        _require_token(item, field_name="verification_requirements item")
        for item in value
    )
    if len(set(requirements)) != len(requirements):
        raise BrainRequestError("verification_requirements must not contain duplicates")
    return requirements


def _canonicalize_input(value: object) -> str:
    try:
        return to_json(value, indent=None)
    except FoundationError as exc:
        raise BrainRequestError(
            "input must be JSON-compatible and within Foundation safety bounds"
        ) from exc


def _require_canonical_input_json(value: object) -> str:
    if not isinstance(value, str):
        raise BrainRequestError("input_json must be a string")
    try:
        decoded = from_json(value)
        canonical = to_json(decoded, indent=None)
    except FoundationError as exc:
        raise BrainRequestError(
            "input_json must be valid JSON within Foundation safety bounds"
        ) from exc
    if canonical != value:
        raise BrainRequestError("input_json must use canonical Foundation JSON encoding")
    return value


@dataclass(frozen=True, slots=True)
class BrainRequest:
    """Store one immutable normalized request ready for routing consideration.

    The request carries authoritative security-binding references but performs no
    authorization or effective-classification policy evaluation. Source-provided
    classification remains separate untrusted metadata.
    """

    request_id: RequestId
    correlation_id: CorrelationId
    security_binding: RoutingSecurityBinding
    task_type: str
    domain: str
    task_complexity: str
    safety_impact: str
    source_data_classification: str | None
    identity_context_ref: str | None
    max_latency_ms: int
    max_compute_units: int
    max_memory_bytes: int
    reasoning_budget: ReasoningBudget
    required_accuracy: float | None
    required_determinism: bool
    required_explainability: bool
    verification_requirements: tuple[str, ...]
    admitted_at: datetime
    deadline: datetime | None
    input_json: str

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, RequestId):
            raise BrainRequestError("request_id must be a RequestId")
        if not isinstance(self.correlation_id, CorrelationId):
            raise BrainRequestError("correlation_id must be a CorrelationId")
        if not isinstance(self.security_binding, RoutingSecurityBinding):
            raise BrainRequestError(
                "security_binding must be a RoutingSecurityBinding"
            )
        if self.security_binding.request_id != self.request_id:
            raise BrainRequestError(
                "security_binding request_id must match request_id"
            )

        _require_token(self.task_type, field_name="task_type")
        _require_token(self.domain, field_name="domain")
        _require_token(self.task_complexity, field_name="task_complexity")
        _require_token(self.safety_impact, field_name="safety_impact")
        _require_optional_text(
            self.source_data_classification,
            field_name="source_data_classification",
        )
        _require_optional_text(
            self.identity_context_ref,
            field_name="identity_context_ref",
        )
        _require_non_negative_int(self.max_latency_ms, field_name="max_latency_ms")
        _require_non_negative_int(
            self.max_compute_units,
            field_name="max_compute_units",
        )
        _require_non_negative_int(
            self.max_memory_bytes,
            field_name="max_memory_bytes",
        )

        if not isinstance(self.reasoning_budget, ReasoningBudget):
            raise BrainRequestError("reasoning_budget must be a ReasoningBudget")
        _require_accuracy(self.required_accuracy)
        if not isinstance(self.required_determinism, bool):
            raise BrainRequestError("required_determinism must be a bool")
        if not isinstance(self.required_explainability, bool):
            raise BrainRequestError("required_explainability must be a bool")
        _require_verification_requirements(self.verification_requirements)

        admitted_at = _require_utc_datetime(
            self.admitted_at,
            field_name="admitted_at",
        )
        if self.deadline is not None:
            deadline = _require_utc_datetime(self.deadline, field_name="deadline")
            if deadline <= admitted_at:
                raise BrainRequestError("deadline must be later than admitted_at")

        _require_canonical_input_json(self.input_json)


def admit_brain_request(
    *,
    request_id: RequestId,
    correlation_id: CorrelationId,
    security_binding: RoutingSecurityBinding,
    task_type: str,
    domain: str,
    task_complexity: str,
    safety_impact: str,
    source_data_classification: str | None,
    identity_context_ref: str | None,
    max_latency_ms: int,
    max_compute_units: int,
    max_memory_bytes: int,
    reasoning_budget: ReasoningBudget,
    required_accuracy: float | None,
    required_determinism: bool,
    required_explainability: bool,
    verification_requirements: tuple[str, ...],
    admitted_at: datetime,
    deadline: datetime | None,
    input_value: object,
) -> BrainRequest:
    """Normalize bounded JSON input into an immutable request admission record."""
    return BrainRequest(
        request_id=request_id,
        correlation_id=correlation_id,
        security_binding=security_binding,
        task_type=task_type,
        domain=domain,
        task_complexity=task_complexity,
        safety_impact=safety_impact,
        source_data_classification=source_data_classification,
        identity_context_ref=identity_context_ref,
        max_latency_ms=max_latency_ms,
        max_compute_units=max_compute_units,
        max_memory_bytes=max_memory_bytes,
        reasoning_budget=reasoning_budget,
        required_accuracy=required_accuracy,
        required_determinism=required_determinism,
        required_explainability=required_explainability,
        verification_requirements=verification_requirements,
        admitted_at=admitted_at,
        deadline=deadline,
        input_json=_canonicalize_input(input_value),
    )
