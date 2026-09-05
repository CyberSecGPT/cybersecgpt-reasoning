"""Immutable P5 reasoning budgets and monotonic consumption accounting."""

from dataclasses import dataclass
from enum import StrEnum

from .errors import ReasoningBudgetError

__all__ = [
    "ReasoningBudget",
    "ReasoningBudgetDelta",
    "ReasoningBudgetDimension",
    "ReasoningBudgetExceededError",
    "ReasoningBudgetUsage",
    "consume_reasoning_budget",
    "exhausted_reasoning_budget_dimensions",
]


class ReasoningBudgetDimension(StrEnum):
    """Machine-evaluable budget dimensions enforced by this P5 slice."""

    CANDIDATES = "CANDIDATES"
    BRANCH_DEPTH = "BRANCH_DEPTH"
    STEPS = "STEPS"
    MODEL_TOKENS = "MODEL_TOKENS"
    TOOL_CALLS = "TOOL_CALLS"
    RETRIEVAL_CALLS = "RETRIEVAL_CALLS"
    VERIFIER_PASSES = "VERIFIER_PASSES"


class ReasoningBudgetExceededError(ReasoningBudgetError):
    """Report a fail-closed attempt to consume beyond one or more ceilings."""

    def __init__(self, dimensions: tuple[ReasoningBudgetDimension, ...]) -> None:
        self.dimensions = dimensions
        names = ", ".join(dimension.value for dimension in dimensions)
        super().__init__(f"reasoning budget exceeded: {names}")


def _require_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ReasoningBudgetError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise ReasoningBudgetError(
            f"{field_name} must be non-empty and have no surrounding whitespace"
        )
    return value


def _require_non_negative_int(value: object, *, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise ReasoningBudgetError(f"{field_name} must be a non-negative integer")
    return value


def _require_stop_conditions(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise ReasoningBudgetError("stop_conditions must be a tuple")
    conditions = tuple(
        _require_text(condition, field_name="stop_conditions item")
        for condition in value
    )
    if len(set(conditions)) != len(conditions):
        raise ReasoningBudgetError("stop_conditions must not contain duplicates")
    return conditions


@dataclass(frozen=True, slots=True)
class ReasoningBudget:
    """Define immutable ceilings for one admitted reasoning-control profile.

    The object is control metadata, not authorization. A caller that needs larger
    ceilings must obtain a freshly admitted routing/authorization decision rather
    than mutating this value or reusing an existing usage ledger.
    """

    policy_name: str
    max_candidates: int
    max_branch_depth: int
    max_steps: int
    max_model_tokens: int
    max_tool_calls: int
    max_retrieval_calls: int
    max_verifier_passes: int
    stop_conditions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.policy_name, field_name="policy_name")
        for field_name in _COUNTER_FIELDS:
            _require_non_negative_int(getattr(self, f"max_{field_name}"), field_name=f"max_{field_name}")
        _require_stop_conditions(self.stop_conditions)


@dataclass(frozen=True, slots=True)
class ReasoningBudgetDelta:
    """Describe one monotonic increment to controller-accounted usage."""

    candidates: int = 0
    branch_depth: int = 0
    steps: int = 0
    model_tokens: int = 0
    tool_calls: int = 0
    retrieval_calls: int = 0
    verifier_passes: int = 0

    def __post_init__(self) -> None:
        for field_name in _COUNTER_FIELDS:
            _require_non_negative_int(getattr(self, field_name), field_name=field_name)


@dataclass(frozen=True, slots=True)
class ReasoningBudgetUsage:
    """Store immutable monotonic usage against one immutable budget."""

    budget: ReasoningBudget
    candidates: int = 0
    branch_depth: int = 0
    steps: int = 0
    model_tokens: int = 0
    tool_calls: int = 0
    retrieval_calls: int = 0
    verifier_passes: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.budget, ReasoningBudget):
            raise ReasoningBudgetError("budget must be a ReasoningBudget")
        for field_name in _COUNTER_FIELDS:
            _require_non_negative_int(getattr(self, field_name), field_name=field_name)
        exceeded = _exceeded_dimensions(self.budget, self)
        if exceeded:
            names = ", ".join(dimension.value for dimension in exceeded)
            raise ReasoningBudgetError(f"usage exceeds budget: {names}")


_COUNTER_DIMENSIONS: tuple[tuple[str, ReasoningBudgetDimension], ...] = (
    ("candidates", ReasoningBudgetDimension.CANDIDATES),
    ("branch_depth", ReasoningBudgetDimension.BRANCH_DEPTH),
    ("steps", ReasoningBudgetDimension.STEPS),
    ("model_tokens", ReasoningBudgetDimension.MODEL_TOKENS),
    ("tool_calls", ReasoningBudgetDimension.TOOL_CALLS),
    ("retrieval_calls", ReasoningBudgetDimension.RETRIEVAL_CALLS),
    ("verifier_passes", ReasoningBudgetDimension.VERIFIER_PASSES),
)
_COUNTER_FIELDS = tuple(field_name for field_name, _ in _COUNTER_DIMENSIONS)


def _exceeded_dimensions(
    budget: ReasoningBudget,
    usage: ReasoningBudgetUsage,
) -> tuple[ReasoningBudgetDimension, ...]:
    return tuple(
        dimension
        for field_name, dimension in _COUNTER_DIMENSIONS
        if getattr(usage, field_name) > getattr(budget, f"max_{field_name}")
    )


def exhausted_reasoning_budget_dimensions(
    usage: ReasoningBudgetUsage,
) -> tuple[ReasoningBudgetDimension, ...]:
    """Return ceilings exactly reached by the current immutable usage snapshot."""
    if not isinstance(usage, ReasoningBudgetUsage):
        raise ReasoningBudgetError("usage must be a ReasoningBudgetUsage")
    return tuple(
        dimension
        for field_name, dimension in _COUNTER_DIMENSIONS
        if getattr(usage, field_name) == getattr(usage.budget, f"max_{field_name}")
    )


def consume_reasoning_budget(
    usage: ReasoningBudgetUsage,
    delta: ReasoningBudgetDelta,
) -> ReasoningBudgetUsage:
    """Apply one bounded monotonic consumption increment and fail closed on excess.

    Candidate, step, token, tool, retrieval, and verifier counters are additive.
    Branch depth is a monotonic high-water mark and therefore never decreases.
    """
    if not isinstance(usage, ReasoningBudgetUsage):
        raise ReasoningBudgetError("usage must be a ReasoningBudgetUsage")
    if not isinstance(delta, ReasoningBudgetDelta):
        raise ReasoningBudgetError("delta must be a ReasoningBudgetDelta")

    values = {
        field_name: getattr(usage, field_name) + getattr(delta, field_name)
        for field_name in _COUNTER_FIELDS
    }
    values["branch_depth"] = max(usage.branch_depth, delta.branch_depth)

    exceeded = tuple(
        dimension
        for field_name, dimension in _COUNTER_DIMENSIONS
        if values[field_name] > getattr(usage.budget, f"max_{field_name}")
    )
    if exceeded:
        raise ReasoningBudgetExceededError(exceeded)

    return ReasoningBudgetUsage(budget=usage.budget, **values)
