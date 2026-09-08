"""Close the final fallback reason-code coverage branches."""

import cybersecgpt.reasoning.fallback as fallback_module

from .test_fallback import run_replan


def _selection_with_reason_codes(
    reason_codes: tuple[fallback_module.RoutingDecisionReasonCode, ...],
) -> fallback_module.CandidateSelectionResult:
    base = run_replan().candidate_selection
    return fallback_module.CandidateSelectionResult(
        request_id=base.request_id,
        capability_snapshot_id=base.capability_snapshot_id,
        policy=base.policy,
        observed_at=base.observed_at,
        evaluations=base.evaluations,
        selected_substrates=base.selected_substrates,
        reason_codes=reason_codes,
    )


def test_selected_fallback_adds_capability_match_reason() -> None:
    base = _selection_with_reason_codes(())
    selected = fallback_module._with_fallback_selection(
        base,
        base.selected_substrates,
    )

    assert fallback_module.RoutingDecisionReasonCode.CAPABILITY_MATCH in (
        selected.reason_codes
    )


def test_empty_fallback_selection_removes_capability_match_reason() -> None:
    capability_match = fallback_module.RoutingDecisionReasonCode.CAPABILITY_MATCH
    base = _selection_with_reason_codes((capability_match,))

    exhausted = fallback_module._with_fallback_selection(base, ())

    assert capability_match not in exhausted.reason_codes
