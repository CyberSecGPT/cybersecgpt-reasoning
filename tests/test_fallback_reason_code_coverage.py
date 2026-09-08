"""Close the final fallback reason-code coverage branches."""

import cybersecgpt.reasoning.fallback as fallback_module

from .test_fallback import run_replan


def test_selected_fallback_repairs_missing_capability_match_reason() -> None:
    base = run_replan().candidate_selection
    capability_match = fallback_module.RoutingDecisionReasonCode.CAPABILITY_MATCH
    assert capability_match in base.reason_codes

    object.__setattr__(
        base,
        "reason_codes",
        tuple(code for code in base.reason_codes if code is not capability_match),
    )

    repaired = fallback_module._with_fallback_selection(
        base,
        base.selected_substrates,
    )

    assert capability_match in repaired.reason_codes


def test_empty_fallback_selection_removes_capability_match_reason() -> None:
    base = run_replan().candidate_selection
    capability_match = fallback_module.RoutingDecisionReasonCode.CAPABILITY_MATCH
    assert capability_match in base.reason_codes

    exhausted = fallback_module._with_fallback_selection(base, ())

    assert capability_match not in exhausted.reason_codes
