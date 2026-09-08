"""Close the final fallback reason-code coverage branch."""

from cybersecgpt.reasoning import CandidateSelectionResult, RoutingDecisionReasonCode
from cybersecgpt.reasoning.fallback import _with_fallback_selection

from .test_fallback import run_replan


def test_empty_fallback_selection_removes_capability_match_reason() -> None:
    base = run_replan().candidate_selection
    capability_match = RoutingDecisionReasonCode.CAPABILITY_MATCH
    seeded = CandidateSelectionResult(
        request_id=base.request_id,
        capability_snapshot_id=base.capability_snapshot_id,
        policy=base.policy,
        observed_at=base.observed_at,
        evaluations=base.evaluations,
        selected_substrates=base.selected_substrates,
        reason_codes=(capability_match,)
        + tuple(code for code in base.reason_codes if code is not capability_match),
    )

    exhausted = _with_fallback_selection(seeded, ())

    assert capability_match not in exhausted.reason_codes
