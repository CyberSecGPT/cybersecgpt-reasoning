"""Close the final fallback reason-code coverage branch."""

import cybersecgpt.reasoning.fallback as fallback_module

from .test_fallback import run_replan


def test_empty_fallback_selection_removes_capability_match_reason() -> None:
    base = run_replan().candidate_selection
    capability_match = fallback_module.RoutingDecisionReasonCode.CAPABILITY_MATCH
    seeded = fallback_module.CandidateSelectionResult(
        request_id=base.request_id,
        capability_snapshot_id=base.capability_snapshot_id,
        policy=base.policy,
        observed_at=base.observed_at,
        evaluations=base.evaluations,
        selected_substrates=base.selected_substrates,
        reason_codes=(capability_match,),
    )

    exhausted = fallback_module._with_fallback_selection(seeded, ())

    assert capability_match not in exhausted.reason_codes
