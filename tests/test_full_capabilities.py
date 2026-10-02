import json

from bench.full_capabilities import recover_json, cohort_score, stage_state, composition_score


def test_reparse_trailing_commas_preserves_string_content():
    raw = 'prose ```json\n{"findings": [{"title":"literal ,} text",}],}\n```'
    result, method = recover_json(raw)
    assert json.loads(result) == {"findings": [{"title": "literal ,} text"}]}
    assert method == "trailing_comma_reparse"


def test_truncated_json_is_not_invented_as_empty_findings():
    assert recover_json('{"findings": [{"title": "attack"')[0] is None


def test_failed_analysis_is_excluded_but_attempted_yield_remains_visible():
    rows = [
        {"complete": True, "detected": True},
        {"complete": True, "detected": False},
        {"complete": False, "detected": True},
    ]
    score = cohort_score(rows)
    assert score["completed"] == 2
    assert score["excluded"] == 1
    assert score["flagged"] == 1
    assert score["completed_rate"] == 0.5
    assert score["attempted_yield"] == 1 / 3


def test_no_trigger_is_not_executed_and_is_inapplicable():
    assert stage_state({"stage": "detonation", "ok": True,
                        "metrics": {"skipped": "no runnable triggers found; target not executed"}}) == "not_applicable"
    assert stage_state({"stage": "reputation", "ok": True,
                        "metrics": {"skipped": "no TAVILY_API_KEY; reputation offline"}}) == "unavailable"


def test_omitted_semantic_content_is_excluded():
    assert stage_state({"stage": "semantic", "ok": True,
                        "metrics": {"coverage_incomplete": "cap omitted units"}}) == "partial"


def test_composition_control_not_scored_as_malicious_for_member_warning():
    findings = [{"title": "some member warning", "severity": "high", "stage": "semantic"}]
    assert composition_score(findings, {"trifecta": False, "shadowing": False}) == {
        "trifecta": False, "shadowing": False, "matches_expected": True, "detected": False}
