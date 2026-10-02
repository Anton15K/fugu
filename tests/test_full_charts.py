from bench.full_charts import (
    DEFAULT_OUTPUT,
    DEFAULT_SOURCE,
    cohort_annotation,
    comparison_data,
    contribution_data,
)


def test_composition_chart_labels_detection_and_correctly_unflagged_controls():
    attack = {"cohort": "composition", "kind": "malicious", "flagged": 4, "completed": 4,
              "completed_rate": 1.0}
    control = {"cohort": "composition", "kind": "benign", "flagged": 0, "completed": 3,
               "completed_rate": 0.0}
    assert cohort_annotation(attack) == "4/4 detected"
    assert cohort_annotation(control) == "3/3 correctly unflagged · raw alerts 0/3"


def test_full_chart_default_output_is_separate_from_frozen_input():
    assert DEFAULT_OUTPUT != DEFAULT_SOURCE
    assert "2026-10-02-composition-v2" in str(DEFAULT_OUTPUT)


def test_paired_comparison_excludes_same_failed_cases_for_every_tool():
    cases = [{"id": "attack-a", "cohort": "mcptox", "kind": "malicious"},
             {"id": "attack-b", "cohort": "mcptox", "kind": "malicious"},
             {"id": "clean", "cohort": "clean_descriptions", "kind": "benign"}]
    fugu = {"rows": [{**cases[0], "complete": True, "detected": True},
                     {**cases[1], "complete": False, "detected": True},
                     {**cases[2], "complete": True, "detected": False}]}
    competitor = {"results": [{"id": c["id"], "status": "completed",
                              "flagged_medium": c["id"] == "attack-b",
                              "flagged_native": c["kind"] == "malicious"} for c in cases]}
    data = comparison_data(fugu, {"cases": cases}, {"fuzzd": competitor, "mcp-sec-audit": competitor})
    assert data["paired_attack_ids"] == ["attack-a"]
    assert data["excluded_ids"] == ["attack-b"]
    assert data["paired"]["fuzzd"]["attack_medium_positive"] == 0
    assert data["paired"]["fugu"]["attack_medium_positive"] == 1


def test_unsupported_competitor_is_not_scored_as_a_miss():
    case = {"id": "a", "cohort": "mcptox", "kind": "malicious"}
    fugu = {"rows": [{**case, "complete": True, "detected": True}]}
    unavailable = {"results": [{"id": "a", "status": "unsupported"}]}
    data = comparison_data(fugu, {"cases": [case]}, {"fuzzd": unavailable, "mcp-sec-audit": unavailable})
    assert data["paired_attack_ids"] == []
    assert data["paired"]["fuzzd"]["attack_medium_rate"] is None


def test_stage_alerts_do_not_count_info_or_partial_as_completed_detection():
    rows = [{"cohort":"crafted", "kind":"malicious", "stages":[
        {"stage":"static", "state":"completed", "findings":[{"severity":"info"}]},
        {"stage":"harness", "state":"partial", "findings":[{"severity":"critical"}]},
        {"stage":"detonation", "state":"not_applicable", "findings":[]},
    ]}]
    data = contribution_data(rows)
    assert data['crafted/malicious']['static'] == {'completed':1,'flagged':0,'rate':0.0}
    assert data['crafted/malicious']['harness'] == {'completed':0,'flagged':0,'rate':None}
    assert data['crafted/malicious']['detonation'] == {'completed':0,'flagged':0,'rate':None}
