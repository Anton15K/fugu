import importlib
import importlib.util


def charts():
    assert importlib.util.find_spec("bench.current_limits_charts"), "Current-profile charts are missing"
    return importlib.import_module("bench.current_limits_charts")


def test_pair_excludes_same_incomplete_ids_for_each_historical_tool():
    mod = charts()
    cases = [{"id": "a", "cohort": "mcptox", "kind": "malicious"},
             {"id": "b", "cohort": "mcptox", "kind": "malicious"},
             {"id": "c", "cohort": "clean_descriptions", "kind": "benign"}]
    fresh = {"rows": [{**cases[0], "complete": True, "detected": True, "status": "completed"},
                      {**cases[1], "complete": False, "detected": True, "status": "partial"},
                      {**cases[2], "complete": True, "detected": False, "status": "completed"}]}
    historical = {"version": "pinned", "results": [
        {"id": c["id"], "status": "completed", "flagged_medium": c["id"] == "b",
         "flagged_native": c["kind"] == "malicious"} for c in cases]}
    data = mod.comparison_data(fresh, {"cases": cases}, {"fuzzd": historical, "mcp-sec-audit": historical})
    assert data["paired_attack_ids"] == ["a"]
    assert data["excluded_ids"] == ["b"]
    assert data["paired"]["fuzzd"]["attack_medium_positive"] == 0
    assert data["primary"]["fugu"]["planned_attacks"] == 2
    assert data["primary"]["fugu"]["attack_detected"] == 1
    assert data["primary"]["fugu"]["attack_incomplete"] == 1
    assert data["primary"]["fugu"]["attack_planned_rate"] == 0.5
    assert data["primary"]["fuzzd"]["execution"] == "historical"


def test_unsupported_tool_is_unavailable_and_unknown_cost_remains_null():
    mod = charts()
    case = {"id": "a", "cohort": "mcptox", "kind": "malicious"}
    fresh = {"rows": [{**case, "complete": True, "detected": False, "status": "completed"}],
             "usage": {"attempts": 1, "prompt_tokens_total": None,
                       "completion_tokens_total": None, "unknown_usage_calls": 1}}
    tool = {"results": [{"id": "a", "status": "unsupported"}]}
    data = mod.chart_data(fresh, {"cases": [case]}, {"fuzzd": tool, "mcp-sec-audit": tool})
    assert data["comparison"]["primary"]["fuzzd"]["attack_medium_rate"] is None
    assert data["comparison"]["primary"]["fuzzd"]["unavailable_attack_ids"] == ["a"]
    assert data["cost"] is None
    assert data["usage"]["prompt_tokens_total"] is None


def test_benign_flags_and_pending_adjudication_are_distinct():
    mod = charts()
    cases = [{"id": "clean", "cohort": "clean_descriptions", "kind": "benign"}]
    fresh = {"rows": [{**cases[0], "complete": True, "status": "completed", "detected": True,
                       "adjudicated_false_positive": None}]}
    data = mod.comparison_data(fresh, {"cases": cases}, {})
    fugu = data["primary"]["fugu"]
    assert fugu["raw_benign_flags"] == 1
    assert fugu["confirmed_false_positives"] == 0
    assert fugu["pending_adjudication"] == 1


def test_missing_coverage_is_not_zero_omission_and_synthetic_scope_stays_visible():
    mod = charts()
    case = {"id": "a", "cohort": "mcptox", "kind": "malicious"}
    fresh = {"synthetic": True, "rows": [{**case, "complete": False, "detected": None,
                                          "status": "unattempted"}], "coverage": {"semantic": {
        "omitted_chars": {"total": None, "known_subtotal": 0, "unknown_audits": 1}}}}
    data = mod.chart_data(fresh, {"cases": [case]}, {})
    assert data["synthetic"] is True
    assert data["coverage"]["semantic"]["omitted_chars"]["total"] is None
    assert data["comparison"]["primary"]["fugu"]["execution"] == "synthetic offline fixture"
    assert data["historical_telemetry"]["execution"] == "historical"


def test_historical_telemetry_sums_retained_sdk_records_without_claiming_fresh_calls(tmp_path):
    mod = charts()
    from bench.current_limits import write_json
    for folder, number, usage in [("calls", 1, {"prompt_tokens": 10, "completion_tokens": 2}),
                                   ("recovery/calls", 1, {"prompt_tokens": 10, "completion_tokens": None})]:
        write_json(tmp_path / folder / f"{number:05d}.json", {"number": number,
            "requested_model": "synthetic-model", "max_tokens": 4096, "model": "synthetic-served",
            "finish_reason": "stop", "raw_response": "nonempty", "usage": usage,
            "duration_s": 2, "parse_valid": True, "structured_retry_index": 0})
    write_json(tmp_path / "fugu.json", {"rows": [{"complete": False}]})
    write_json(tmp_path / "fugu-recovered.json", {"rows": [{"complete": True}], "recovery": {}})
    result = mod.historical_telemetry(tmp_path)
    assert result["execution"] == "historical"
    assert result["usage"]["attempts"] == 2
    assert result["usage"]["prompt_tokens_total"] == 20
    assert result["usage"]["completion_tokens_total"] is None
    assert result["usage"]["unknown_usage_calls"] == 1
    assert result["initial_full_capability_completed"] == 0
    assert result["recovered_full_capability_completed"] == 1
    assert len(result["source_sha256"]) == 4
    write_json(tmp_path / "cases.json", {"cases": [{"id": "a", "input_sha256": {"tool.txt": "inert-hash"}}]})
    write_json(tmp_path / "harness-mount-bounds.json", {"rows": [{"context": "a",
        "content_omitted_by_mount_budget": 0, "mounted_packet_chars": 20,
        "targeted_probe_packet_char_limit": 2500}]})
    exposed = mod.historical_telemetry(tmp_path)
    assert len(exposed["source_sha256"]) == 6
    assert "calls/00001.json" in exposed["source_sha256"]
    assert exposed["exposure"]["unique_inputs"] == 1
