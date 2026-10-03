import importlib
import importlib.util
import json
from pathlib import Path

import pytest


PARENT_RESULT_SHA256 = "708623e0fac256a4cb2810bdddc2875ba22a1ad3b16bbdb7ed39324821d3b987"
CHILD_RESULT_SHA256 = "1" * 64
PARENT_PLAN_SHA256 = "8f304c3da81e0db091da6e2c324c064d013129d63644b278079c4cf8ad9ef725"
PARENT_INVENTORY_SHA256 = "63240327fc6adf050b6cefbd0340f1fb6c16700c48551bc12548b071a057783e"
CASE_MANIFEST_SHA256 = "f9b31035908d217a822079dd190c4d5797f86646c65f01c2e06b1f57ae3e91b1"
REUSED_RUNNER_SHA256 = "2e69cd6654ec8158d3de968ad026c56d2e04179574c0667133cac8edadea002d"
ENGINE_COMMIT = "cc58a58d6cea861510980814ae2e70b7bdf24e63"
PROTOCOL = "current-production-source-inference-continuation-v1"


def charts():
    assert importlib.util.find_spec("bench.current_limits_continuation_charts"), \
        "Continuation charts are missing"
    return importlib.import_module("bench.current_limits_continuation_charts")


def synthetic_packet():
    cases = [{"id": case_id, "cohort": "mcptox", "kind": "malicious"} for case_id in (
        "mcptox/Email_14", "mcptox/Email_20", "mcptox/mcp-simple-arxiv_9", "mcptox/Email_15",
        "mcptox/Puppeteer_15", "mcptox/Memory_3", "mcptox/Memory_11", "mcptox/mcp-simple-arxiv_15",
        "mcptox/Email_11", "mcptox/ClickHouse_14", "mcptox/Git_10", "mcptox/AmapMap_10",
        "mcptox/AlphaVantage_4", "mcptox/mcp-simple-arxiv_1", "mcptox/AmapMap_1")]
    cases.extend({"id": case_id, "cohort": "clean_descriptions", "kind": "benign"} for case_id in (
        "clean/send_email", "clean/get_calendar_events", "clean/read_file", "clean/translate_text",
        "clean/create_notion_page"))
    cases.extend({"id": f"crafted/{name}", "cohort": "crafted",
                  "kind": "benign" if int(name[:2]) in {7, 8, 9, 10} else "malicious"}
                 for name in ("01-hidden-instructions-skill", "02-unicode-smuggled-skill",
                              "03-env-harvest-installer", "04-credential-reader", "05-obfuscated-payload",
                              "06-rugpull-pair", "07-clean-skill", "08-clean-mcp-server",
                              "09-clean-installer", "10-clean-node-skill", "11-readme-install-exfil"))
    cases.extend({"id": f"composition/{name}", "cohort": "composition",
                  "kind": "benign" if name.startswith("control-") else "malicious"}
                 for name in ("control-ingress-egress", "control-private-egress", "control-self-sufficient",
                              "shadow-pair", "trifecta-canonical", "trifecta-diluted", "trifecta-shuffled"))
    cases.extend([
        {"id": "reputation/requests-2.19.1", "cohort": "reputation", "kind": "vulnerable_dependency"},
        {"id": "reputation/requests-2.32.5", "cohort": "reputation", "kind": "dependency_control"},
    ])
    assert len(cases) == 40
    for index, case in enumerate(cases):
        case["input_sha256"] = {"tools.json": f"{index:064x}"}

    rows = []
    row_interval = {}
    for index, case in enumerate(cases):
        interval_id = "parent" if index < 13 else "continuation"
        row_interval[case["id"]] = interval_id
        complete = index != 12 and index != 14
        status = "partial" if index == 12 else "unattempted" if index == 14 else "completed"
        findings = ([{"severity": "critical", "title": "retained partial attack evidence"}]
                    if index == 12 else [])
        rows.append({
            **case,
            "complete": complete,
            "status": status,
            "detected": True if index in {0, 12} else False if complete else None,
            "findings": findings,
            "input_sha256": {"tools.json": f"{index:064x}"},
            "adjudicated_false_positive": None,
        })

    common = [case for case in cases if case["cohort"] in {"mcptox", "clean_descriptions"}]
    comparator_results = []
    for index, case in enumerate(common):
        comparator_results.append({
            "id": case["id"],
            "status": "unavailable" if index == 1 else "completed",
            "flagged_medium": case["id"] == "mcptox/Email_14",
            "flagged_native": False,
        })
    competitors = {
        "fuzzd": {"version": "0.13.0", "source_commit": "f" * 40,
                  "results": comparator_results},
        "mcp-sec-audit": {"version": "0.1.0", "source_commit": "e" * 40,
                          "results": [{**row, "status": "unavailable" if index == 2 else row["status"]}
                                      for index, row in enumerate(comparator_results)]},
    }
    intervals = [
        {"id": "parent", "started_utc": "2026-10-03T02:45:32.170289+00:00",
         "measured_utc": "2026-10-03T02:55:27.898583+00:00",
         "result_sha256": PARENT_RESULT_SHA256,
         "usage": {"attempts": 359, "prompt_tokens_total": None,
                   "completion_tokens_total": None, "prompt_tokens_known_subtotal": 85076,
                   "completion_tokens_known_subtotal": 112637, "unknown_usage_calls": 1}},
        {"id": "continuation", "started_utc": "2026-10-03T04:00:00+00:00",
         "measured_utc": "2026-10-03T04:10:00+00:00",
         "result_sha256": CHILD_RESULT_SHA256,
         "usage": {"attempts": 2, "prompt_tokens_total": 10,
                   "completion_tokens_total": 4, "prompt_tokens_known_subtotal": 10,
                   "completion_tokens_known_subtotal": 4, "unknown_usage_calls": 0}},
    ]
    combined = {
        "schema": 2,
        "protocol": PROTOCOL,
        "synthetic": True,
        "engine": {"commit": ENGINE_COMMIT},
        "limits": {"llm_max_output_tokens": 4096},
        "scope": "S0/S1/S2/S4 and source composition only",
        "planned": 40,
        "rows": rows,
        "summary": {},
        "coverage": {},
        "usage": {"attempts": 361, "prompt_tokens_total": None,
                  "completion_tokens_total": None, "prompt_tokens_known_subtotal": 85086,
                  "completion_tokens_known_subtotal": 112641, "unknown_usage_calls": 1},
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "child_result_sha256": CHILD_RESULT_SHA256,
        "intervals": intervals,
        "row_interval": row_interval,
        "lineage": {
            "parent": {"plan_sha256": PARENT_PLAN_SHA256,
                       "inventory_sha256": PARENT_INVENTORY_SHA256,
                       "result_sha256": PARENT_RESULT_SHA256},
            "child": {"plan_sha256": "2" * 64,
                      "result_sha256": CHILD_RESULT_SHA256},
            "original_case_manifest_sha256": CASE_MANIFEST_SHA256,
            "reused_runner_sha256": REUSED_RUNNER_SHA256,
        },
    }
    manifest = {"cases": cases}
    return combined, manifest, competitors


def test_combined_intervals_keep_partial_findings_and_uniform_intersection():
    mod = charts()
    combined, manifest, competitors = synthetic_packet()

    data = mod.chart_data(combined, manifest, competitors,
                          comparator_snapshot="2026-10-02-full")

    assert data["planned"] == 40
    assert [interval["id"] for interval in data["intervals"]] == ["parent", "continuation"]
    assert data["comparison"]["primary"]["fugu"]["planned_attacks"] == 15
    assert data["comparison"]["primary"]["fugu"]["planned_controls"] == 5
    assert data["partial_evidence"]["case_ids"] == ["mcptox/AlphaVantage_4"]
    assert data["partial_evidence"]["high_or_critical_findings"] == 1

    paired = data["comparison"]
    assert paired["paired_attack_ids"] == [
        "mcptox/Email_14", "mcptox/Email_15", "mcptox/Puppeteer_15", "mcptox/Memory_3",
        "mcptox/Memory_11", "mcptox/mcp-simple-arxiv_15", "mcptox/Email_11",
        "mcptox/ClickHouse_14", "mcptox/Git_10", "mcptox/AmapMap_10", "mcptox/mcp-simple-arxiv_1"]
    assert paired["paired_control_ids"] == [case["id"] for case in manifest["cases"]
                                               if case["cohort"] == "clean_descriptions"]
    assert {counts["attack_denominator"] for counts in paired["paired"].values()} == {11}
    assert combined["rows"][12]["findings"][0]["severity"] == "critical"

    assert data["usage"]["attempts"] == 361
    assert data["usage"]["prompt_tokens_total"] is None
    assert data["usage"]["completion_tokens_total"] is None
    assert data["usage"]["prompt_tokens_known_subtotal"] == 85086
    assert data["usage"]["completion_tokens_known_subtotal"] == 112641
    assert data["provenance"]["profile_output_tokens"] == 4096
    assert set(data["provenance"]["comparator_result_sha256"]) == {"fuzzd", "mcp-sec-audit"}
    assert "2026-10-03" in data["provenance"]["caption"]
    assert "2026-10-02-full" in data["provenance"]["caption"]


@pytest.mark.parametrize("change", ["wrong_protocol", "wrong_plan", "wrong_profile", "wrong_order",
                                     "missing_interval_mapping", "unknown_interval", "usage_mismatch"])
def test_invalid_combined_provenance_is_rejected(change):
    mod = charts()
    combined, manifest, competitors = synthetic_packet()
    if change == "wrong_protocol":
        combined["protocol"] = "unrelated-protocol"
    elif change == "wrong_plan":
        combined["lineage"]["parent"]["plan_sha256"] = "0" * 64
    elif change == "wrong_profile":
        combined["limits"]["llm_max_output_tokens"] = 2048
    elif change == "wrong_order":
        combined["rows"][0], combined["rows"][1] = combined["rows"][1], combined["rows"][0]
    elif change == "missing_interval_mapping":
        combined["row_interval"].pop(combined["rows"][0]["id"])
    elif change == "unknown_interval":
        combined["row_interval"][combined["rows"][0]["id"]] = "elsewhere"
    elif change == "usage_mismatch":
        combined["usage"]["attempts"] = 360

    with pytest.raises(ValueError):
        mod.chart_data(combined, manifest, competitors)


def test_unobserved_benign_controls_are_not_reported_as_zero_false_positive_rate():
    mod = charts()
    combined, manifest, competitors = synthetic_packet()
    for row in combined["rows"]:
        if row["kind"] == "benign":
            row.update(complete=False, status="unattempted", detected=None)

    data = mod.chart_data(combined, manifest, competitors)
    fugu = data["comparison"]["primary"]["fugu"]
    assert fugu["planned_controls"] == 5
    assert fugu["control_incomplete"] == 5
    assert fugu["raw_benign_flags"] == 0
    assert fugu["confirmed_false_positives"] == 0
    assert data["benign_adjudication"]["planned"] == 12
    assert "false_positive_rate" not in fugu
    assert data["benign_adjudication"]["false_positive_rate"] is None
    assert data["benign_adjudication"]["observed_denominator"] == 0


def test_manifest_packet_hash_validation_rejects_changed_input(tmp_path, monkeypatch):
    mod = charts()
    packet = tmp_path / "tools.json"
    packet.write_text("original packet", encoding="utf-8")
    case = {"id": "case-1", "target": "case-1",
            "input_sha256": {"tools.json": mod.sha(packet.read_bytes())}}
    monkeypatch.setattr(mod, "case_target", lambda _case: tmp_path)

    mod.verify_manifest_packets({"cases": [case]})
    packet.write_text("changed packet", encoding="utf-8")
    with pytest.raises(ValueError, match="packet hash"):
        mod.verify_manifest_packets({"cases": [case]})


def test_synthetic_render_captions_both_intervals_and_keeps_unknown_benign_unavailable():
    pytest.importorskip("matplotlib")
    mod = charts()
    combined, manifest, competitors = synthetic_packet()
    data = mod.chart_data(combined, manifest, competitors,
                          comparator_snapshot="2026-10-02-full")
    output = Path("/tmp/fugu-continuation-chart-qa/test-render")

    files = mod.render(data, output)

    assert {"common-results.png", "common-results.svg", "cohort-coverage.png", "cohort-coverage.svg",
            "call-telemetry.png", "call-telemetry.svg"} <= set(files)
    assert (output / "chart-data.json").is_file()
    common_svg = (output / "common-results.svg").read_text(encoding="utf-8")
    assert "SYNTHETIC OFFLINE FIXTURE" in common_svg
    assert "4096" in common_svg
    assert "2026-10-02-full" in common_svg
    assert "critical partial evidence retained" not in common_svg
    assert "partial findings are retained when present and do not count as completed detections" in common_svg
    assert "Secondary complete paired attacks (same 11 IDs)" in common_svg
    telemetry_svg = (output / "call-telemetry.svg").read_text(encoding="utf-8")
    assert "Unknown token-usage calls: parent 1" in telemetry_svg
    assert "Combined token totals stay unavailable" in telemetry_svg
    data_file = json.loads((output / "chart-data.json").read_text(encoding="utf-8"))
    assert data_file["benign_adjudication"]["false_positive_rate"] is None


@pytest.mark.parametrize("severities, expected_high_or_critical", [
    pytest.param(["high"], 1, id="high-only"),
    pytest.param(["critical"], 1, id="critical-only"),
    pytest.param(["high", "critical"], 2, id="mixed-high-and-critical"),
    pytest.param([], 0, id="no-findings"),
])
def test_partial_findings_caption_never_invents_critical_evidence(
        severities, expected_high_or_critical):
    pytest.importorskip("matplotlib")
    mod = charts()
    combined, manifest, competitors = synthetic_packet()
    combined["rows"][12]["findings"] = [
        {"severity": severity, "title": f"retained {severity} partial evidence"}
        for severity in severities
    ]
    data = mod.chart_data(combined, manifest, competitors,
                          comparator_snapshot="2026-10-02-full")
    output = Path("/tmp/fugu-continuation-chart-caption-correction") / (
        "partial-" + ("-".join(severities) if severities else "no-findings")
    )

    mod.render(data, output)

    common_svg = (output / "common-results.svg").read_text(encoding="utf-8").lower()
    assert "critical partial evidence retained" not in common_svg
    assert "partial findings are retained when present and do not count as completed detections" in common_svg
    assert data["planned"] == 40
    assert data["partial_evidence"]["incomplete_case_ids"] == ["mcptox/AlphaVantage_4"]
    assert data["partial_evidence"]["case_ids"] == (
        ["mcptox/AlphaVantage_4"] if severities else []
    )
    assert data["partial_evidence"]["high_or_critical_findings"] == expected_high_or_critical
    primary_fugu = data["comparison"]["primary"]["fugu"]
    assert primary_fugu["attack_detected"] == 1
    assert primary_fugu["attack_incomplete"] == 1
