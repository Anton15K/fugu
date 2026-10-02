import json
import hashlib

import pytest

from bench.fresh_benchmark import aggregate, clean_tool_document, select_balanced
from bench.fresh_benchmark import load_clean_tools
from bench.benchmark_charts import percentage, export_table, dataset, DEFAULT_RESULTS


def test_incomplete_runs_are_not_counted_as_clean_or_in_denominator():
    result = aggregate([
        {"complete": True, "flagged": True},
        {"complete": True, "flagged": False},
        {"complete": False, "flagged": None},
    ])
    assert result == {"attempted": 3, "completed": 2, "incomplete": 1,
                      "flagged": 1, "rate": 0.5}
    assert aggregate([])["rate"] is None
    assert aggregate([{"complete": False, "flagged": None}])["rate"] is None


def test_adapter_does_not_expose_benchmark_labels():
    case = {"poisoned_tool_name": "read", "poisoned_description": "Return requested file.",
            "case_id": "ATTACK_LABEL", "category": "SECRET_CATEGORY", "paradigm": "T3"}
    document = clean_tool_document(case)
    assert document["tools"][0]["description"] == "Return requested file."
    assert document["tools"][0]["name"] == "read"
    assert set(document["tools"][0]) == {"name", "description"}
    assert not any(x in json.dumps(document) for x in ("ATTACK_LABEL", "SECRET_CATEGORY", "T3", "poisoned"))


def test_balanced_sample_is_order_independent_and_exact():
    rows = [{"id": f"{g}{i}", "group": g} for g in "ABC" for i in range(15)]
    picked = select_balanced(rows, "group", "id", 10, "20261002")
    assert picked == select_balanced(rows[::-1], "group", "id", 10, "20261002")
    assert len(picked) == len({r["id"] for r in picked}) == 30
    assert all(sum(r["group"] == g for r in picked) == 10 for g in "ABC")
    with pytest.raises(ValueError):
        select_balanced(rows, "group", "id", 16, "20261002")


def test_missing_values_stay_missing_and_invalid_counts_fail():
    assert percentage(None, 20) is None
    assert percentage(0, 0) is None
    assert percentage(0, 20) == 0
    assert percentage(367, 491) == pytest.approx(74.7454175153)
    with pytest.raises(ValueError):
        percentage(21, 20)


def test_csv_keeps_missing_measurements_empty(tmp_path):
    path = tmp_path / 'table.csv'
    export_table([{'tool': 'unmeasured', 'numerator': None, 'denominator': None,
                   'percent': None}], path)
    assert path.read_text().splitlines()[1] == 'unmeasured,,,'
    assert b'\r' not in path.read_bytes()  # Preserve manifest hashes after Git normalization.


def test_retained_live_chart_uses_planned_cases_without_hiding_failures():
    rows = dataset(DEFAULT_RESULTS)
    attack = next(r for r in rows if r['tool'] == 'Fugu' and r['mode'] == 'S0+S1+S2'
                  and r['cohort'] == 'mcptox_pure')
    assert (attack['numerator'], attack['denominator'], attack['completed'], attack['incomplete']) == (26, 30, 28, 2)
    assert attack['percent'] == pytest.approx(100 * 26 / 30)
    snyk = next(r for r in rows if r['tool'] == 'Snyk Agent Scan')
    assert snyk['percent'] is None


def test_clean_fixture_missing_or_changed_fails_with_actionable_error(tmp_path):
    path = tmp_path / 'clean_tools.json'
    with pytest.raises(FileNotFoundError, match='pinned clean-tools fixture'):
        load_clean_tools(path)
    path.write_text('[]')
    with pytest.raises(ValueError, match='SHA-256 mismatch'):
        load_clean_tools(path)


def test_clean_fixture_loads_only_after_hash_verification(tmp_path, monkeypatch):
    import bench.fresh_benchmark as runner
    content = b'[{"name":"example","description":"Read requested data."}]'
    path = tmp_path / 'clean_tools.json'
    path.write_bytes(content)
    monkeypatch.setattr(runner, 'CLEAN_TOOLS_SHA256', hashlib.sha256(content).hexdigest())
    assert load_clean_tools(path) == json.loads(content)
