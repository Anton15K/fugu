import json
import hashlib
import asyncio

import pytest

from bench.fresh_benchmark import aggregate, clean_tool_document, select_balanced
from bench.fresh_benchmark import load_clean_tools, audit
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


def synthetic_sample(tmp_path, files):
    for i in range(files):
        (tmp_path / f'note-{i:02}.md').write_text('Fabricated ordinary note.')
    return {'id': 'synthetic/coverage', 'set': 'synthetic', 'kind': 'benign',
            'group': 'synthetic', 'path': str(tmp_path)}


def fake_judge_record():
    from fugu.pipeline.stages.semantic import JudgeCall
    return JudgeCall('offline-test', 0, 0, 0, {})


@pytest.mark.parametrize('files,completed,omitted', [(1, 1, 0), (24, 24, 0), (25, 24, 1)])
def test_semantic_unit_cap_does_not_count_omitted_content_as_complete(tmp_path, files, completed, omitted):
    def fake_call(*args):
        return '{"findings": []}', fake_judge_record()

    row = asyncio.run(audit(synthetic_sample(tmp_path, files), True, fake_call))
    metrics = row['stages'][-1]['metrics']
    assert (metrics['units_total'], metrics['units_completed'], metrics['units_omitted']) == (files, completed, omitted)
    assert len(metrics['llm_calls']) == completed
    assert row['complete'] is (omitted == 0)
    assert row['flagged'] is (None if omitted else False)
    summary = aggregate([row])
    assert summary['completed'] == (0 if omitted else 1)
    assert summary['rate'] is None if omitted else summary['rate'] == 0


@pytest.mark.parametrize('failure', ['call', 'parse', 'mixed_findings'])
def test_partial_semantic_errors_retain_valid_findings_without_entering_complete_denominator(tmp_path, failure):
    valid = {'title': 'Fabricated finding', 'severity': 'high', 'owasp_ids': ['LLM01'],
             'excerpt': 'Fabricated ordinary note.', 'detail': 'Offline synthetic test.'}
    calls = 0

    def fake_call(*args):
        nonlocal calls
        calls += 1
        if calls == 2 or (failure == 'parse' and calls == 3):
            if failure == 'call':
                raise RuntimeError('fabricated call failure')
            if failure == 'parse':
                return 'not JSON', fake_judge_record()
            return json.dumps({'findings': [valid, None]}), fake_judge_record()
        return json.dumps({'findings': [valid]}), fake_judge_record()

    row = asyncio.run(audit(synthetic_sample(tmp_path, 2), True, fake_call))
    semantic = row['stages'][-1]
    assert semantic['ok'] is True  # At least one unit remains usable.
    assert semantic['metrics']['coverage_incomplete']
    assert semantic['metrics']['units_completed'] == 1
    assert len(semantic['findings']) == (2 if failure == 'mixed_findings' else 1)
    assert semantic['findings'][0]['evidence'][0]['excerpt'] == valid['excerpt']
    assert row['complete'] is False
    assert row['flagged'] is None
    assert aggregate([row])['completed'] == 0


def test_recovered_semantic_response_enters_complete_denominator(tmp_path):
    valid = {'title': 'Fabricated finding', 'severity': 'high', 'owasp_ids': ['LLM01'],
             'excerpt': 'Fabricated ordinary note.', 'detail': 'Offline synthetic test.'}
    prompts = []

    def fake_call(system, user):
        prompts.append((system, user))
        if len(prompts) == 2:
            return 'not JSON', fake_judge_record()
        return json.dumps({'findings': [valid]}), fake_judge_record()

    row = asyncio.run(audit(synthetic_sample(tmp_path, 2), True, fake_call))
    semantic = row['stages'][-1]
    assert len(prompts) == 3
    assert prompts[1] == prompts[2]
    assert semantic['metrics']['units_completed'] == 2
    assert not semantic['metrics'].get('coverage_incomplete')
    assert semantic['metrics']['response_recoveries'][0]['initial_error'] == 'invalid_json'
    assert len(semantic['findings']) == 2
    assert row['complete'] is True
    assert row['flagged'] is True
    assert aggregate([row])['completed'] == 1


def test_input_copy_omissions_remain_incomplete_after_remaining_files_are_analyzed(tmp_path):
    sample = synthetic_sample(tmp_path, 1)
    (tmp_path / 'oversized.md').write_text('x' * 2_000_001)

    def fake_call(*args):
        return '{"findings": []}', fake_judge_record()

    row = asyncio.run(audit(sample, True, fake_call))
    assert row['complete'] is False
    assert row['flagged'] is None
    assert row['input_collection']['skipped_large'] == 1
    assert row['stages'][-1]['metrics']['units_completed'] == 1
