import pytest
from bench.paired_workflow import state, summary


@pytest.mark.parametrize('metrics,ok,expected', [
    ({}, True, 'completed'),
    ({'coverage_incomplete': 'partial'}, True, 'partial'),
    ({'parse_errors': ['bad json']}, True, 'partial'),
    ({'skipped': 'no runnable triggers found; target not executed'}, True, 'not_applicable'),
    ({'skipped': 'no NEBIUS_API_KEY'}, True, 'unavailable'),
    ({'unattempted': 'provider_error'}, False, 'unattempted'),
    ({}, False, 'failed'),
])
def test_coverage_states_preserve_missing_and_failed_work(metrics, ok, expected):
    assert state({'ok': ok, 'metrics': metrics}) == expected


def test_partial_positive_is_excluded_and_kept_visible():
    rows = [{'cohort': 'mcptox', 'kind': 'malicious',
             'baseline': {'complete': False, 'detected': True},
             'integrated': {'complete': False, 'detected': True}}]
    for row in summary(rows):
        assert row['complete'] == 0 and row['excluded'] == 1
        assert row['flagged_complete'] == 0 and row['flagged_partial'] == 1


def test_chart_cli_accepts_separate_output_without_plot_dependencies(tmp_path):
    from bench.render_paired_workflow import parse_args

    measurement = tmp_path / 'measurement'
    output = tmp_path / 'verification' / 'charts'
    args = parse_args([str(measurement), '--output', str(output)])
    assert args.measurement == measurement
    assert args.output == output


def test_hardening_cli_preserves_original_measurement(tmp_path):
    import hashlib
    import json
    from bench.verify_static_hardening import main

    package = tmp_path / 'package'
    measurement = package / 'measurement'
    measurement.mkdir(parents=True)
    (measurement / 'audits').mkdir()
    source = tmp_path / 'delivered-source'
    surface = source / 'src/fugu/pipeline/stages/tool_surface.py'
    surface.parent.mkdir(parents=True)
    surface.write_text('# evidence masking amendment\n')
    relative = surface.relative_to(source).as_posix()
    (measurement / 'plan.json').write_text(json.dumps({
        'engine': {relative: hashlib.sha256(b'# frozen\n').hexdigest()},
        'image': 'synthetic-image', 'binary_sha256': '0' * 64,
    }))
    (measurement / 'cases.json').write_text('{"cases": []}')
    original = measurement / 'hardening-equivalence.json'
    original.write_text('{"retained": true}')
    before = {p.name: p.read_bytes() for p in measurement.glob('*.json')}
    output = tmp_path / 'verification' / 'hardening.json'

    main([str(package), '--source-root', str(source), '--output', str(output)])

    assert {p.name: p.read_bytes() for p in measurement.glob('*.json')} == before
    result = json.loads(output.read_text())
    assert result['changed_engine_files'] == [relative]
    assert result['engine_after'][relative] == hashlib.sha256(surface.read_bytes()).hexdigest()
    assert result['unique_inputs'] == 0

    # A real scan must execute the same source whose hashes it reports.
    (measurement / 'cases.json').write_text('{"cases": [{"id": "synthetic"}]}')
    with pytest.raises(AssertionError, match='loaded engine does not match --source-root'):
        main([str(package), '--source-root', str(source), '--output', str(output)])
