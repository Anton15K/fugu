"""CLI behavior against canonical intake/stages; all hosted transports are fake."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace

import pytest

from fugu.cli import main
from fugu import cli_output
from fugu.credentials import CredentialSet

FIXTURES = Path(__file__).parent / 'fixtures' / 'judge_casebook'


def audit_module():
    from fugu import cli_audit
    return cli_audit


@pytest.mark.parametrize('status,incomplete,expected', [
    ('pass', False, 0), ('warn', False, 1), ('fail', False, 1),
    ('pass', True, 3), ('fail', True, 3),
])
def test_coverage_controls_exit(status, incomplete, expected):
    assert cli_output.exit_for_report({'audit_status': 'done', 'verdict': {'status': status},
        'coverage': {'incomplete': incomplete}, 'error': None}) == expected


@pytest.mark.parametrize('category,expected', [('usage', 2), ('configuration', 2),
    ('credential', 2), ('intake', 2), ('audit', 3), ('cancelled', 130)])
def test_error_exit_priority(category, expected):
    assert cli_output.exit_for_report({'audit_status': 'failed', 'verdict': {'status': 'fail'},
        'coverage': {'incomplete': True}, 'error': {'category': category}}) == expected


def test_no_verdict_cannot_pass():
    assert cli_output.exit_for_report({'audit_status': 'done', 'verdict': None,
        'coverage': {'incomplete': False}, 'error': None}) == 3


@pytest.fixture
def offline_guard(monkeypatch, tmp_path):
    import fugu.client as provider
    import fugu.credentials as credentials
    import fugu.server.jobs as jobs
    from fugu.pipeline.stages.tool_surface import ToolSurfaceScanner
    attempts = []
    def deny(kind):
        def blocked(*args, **kwargs):
            attempts.append(kind)
            raise AssertionError(kind)
        return blocked
    monkeypatch.setattr(provider, 'make_client', deny('provider'))
    monkeypatch.setattr(credentials, 'NativeSecretStore', deny('keyring-adapter'))
    monkeypatch.setattr(ToolSurfaceScanner, 'from_environment', deny('scanner-discovery'))
    monkeypatch.setattr(socket.socket, 'connect', deny('network'))
    monkeypatch.setattr(socket.socket, 'connect_ex', deny('network'))
    monkeypatch.setattr(socket, 'create_connection', deny('network'))
    monkeypatch.setattr(subprocess, 'Popen', deny('subprocess'))
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', deny('subprocess'))
    monkeypatch.setattr(asyncio, 'create_subprocess_shell', deny('subprocess'))
    snapshots = tmp_path / 'snapshots'
    snapshots.mkdir()
    mkdtemp = jobs.tempfile.mkdtemp
    def owned(*args, **kwargs):
        return mkdtemp(*args, **{**kwargs, 'dir': snapshots})
    monkeypatch.setattr(jobs.tempfile, 'mkdtemp', owned)
    yield attempts
    assert attempts == []
    assert list(snapshots.iterdir()) == []


@pytest.mark.parametrize('name,verdict,exit_code', [('ordinary', 'pass', 0), ('hidden', 'fail', 1)])
def test_real_offline_fixtures(name, verdict, exit_code, offline_guard, capsys):
    source = FIXTURES / name
    assert main(['audit', str(source), '--mode', 'offline', '--format', 'json']) == exit_code
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert captured.out.count('\n') == 1
    assert report['schema_version'] == 1
    assert report['verdict']['status'] == verdict
    assert report['exit_code'] == exit_code
    assert report['coverage']['required_stages'] == ['concealment', 'static']
    assert report['coverage']['incomplete'] is False
    assert set(report['coverage']['excluded_stages']) == {'semantic', 'harness', 'reputation', 'detonation', 'tool_surface'}
    assert [s['stage'] for s in report['stages']] == ['concealment', 'static']
    assert report['stages'][1]['metrics']['tool_surface'] == {'enabled': False}
    assert source.is_dir()
    if name == 'hidden':
        finding = next(f for f in report['findings'] if f['stage'] == 'concealment')
        assert any('PRIVATE_DEMO_MARKER' in e['excerpt'] for e in finding['evidence'])


def test_real_missing_source_is_intake_error(offline_guard, tmp_path, capsys):
    assert main(['audit', str(tmp_path / 'missing'), '--mode', 'offline', '--format', 'json']) == 2
    report = json.loads(capsys.readouterr().out)
    assert report['verdict'] is None
    assert report['error']['category'] == 'intake'


@pytest.mark.parametrize('extra', [['--reputation'], ['--detonate']])
def test_offline_flags_rejected_before_intake(extra, offline_guard, capsys):
    assert main(['audit', 'missing', '--mode', 'offline', '--format', 'json', *extra]) == 2
    assert json.loads(capsys.readouterr().out)['error']['category'] == 'usage'


@pytest.mark.parametrize('source', ['https://example.invalid/repo', 'git@example.invalid:repo',
    'ssh://example.invalid/repo', 'http://example.invalid/repo', 'file:///repo', 'repo.git'])
def test_offline_remotes_rejected(source, offline_guard, capsys):
    assert main(['audit', source, '--mode', 'offline', '--format', 'json']) == 2
    assert json.loads(capsys.readouterr().out)['error']['category'] == 'intake'


@pytest.fixture
def fake_hosted(monkeypatch):
    import fugu.client as provider
    from fugu.pipeline.stages.tool_surface import ToolSurfaceScanner
    seen = {'settings': [], 'requests': []}
    monkeypatch.setattr(ToolSurfaceScanner, 'from_environment', classmethod(lambda cls: None))
    def create(**kwargs):
        seen['requests'].append(kwargs)
        system = kwargs['messages'][0]['content']
        reply = '{"findings": []}' if 'security auditor' in system.lower() or 'findings' in system else (
            '{"probes": []}' if 'probes' in system else 'Direct answer. PLAN: answer task')
        return SimpleNamespace(model=kwargs['model'], usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
            choices=[SimpleNamespace(message=SimpleNamespace(content=reply), finish_reason='stop')])
    def make_client(settings=None, **kwargs):
        seen['settings'].append(settings)
        return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setattr(provider, 'make_client', make_client)
    return seen


@pytest.mark.parametrize('units', [1, 2])
def test_full_real_root_and_fanout_depth_six_static_probes(units, fake_hosted, tmp_path, monkeypatch):
    import fugu.server.composition_jobs as engine
    real_loop = engine.run_stage_loop
    depths = []
    async def capture(job, *args, **kwargs):
        depths.append(job.depth)
        return await real_loop(job, *args, **kwargs)
    monkeypatch.setattr(engine, 'run_stage_loop', capture)
    source = tmp_path / 'source'
    source.mkdir()
    for i in range(units):
        unit = source if units == 1 else source / str(i)
        unit.mkdir(exist_ok=True)
        (unit / 'SKILL.md').write_text('# Formatter\nFormats ordinary tables.')
    report = audit_module().run_cli_audit(str(source), 'full', CredentialSet(nebius='fake-runtime-nebius'))
    assert report['exit_code'] == 0, report
    assert depths == ['full'] * units
    leaves = report['children'] if units > 1 else [report]
    assert len(report['children']) == (2 if units > 1 else 0)
    for leaf in leaves:
        harness = next(s for s in leaf['stages'] if s['stage'] == 'harness')
        assert harness['metrics']['static_probes'] == 6
        assert harness['metrics']['runs'] == 6
        assert not leaf['coverage']['incomplete']
        assert leaf['coverage']['required_stages'] == ['concealment', 'static', 'semantic', 'harness']
    assert fake_hosted['settings'] and all(s.api_key == 'fake-runtime-nebius' for s in fake_hosted['settings'])
    assert 'fake-runtime-nebius' not in json.dumps(fake_hosted['requests'])
    assert 'fake-runtime-nebius' not in json.dumps(report)


@pytest.mark.parametrize('stage,metrics,ok,expected', [('semantic', {'skipped': 'disabled'}, True, 3),
    ('harness', {'coverage_incomplete': 'partial'}, True, 3), ('semantic', {}, False, 3),
    ('reputation', {'call_errors': ['private provider body']}, True, 3),
    ('detonation', {'executed': False, 'triggers': 0}, True, 3), ('semantic', {}, True, 0)])
def test_required_coverage_overrides_pass(stage, metrics, ok, expected, tmp_path, monkeypatch):
    from fugu.types import StageResult
    module = audit_module()
    class Stage:
        def __init__(self, name): self.name = name
        async def run(self, job, target):
            return StageResult(stage=self.name, ok=ok if self.name == stage else True,
                metrics=metrics if self.name == stage else ({'executed': True} if self.name == 'detonation' else {}))
    monkeypatch.setattr(module, '_build_stages', lambda *args, **kwargs:
        [Stage(name) for name in ['concealment', 'static', 'semantic', 'harness', 'reputation', 'detonation']])
    report = module.run_cli_audit(str(FIXTURES / 'ordinary'), 'full',
        CredentialSet(nebius='fake-nebius', tavily='fake-tavily'), detonate=True)
    assert report['exit_code'] == expected
    assert report['coverage']['incomplete'] is (expected == 3)


def test_fanout_missing_required_stage_overrides_parent_pass(tmp_path, monkeypatch):
    from fugu.types import StageResult
    module = audit_module()
    class Local:
        name = 'concealment'
        async def run(self, job, target): return StageResult(stage=self.name, ok=True)
    monkeypatch.setattr(module, '_build_stages', lambda *args, **kwargs: [Local()])
    for name in ['one', 'two']:
        unit = tmp_path / name
        unit.mkdir()
        (unit / 'SKILL.md').write_text('# Ordinary skill')
    report = module.run_cli_audit(str(tmp_path), 'full', CredentialSet(nebius='fake-nebius'))
    assert report['verdict']['status'] == 'pass'
    assert report['exit_code'] == 3
    assert all(child['coverage']['incomplete'] for child in report['children'])


@pytest.mark.parametrize('tavily,flag,reads,code', [(None, False, [], 0),
    (None, True, ['tavily'], 0), ('', True, [], 2), ('fake-env-tavily', False, [], 0)])
def test_headless_full_lazy_optional_storage(tavily, flag, reads, code, monkeypatch, capsys):
    import fugu.credentials as credentials
    module = audit_module()
    monkeypatch.setenv('NEBIUS_API_KEY', 'fake-env-nebius')
    monkeypatch.delenv('TAVILY_API_KEY', raising=False)
    if tavily is not None: monkeypatch.setenv('TAVILY_API_KEY', tavily)
    acquired = []
    class Store:
        def get(self, provider): acquired.append(provider); return 'fake-saved-tavily'
    monkeypatch.setattr(credentials, 'NativeSecretStore', Store)
    received = []
    def run(source, mode, keys, **kwargs):
        received.append(keys)
        return cli_output.error_report(source, mode, None, verdict={'status': 'pass'}, audit_status='done')
    monkeypatch.setattr(module, 'run_cli_audit', run)
    argv = ['audit', 'authored-local', '--allow-hosted', '--format', 'json'] + (['--reputation'] if flag else [])
    assert main(argv) == code
    assert acquired == reads
    json.loads(capsys.readouterr().out)
    if code == 0:
        assert received[0].tavily == (tavily or ('fake-saved-tavily' if flag else ''))


def test_full_preflight_consent_and_missing_key_before_intake(monkeypatch, capsys):
    import fugu.credentials as credentials
    monkeypatch.setenv('NEBIUS_API_KEY', '')
    monkeypatch.setattr(credentials, 'NativeSecretStore', lambda: pytest.fail('unexpected storage'))
    assert main(['audit', 'missing', '--format', 'json', '--allow-hosted']) == 2
    assert json.loads(capsys.readouterr().out)['error']['category'] == 'credential'
    monkeypatch.setenv('NEBIUS_API_KEY', 'fake-key')
    monkeypatch.setattr('sys.stdin.isatty', lambda: False)
    assert main(['audit', 'missing', '--format', 'json']) == 2
    assert json.loads(capsys.readouterr().out)['error']['category'] == 'consent'


@pytest.mark.parametrize('source', ['http://example.invalid/r', 'ssh://example.invalid/r',
    'https://user:fake-token@example.invalid/r', 'https://fake-token@example.invalid/r'])
def test_full_rejects_unsafe_git_before_keys(source, monkeypatch, capsys):
    import fugu.credentials as credentials
    monkeypatch.setattr(credentials, 'NativeSecretStore', lambda: pytest.fail('unexpected store'))
    assert main(['audit', source, '--format', 'json', '--allow-hosted']) == 2
    output = capsys.readouterr()
    assert json.loads(output.out)['error']['category'] == 'intake'
    assert 'fake-token' not in output.out + output.err


def test_json_usage_error_is_single_object(capsys):
    assert main(['audit', 'local', '--format', 'json', '--unknown']) == 2
    output = capsys.readouterr()
    assert output.out.count('\n') == 1
    assert json.loads(output.out)['error']['category'] == 'usage'


def test_render_redacts_values_with_json_escapes_and_preserves_canary():
    report = {'verdict': {'status': 'fail'}, 'mode': 'offline', 'coverage': {'incomplete': False},
        'findings': [{'detail': 'fake-"credential\n and FUGU-CANARY-demo'}]}
    rendered = cli_output.render_report(report, 'json', ['fake-"credential\n'])
    assert 'credential' not in rendered
    assert json.loads(rendered)['findings'][0]['detail'] == '[REDACTED] and FUGU-CANARY-demo'


def test_local_directory_named_git_is_offline(tmp_path, offline_guard, capsys):
    source = tmp_path / 'ordinary.git'
    source.mkdir()
    (source / 'SKILL.md').write_text('# Ordinary skill')
    assert main(['audit', str(source), '--mode', 'offline', '--format', 'json']) == 0
    assert json.loads(capsys.readouterr().out)['verdict']['status'] == 'pass'


def test_canonical_omission_counts_incomplete(tmp_path, offline_guard):
    source = tmp_path / 'source'
    source.mkdir()
    for i in range(25):
        unit = source / f'unit-{i:02}'
        unit.mkdir()
        (unit / 'SKILL.md').write_text('# Ordinary skill')
    report = audit_module().run_cli_audit(str(source), 'offline', CredentialSet())
    assert len(report['children']) == 24
    assert report['verdict']['omitted_units'] == 1
    assert report['exit_code'] == 3
    assert report['coverage']['omitted_units'] == 1
    assert report['coverage']['omitted_unit_labels'] == ['unit-24']
    assert all(c['label'].startswith('unit-') for c in report['children'])


def test_real_no_trigger_detonation_is_incomplete(fake_hosted, monkeypatch):
    from fugu.detonation.docker_driver import DockerDriver
    async def deny(*args, **kwargs): pytest.fail('no-trigger target must not execute')
    monkeypatch.setattr(DockerDriver, 'detonate', deny)
    report = audit_module().run_cli_audit(str(FIXTURES / 'ordinary'), 'full', CredentialSet(nebius='fake-nebius'), detonate=True)
    result = next(s for s in report['stages'] if s['stage'] == 'detonation')
    assert result['metrics']['executed'] is False
    assert report['exit_code'] == 3


@pytest.mark.parametrize('answer,expected', [('yes\n', 0), ('no\n', 2), ('', 2)])
def test_interactive_consent_only_stderr(answer, expected, monkeypatch, capsys):
    import io
    import sys
    module = audit_module()
    monkeypatch.setenv('NEBIUS_API_KEY', 'fake-env-nebius')
    monkeypatch.setenv('TAVILY_API_KEY', '')
    stream = io.StringIO(answer)
    stream.isatty = lambda: True
    monkeypatch.setattr(sys, 'stdin', stream)
    calls = []
    def run(source, mode, keys, **kwargs):
        calls.append(source)
        return cli_output.error_report(source, mode, None, verdict={'status': 'pass'}, audit_status='done')
    monkeypatch.setattr(module, 'run_cli_audit', run)
    assert main(['audit', 'authored-source', '--format', 'json']) == expected
    output = capsys.readouterr()
    assert 'billing' in output.err or 'billed' in output.err
    assert 'Allow these hosted' in output.err
    assert output.out.count('\n') == 1
    json.loads(output.out)
    assert calls == (['authored-source'] if expected == 0 else [])


def test_saved_reputation_missing_is_preflight(monkeypatch, capsys):
    import fugu.credentials as credentials
    module = audit_module()
    monkeypatch.setenv('NEBIUS_API_KEY', 'fake-env-nebius')
    monkeypatch.delenv('TAVILY_API_KEY', raising=False)
    calls = []
    class Store:
        def get(self, provider): calls.append(provider); return None
    monkeypatch.setattr(credentials, 'NativeSecretStore', Store)
    monkeypatch.setattr(module, 'run_cli_audit', lambda *args, **kwargs: pytest.fail('preflight intake'))
    assert main(['audit', 'missing', '--reputation', '--allow-hosted', '--format', 'json']) == 2
    assert calls == ['tavily']
    assert json.loads(capsys.readouterr().out)['error']['category'] == 'credential'


def test_text_leads_with_verdict_mode_coverage_action():
    report = {'mode': 'offline', 'verdict': {'status': 'pass'}, 'coverage': {'incomplete': False,
        'excluded_stages': ['semantic', 'harness']}, 'findings': [], 'error': None}
    lines = cli_output.render_report(report, 'text').splitlines()
    assert lines[0] == 'Verdict: PASS | Mode: offline'
    assert lines[1] == 'Coverage: chosen profile complete'
    assert lines[3].startswith('Next action:')
    assert 'does not certify safety' in '\n'.join(lines)


def test_env_only_full_has_no_native_storage_requests(fake_hosted, monkeypatch, capsys):
    import fugu.credentials as credentials
    monkeypatch.setenv('NEBIUS_API_KEY', 'fake-env-nebius')
    monkeypatch.delenv('TAVILY_API_KEY', raising=False)
    monkeypatch.setattr(credentials, 'NativeSecretStore', lambda: pytest.fail('env-only backend request'))
    assert main(['audit', str(FIXTURES / 'ordinary'), '--allow-hosted', '--format', 'json']) == 0
    report = json.loads(capsys.readouterr().out)
    assert 'reputation' in report['coverage']['excluded_stages']
    assert 'tool_surface' in report['coverage']['excluded_stages']


def test_real_provider_failure_does_not_fallback_to_saved_keys(fake_hosted, monkeypatch, capsys):
    import fugu.credentials as credentials
    import fugu.client as provider
    monkeypatch.setenv('NEBIUS_API_KEY', 'fake-invalid-env-key')
    monkeypatch.delenv('TAVILY_API_KEY', raising=False)
    monkeypatch.setattr(credentials, 'NativeSecretStore', lambda: pytest.fail('auth fallback'))
    def fail(**kwargs): raise RuntimeError('private provider body fake-invalid-env-key')
    def make_client(*args, **kwargs):
        return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=fail)))
    monkeypatch.setattr(provider, 'make_client', make_client)
    assert main(['audit', str(FIXTURES / 'ordinary'), '--allow-hosted', '--format', 'json']) == 3
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report['verdict'] is not None and report['coverage']['incomplete'] is True
    assert 'fake-invalid-env-key' not in output.out + output.err
    assert 'private provider body' not in output.out + output.err


def test_real_reputation_uses_scoped_tavily(fake_hosted, monkeypatch, tmp_path):
    import fugu.pipeline.stages.reputation as reputation
    seen = []
    def search(key, query): seen.append((key, query)); return {'results': []}
    monkeypatch.setattr(reputation, '_default_search', search)
    monkeypatch.setenv('TAVILY_API_KEY', 'fake-environment-override')
    (tmp_path / 'SKILL.md').write_text('# Ordinary skill\nFormats tables.')
    (tmp_path / 'package.json').write_text('{"dependencies":{"ordinary-package":"1.2.3"}}')
    report = audit_module().run_cli_audit(str(tmp_path), 'full',
        CredentialSet(nebius='fake-nebius', tavily='fake-scoped-tavily'))
    assert report['exit_code'] == 0, report
    assert seen and all(key == 'fake-scoped-tavily' for key, _ in seen)
    assert 'reputation' in report['coverage']['required_stages']
    assert 'fake-scoped-tavily' not in json.dumps(report)
    assert 'fake-scoped-tavily' not in json.dumps(fake_hosted['requests'])


def test_binary_source_omissions_are_incomplete(tmp_path, offline_guard, capsys):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'payload.dat').write_bytes(b'\x00' * 128)
    assert main(['audit', str(source), '--mode', 'offline', '--format', 'json']) == 3
    report = json.loads(capsys.readouterr().out)
    assert report['verdict']['status'] == 'pass'
    assert report['coverage']['incomplete'] is True
