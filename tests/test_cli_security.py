"""Secret and resource boundaries using inert transports, never target execution."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from fugu.cli import main
from fugu.credentials import CredentialSet


@pytest.fixture
def secret_env(monkeypatch):
    monkeypatch.setenv('NEBIUS_API_KEY', 'fake-security-nebius')
    monkeypatch.setenv('TAVILY_API_KEY', 'fake-security-tavily')


def test_environment_filter_preserves_normal_variables():
    from fugu.subprocess_env import credential_free_env
    environ = {'NEBIUS_API_KEY': 'fake-secret', 'TAVILY_API_KEY': 'fake-secret-2',
        'PATH': '/normal/bin', 'HOME': '/normal/home', 'DOCKER_HOST': 'local-host'}
    assert credential_free_env(environ) == {'PATH': '/normal/bin', 'HOME': '/normal/home', 'DOCKER_HOST': 'local-host'}
    assert 'NEBIUS_API_KEY' in environ


class Process:
    def __init__(self, cancel=False):
        self.returncode = None if cancel else 0
        self.cancel = cancel
        self.killed = False
        self.drained = False
    async def communicate(self):
        if self.cancel and not self.killed: raise asyncio.CancelledError()
        self.drained = True
        self.returncode = 0
        return b'', b''
    async def wait(self): return self.returncode
    def kill(self): self.killed = True


@pytest.mark.parametrize('transport', ['git', 'docker'])
def test_git_docker_child_env_filtered(transport, secret_env, monkeypatch, tmp_path):
    calls = []
    async def launch(*args, **kwargs):
        calls.append((args, kwargs))
        return Process()
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', launch)
    if transport == 'git':
        from fugu.server.jobs import _git_clone
        asyncio.run(_git_clone('https://example.invalid/repo', tmp_path / 'clone'))
    else:
        from fugu.detonation.docker_driver import DockerDriver
        asyncio.run(DockerDriver()._run(['info']))
    assert calls
    for args, options in calls:
        assert 'NEBIUS_API_KEY' not in options['env']
        assert 'TAVILY_API_KEY' not in options['env']
        assert 'PATH' in options['env']
        assert 'fake-security-' not in json.dumps(args)


@pytest.mark.parametrize('transport', ['git', 'docker'])
def test_cancelled_child_is_killed_and_drained(transport, monkeypatch, tmp_path):
    proc = Process(cancel=True)
    async def launch(*args, **kwargs): return proc
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', launch)
    if transport == 'git':
        from fugu.server.jobs import _git_clone
        operation = _git_clone('https://example.invalid/repo', tmp_path / 'clone')
    else:
        from fugu.detonation.docker_driver import DockerDriver
        operation = DockerDriver()._run(['info'])
    with pytest.raises(asyncio.CancelledError): asyncio.run(operation)
    assert proc.killed and proc.drained


def test_docker_trigger_env_and_cleanup_filtered(secret_env, monkeypatch, tmp_path):
    from fugu.detonation.docker_driver import DockerDriver
    calls = []
    async def launch(*args, **kwargs):
        calls.append((args, kwargs))
        return Process()
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', launch)
    driver = DockerDriver()
    asyncio.run(driver._exec_trigger(run_id='owned-fake', victim='owned-fake-victim', net='owned-fake-net',
        dns_ip='192.0.2.1', mitm_ip='192.0.2.2', image='inert-image', trigger='inert-command',
        timeout_s=1, canary_env={'FUGU_CANARY_TOKEN': 'FUGU-CANARY-test'},
        canary_values=['FUGU-CANARY-test'], logs_dir=tmp_path))
    assert len(calls) == 3  # run, diff, rm (fake only)
    for args, options in calls:
        assert 'NEBIUS_API_KEY' not in options['env'] and 'TAVILY_API_KEY' not in options['env']
        assert 'fake-security-' not in json.dumps(args)
    assert any('FUGU_CANARY_TOKEN=FUGU-CANARY-test' in arg for arg in calls[0][0])


def test_scanner_and_cleanup_env_filtered(secret_env, monkeypatch, tmp_path):
    import subprocess
    from fugu.pipeline.stages.tool_surface import ToolSurfaceScanner
    binary = tmp_path / 'trusted-scanner'
    binary.write_text('inert binary')
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'SKILL.md').write_text('# Ordinary skill\nFormats tables.')
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"tools_scanned":1,"findings":[]}', stderr='')
    monkeypatch.setattr(subprocess, 'run', run)
    findings, metrics = ToolSurfaceScanner(binary=binary, image='inert-scanner').scan(target, 10000, 10)
    assert not findings and not metrics.get('coverage_incomplete')
    assert len(calls) == 2
    for args, kwargs in calls:
        assert 'NEBIUS_API_KEY' not in kwargs['env'] and 'TAVILY_API_KEY' not in kwargs['env']
        assert 'fake-security-' not in json.dumps(args)


def test_scanner_explicit_false_does_not_discover_environment(monkeypatch, tmp_path):
    from fugu.pipeline.stages.static_scan import StaticScanStage
    from fugu.pipeline.stages.tool_surface import ToolSurfaceScanner
    monkeypatch.setattr(ToolSurfaceScanner, 'from_environment', lambda: pytest.fail('scanner reactivated'))
    stage = StaticScanStage(surface_scanner=False)
    (tmp_path / 'SKILL.md').write_text('# Ordinary')
    from fugu.types import AuditJob
    result = asyncio.run(stage.run(AuditJob(id='inert', source=str(tmp_path)), tmp_path))
    assert result.metrics['tool_surface'] == {'enabled': False}


def test_cancellation_reclaims_snapshot_preserves_source(monkeypatch, tmp_path):
    from fugu import cli_audit
    from fugu.types import StageResult
    import fugu.server.jobs as jobs
    source = tmp_path / 'source'
    source.mkdir()
    original = source / 'SKILL.md'
    original.write_text('# Ordinary source')
    snapshots = tmp_path / 'owned'
    snapshots.mkdir()
    mkdtemp = jobs.tempfile.mkdtemp
    monkeypatch.setattr(jobs.tempfile, 'mkdtemp', lambda **kwargs: mkdtemp(**{**kwargs, 'dir': snapshots}))
    class Stage:
        name = 'concealment'
        async def run(self, job, target): raise asyncio.CancelledError()
    monkeypatch.setattr(cli_audit, '_build_stages', lambda *args, **kwargs: [Stage()])
    report = cli_audit.run_cli_audit(str(source), 'offline', CredentialSet())
    assert report['exit_code'] == 130
    assert report['error']['category'] == 'cancelled'
    assert not list(snapshots.iterdir())
    assert original.read_text() == '# Ordinary source'


def test_cancellation_during_copy_reclaims_unclaimed_snapshot(monkeypatch, tmp_path):
    import fugu.server.jobs as jobs
    owned = tmp_path / 'owned-snapshot'
    started, release = threading.Event(), threading.Event()
    def copy():
        owned.mkdir()
        started.set()
        release.wait(2)
        return owned
    async def operation():
        task = asyncio.create_task(jobs._materialize_owned_snapshot(asyncio.get_running_loop(), copy))
        await asyncio.to_thread(started.wait, 2)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(operation())
    assert not owned.exists()


def test_safe_errors_redaction_and_canary_preservation(monkeypatch, tmp_path):
    from fugu import cli_audit
    from fugu.types import StageResult, Finding, EvidenceSnippet
    class Stage:
        name = 'concealment'
        async def run(self, job, target):
            return StageResult(stage=self.name, ok=False, error='private SDK body fake-stored-nebius',
                metrics={'call_errors': ['private provider body fake-stored-tavily']}, findings=[Finding(
                    owasp_ids=['LLM01'], stage=self.name, title='inert', detail='fake-stored-nebius', severity='critical',
                    confidence='deterministic', evidence=[EvidenceSnippet(source='inert',
                        excerpt='fake-stored-tavily FUGU-CANARY-demo')])])
    monkeypatch.setattr(cli_audit, '_build_stages', lambda *args, **kwargs: [Stage()])
    (tmp_path / 'SKILL.md').write_text('# Ordinary')
    report = cli_audit.run_cli_audit(str(tmp_path), 'full',
        CredentialSet(nebius='fake-stored-nebius', tavily='fake-stored-tavily'))
    encoded = json.dumps(report)
    assert 'fake-stored-' not in encoded and 'private SDK body' not in encoded and 'private provider body' not in encoded
    assert 'FUGU-CANARY-demo' in encoded
    assert report['verdict']['status'] == 'fail' and report['exit_code'] == 3


def test_hostile_source_dotenv_not_consumed(monkeypatch, tmp_path, capsys):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'SKILL.md').write_text('# Ordinary skill')
    (source / '.env').write_text('NEBIUS_API_KEY=fake-hostile-key\nNEBIUS_BASE_URL=https://evil.invalid/v1\n')
    monkeypatch.chdir(source)
    monkeypatch.delenv('NEBIUS_API_KEY', raising=False)
    assert main(['audit', '.', '--mode', 'offline', '--format', 'json']) == 0
    assert 'fake-hostile-key' not in capsys.readouterr().out
    import os
    assert 'NEBIUS_API_KEY' not in os.environ


def test_chamber_cleanup_continues_when_docker_unavailable(monkeypatch, tmp_path):
    from fugu.detonation.docker_driver import DockerDriver
    owned = tmp_path / 'owned-logs'
    owned.mkdir()
    unrelated = tmp_path / 'unrelated'
    unrelated.mkdir()
    calls = []
    async def unavailable(args, **kwargs):
        calls.append(args)
        raise FileNotFoundError('inert docker unavailable')
    driver = DockerDriver()
    monkeypatch.setattr(driver, '_run', unavailable)
    asyncio.run(driver._teardown('owned-fake', 'owned-network', 'owned-mitm', 'owned-dns',
        ['owned-victim'], owned, 'owned-image'))
    assert not owned.exists() and unrelated.exists()
    assert ['network', 'rm', 'owned-network'] in calls
    assert ['rm', '-f', 'owned-victim'] in calls


def test_cancelled_trigger_process_reaped(monkeypatch, tmp_path):
    from fugu.detonation.docker_driver import DockerDriver
    proc = Process(cancel=True)
    async def launch(*args, **kwargs): return proc
    async def cancel(*args, **kwargs): raise asyncio.CancelledError()
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', launch)
    monkeypatch.setattr(asyncio, 'sleep', cancel)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(DockerDriver()._exec_trigger(run_id='owned-fake', victim='owned-victim',
            net='owned-net', dns_ip='192.0.2.1', mitm_ip='192.0.2.2', image='inert',
            trigger='inert', timeout_s=1, canary_env={}, canary_values=[], logs_dir=tmp_path))
    assert proc.killed and proc.drained


def test_failed_member_private_error_body_not_in_composition_metadata(monkeypatch, tmp_path):
    from fugu import cli_audit
    from fugu.types import StageResult
    source = tmp_path / 'source'
    for name in ['one', 'two']:
        unit = source / name
        unit.mkdir(parents=True)
        (unit / 'SKILL.md').write_text('# Ordinary')
    class Stage:
        name = 'semantic'
        async def run(self, job, target):
            return StageResult(stage=self.name, ok=False, error='private SDK body fake-nebius')
    monkeypatch.setattr(cli_audit, '_build_stages', lambda *args, **kwargs: [Stage()])
    report = cli_audit.run_cli_audit(str(source), 'full', CredentialSet(nebius='fake-nebius'))
    encoded = json.dumps(report)
    assert 'private SDK body' not in encoded and 'fake-nebius' not in encoded
    assert report['exit_code'] == 3
