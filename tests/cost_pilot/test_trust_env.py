"""Benchmark-only SDK policy: explicit proxy-free construction and dispatch."""
from pathlib import Path
from types import SimpleNamespace
import urllib.request

import importlib
import pytest
from openai import DefaultHttpxClient, OpenAI

httpx = importlib.import_module(DefaultHttpxClient.__mro__[1].__module__.split('.')[0])

from bench.cost_pilot.agent import run_agent
from bench.cost_pilot.contracts import SafetyStop, ULTRA
from bench.cost_pilot.ledger import Ledger
from bench.cost_pilot.pricing import Pricing
from bench.cost_pilot.prompts import extract_prompts
from bench.cost_pilot.transport import GuardedTransport
from fugu.config import credential_scope
from fugu.credentials import CredentialSet
from tests.cost_pilot.support import fake_attribution, fake_tariffs
from tests.cost_pilot.test_agent import setup

ENDPOINTS = ('https://api.tokenfactory.nebius.com/v1/',
             'https://api.tokenfactory.us-central1.nebius.com/v1/')
SPEC = Path('docs/superpowers/specs/2026-10-12-whole-system-cost-benchmark-design.md')
REQUEST = {'model': ULTRA, 'messages': [], 'max_tokens': 4096, 'temperature': .1}


def transport(ledger, path, endpoint, admissions):
    def admit():
        admissions.append(1)
        return {'status': 'admitted'}
    return GuardedTransport(ledger, Pricing(fake_tariffs(), test_only=True),
                            path/'receipts', CredentialSet('FAKE-ONLY', base_url=endpoint), admit)


def policy(client, value):
    if value == 'missing':
        del client._client.trust_env
    else:
        client._client.trust_env = value


@pytest.mark.parametrize('endpoint', ENDPOINTS)
@pytest.mark.parametrize('value', [True, None, 'missing', 0])
@pytest.mark.parametrize('after', [0, 1, 2, 3], ids=['initial', 'principal-drift', 'reviewer-drift', 'final-principal-drift'])
def test_direct_policy_rejected_before_initial_liability_or_next_role(tmp_path, endpoint, value, after):
    client, tools, calls = setup(tmp_path)
    client.base_url = endpoint
    client._client = SimpleNamespace(follow_redirects=False, trust_env=False)
    create = client.chat.completions.create
    if after == 0:
        policy(client, value)
    else:
        def mutate(**kwargs):
            result = create(**kwargs)
            if len(calls) == after:
                policy(client, value)
            return result
        client.chat.completions.create = mutate
    admissions = []
    with Ledger(tmp_path/'ledger') as ledger:
        ledger.open_pair('c0')
        tr = transport(ledger, tmp_path, endpoint, admissions)
        result = run_agent('c0', 'security', tools, tr, client, extract_prompts(SPEC), tmp_path/'agent')
        assert result.workflow == 'partial'
        assert result.raw['errors'] == ['sdk_trust_env_policy']
        assert result.raw['attempts'] == len(calls) == after
        assert len([e for e in ledger.events() if e['kind'] == 'reserve']) == after
        assert len([e for e in ledger.events() if e['kind'] == 'dispatch']) == after
        assert len(admissions) == 2*after
        if after == 0:
            assert not [e for e in ledger.events() if e['kind'] == 'earmark']


@pytest.mark.parametrize('endpoint', ENDPOINTS)
@pytest.mark.parametrize('value', [True, None, 'missing', 0])
def test_native_proxy_policy_drift_is_rejected_before_callback(tmp_path, endpoint, value):
    client, _, calls = setup(tmp_path)
    client.base_url = endpoint
    client._client = SimpleNamespace(follow_redirects=False, trust_env=False)
    admissions = []
    with Ledger(tmp_path/'ledger') as ledger:
        ledger.open_pair('c0')
        tr = transport(ledger, tmp_path, endpoint, admissions)
        wrapped = tr.sdk_proxy(client, fake_attribution('fugu'))
        policy(client, value)
        with pytest.raises(SafetyStop, match='sdk_trust_env_policy'):
            wrapped.chat.completions.create(**REQUEST)
        assert calls == admissions == []
        assert tr._turns == {}
        assert not [e for e in ledger.events() if e['kind'] in ('earmark', 'reserve', 'dispatch')]


def reply(request):
    return httpx.Response(200, json={
        'id': 'FAKE-ONLY', 'object': 'chat.completion', 'created': 1, 'model': ULTRA,
        'choices': [{'index': 0, 'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': '{}'}}],
        'usage': {'prompt_tokens': 100, 'completion_tokens': 10, 'total_tokens': 110}})


@pytest.mark.parametrize('endpoint', ENDPOINTS)
@pytest.mark.parametrize('trust_env', [True, False])
def test_real_sdk_mocktransport_policy_and_dispatch(tmp_path, endpoint, trust_env):
    requests = []; admissions = []
    def record(request):
        requests.append(request)
        return reply(request)
    with Ledger(tmp_path/'ledger') as ledger:
        ledger.open_pair('c0')
        tr = transport(ledger, tmp_path, endpoint, admissions)
        with OpenAI(api_key='FAKE-ONLY', base_url=endpoint, max_retries=0, timeout=90,
                    http_client=DefaultHttpxClient(timeout=90, follow_redirects=False,
                                                  trust_env=trust_env, transport=httpx.MockTransport(record))) as client:
            if trust_env:
                with pytest.raises(SafetyStop, match='sdk_trust_env_policy'):
                    tr.sdk_proxy(client, fake_attribution('fugu')).chat.completions.create(**REQUEST)
                assert requests == admissions == []
                assert not [e for e in ledger.events() if e['kind'] in ('reserve', 'dispatch')]
            else:
                tr.sdk_proxy(client, fake_attribution('fugu')).chat.completions.create(**REQUEST)
                assert len(requests) == 1 and len(admissions) == 2
                assert str(requests[0].url).startswith(endpoint)
                assert ledger.summary()['known_micro'] == 130
                assert [e['kind'] for e in ledger.events()][-3:] == ['reserve', 'dispatch', 'settle']


@pytest.mark.parametrize('endpoint', ENDPOINTS)
@pytest.mark.parametrize('failure', [None, 'callback', 'constructor'])
def test_canonical_native_constructs_proxy_free_and_restores_after_exceptions(tmp_path, monkeypatch, endpoint, failure):
    import fugu.client
    httpx_client = importlib.import_module(httpx.__name__ + "._client")
    keys = CredentialSet(nebius='FAKE-ONLY', base_url=endpoint)
    production_factory = fugu.client.make_client
    production_constructor = fugu.client.DefaultHttpxClient
    original_open = urllib.request.urlopen
    original_direct = urllib.request.OpenerDirector.open
    created = []; requests = []
    # Outside the benchmark, production keeps its existing default behavior.
    with credential_scope(keys):
        with production_factory() as client:
            assert client._client.trust_env is True
    def record(request):
        requests.append(request)
        if failure == 'callback':
            raise RuntimeError('synthetic callback failure')
        return reply(request)
    def constructor(*args, **kwargs):
        created.append(dict(kwargs))
        assert kwargs.get('trust_env') is False, 'must disable environment trust at construction'
        assert kwargs['timeout'] == 90 and kwargs['follow_redirects'] is False
        if failure == 'constructor':
            raise RuntimeError('synthetic constructor failure')
        return production_constructor(*args, **kwargs, transport=httpx.MockTransport(record))
    monkeypatch.setattr(fugu.client, 'DefaultHttpxClient', constructor)
    def no_environment_proxies():
        raise AssertionError('benchmark must never inspect proxy environment')
    admissions = []
    with Ledger(tmp_path/'ledger') as ledger:
        ledger.open_pair('c0')
        tr = transport(ledger, tmp_path, endpoint, admissions)
        with monkeypatch.context() as scoped:
            scoped.setattr(httpx_client, 'get_environment_proxies', no_environment_proxies)
            def execute():
                with credential_scope(keys), tr.native_scope(fake_attribution('fugu')):
                    client = fugu.client.make_client()
                    try:
                        assert client._client.trust_env is False
                        assert client.max_retries == 0 and client.timeout == 90
                        assert str(client.base_url) == endpoint
                        assert client._client.follow_redirects is False
                        with tr.native_scope(fake_attribution('fugu')):
                            client.chat.completions.create(**REQUEST)
                        assert fugu.client.make_client is not production_factory
                    finally:
                        client.close()
            if failure:
                with pytest.raises(RuntimeError, match='synthetic .* failure'):
                    execute()
            else:
                execute()
        assert len(created) == 1
        assert len(requests) == (0 if failure == 'constructor' else 1)
        assert fugu.client.make_client is production_factory
        assert fugu.client.DefaultHttpxClient is constructor
        assert urllib.request.urlopen is original_open
        assert urllib.request.OpenerDirector.open is original_direct
        assert tr._scope_depth == 0 and tr._attr.get() is None and tr._open is None
    monkeypatch.setattr(fugu.client, 'DefaultHttpxClient', production_constructor)
    with credential_scope(keys):
        with production_factory() as client:
            assert client._client.trust_env is True
