"""Behavioral regressions for independently reproduced COST-PREFIX findings."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from fugu.credentials import CredentialSet
from bench.cost_pilot.contracts import ULTRA, SUPER, SafetyStop
from bench.cost_pilot.ledger import Ledger
from bench.cost_pilot.pricing import Pricing
from bench.cost_pilot.transport import GuardedTransport
from tests.cost_pilot.support import fake_tariffs, fake_attribution
from tests.cost_pilot.test_transport import REQ, response


def guarded(ledger, tmp_path, tariffs=None, keys=None):
    return GuardedTransport(ledger, Pricing(tariffs or fake_tariffs(), test_only=True),
                            tmp_path / 'evidence', keys or CredentialSet(),
                            lambda: {'status': 'admitted'})


@pytest.mark.parametrize('metadata,source', [
    ({'usage': {'credits': 1}}, 'observed'),
    ({'credits': 1}, 'observed'),
    ({'credits': 1, 'usage': {'credits': 1}}, 'observed'),
    ({}, 'frozen_contract'),
])
def test_prefix01_valid_credits_keep_observed_contractual_distinction(tmp_path, monkeypatch, metadata, source):
    tariffs = fake_tariffs(); tariffs['basic_success_exact_credit_contract_verified'] = True
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path, tariffs)
        monkeypatch.setattr(transport, '_perform_http', lambda *a: {'results': [], **metadata})
        transport.tavily('ordinary public advisory', fake_attribution('fugu'))
        event = next(e for e in ledger.events() if e['kind'] == 'settle')
        assert event['actual'] == 8000
        assert event['usage'] == {'credits': 1, 'credit_source': source}
        assert ledger.summary()['stop'] is None


@pytest.mark.parametrize('metadata', [
    {'usage': {'credits': 2}}, {'credits': 1, 'usage': {'credits': 2}},
    {'credits': None}, {'usage': {'credits': None}}, {'usage': {'credits': True}},
    {'usage': {'credits': '1'}}, {'usage': {'credits': -1}},
    {'usage': {'credits': 1.5}}, {'usage': []}, {'usage': None},
    {'credits': 1, 'usage': {'credits': '1'}},
])
def test_prefix01_bad_credits_retain_and_stop_after_native_catch(tmp_path, monkeypatch, metadata):
    tariffs = fake_tariffs(); tariffs['basic_success_exact_credit_contract_verified'] = True
    calls = []
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path, tariffs)
        def http(*a):
            calls.append('search'); return {'results': [], **metadata}
        monkeypatch.setattr(transport, '_perform_http', http)
        with pytest.raises(SafetyStop): transport.tavily('ordinary public advisory', fake_attribution('fugu'))
        # Native stage catches the first error; the shared owner must still stop.
        with pytest.raises(SafetyStop): transport.tavily('ordinary second advisory', fake_attribution('fugu'))
        with pytest.raises(SafetyStop): transport.sdk(REQ, lambda: calls.append('sdk'), fake_attribution('fugu'))
        assert calls == ['search']
        assert ledger.summary()['known_micro'] == 0
        assert ledger.summary()['unknown_upper_micro'] == 8000
        assert ledger.summary()['stop'] is not None
        assert not any(e['kind'] == 'settle' for e in ledger.events())


def test_prefix01_missing_credits_without_frozen_contract_is_unknown(tmp_path, monkeypatch):
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path)
        monkeypatch.setattr(transport, '_perform_http', lambda *a: {'results': []})
        with pytest.raises(SafetyStop): transport.tavily('ordinary advisory', fake_attribution())
        assert ledger.summary()['unknown_upper_micro'] == 8000


@pytest.mark.parametrize('details', [None, {}, {'reasoning_tokens': None},
    {'reasoning_tokens': True}, {'reasoning_tokens': -1}, {'reasoning_tokens': '0'}, []])
def test_prefix02_separate_reasoning_missing_or_malformed_retains_liability(tmp_path, details):
    tariffs = fake_tariffs(); tariffs['models'][ULTRA].update(
        reasoning_in_output_total=False, reasoning_bound=1000,
        reasoning_micro_per_million=4000000)
    calls = []
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path, tariffs)
        def call():
            calls.append('sdk')
            return {'model': ULTRA, 'usage': {'prompt_tokens': 100, 'completion_tokens': 10,
                                             'completion_tokens_details': details}}
        with pytest.raises(SafetyStop, match='usage_unknown'):
            transport.sdk(REQ, call, fake_attribution('fugu'))
        with pytest.raises(SafetyStop): transport.sdk(REQ, call, fake_attribution('fugu'))
        assert calls == ['sdk']
        assert ledger.summary()['unknown_upper_micro'] == 21000
        assert ledger.summary()['known_micro'] == 0
        assert ledger.summary()['stop'] is not None


@pytest.mark.parametrize('details,want', [(None, 130), ({}, 130),
    ({'reasoning_tokens': 0}, 130), ({'reasoning_tokens': 10}, 130)])
def test_prefix02_inclusive_reasoning_detail_optional(details, want):
    pricing = Pricing(fake_tariffs(), test_only=True)
    assert pricing.settle(pricing.bound('nebius', ULTRA),
        {'prompt_tokens': 100, 'completion_tokens': 10, 'completion_tokens_details': details}, ULTRA) == want


@pytest.mark.parametrize('tokens,want', [(0, 130), (500, 2130)])
def test_prefix02_separate_reasoning_observed_zero_or_positive(tokens, want):
    tariffs = fake_tariffs(); tariffs['models'][ULTRA].update(
        reasoning_in_output_total=False, reasoning_bound=1000,
        reasoning_micro_per_million=4000000)
    pricing = Pricing(tariffs, test_only=True)
    assert pricing.settle(pricing.bound('nebius', ULTRA), {'prompt_tokens': 100,
        'completion_tokens': 10, 'completion_tokens_details': {'reasoning_tokens': tokens}}, ULTRA) == want


@pytest.mark.parametrize('override', [
    {'n': 2}, {'n': True}, {'n': None}, {'n': 0}, {'n': '1'},
    {'max_tokens': None}, {'max_tokens': True}, {'max_tokens': -1},
    {'max_tokens': 4097}, {'max_tokens': 1.5}, {'max_tokens': '4096'},
    {'max_completion_tokens': 1000000}, {'max_completion_tokens': None},
    {'stream': True}, {'stream': 'false'}, {'stream': None},
    {'extra_body': {'max_tokens': 1000000}}, {'extra_headers': {'x-route': 'other'}},
    {'timeout': 300}, {'temperature': True}, {'temperature': float('nan')},
])
def test_prefix03_unsafe_request_rejected_before_admission_reservation_or_callback(tmp_path, override):
    admissions = []; callbacks = []
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0')
        transport = GuardedTransport(ledger, Pricing(fake_tariffs(), test_only=True),
            tmp_path / 'e', CredentialSet(), lambda: (admissions.append(1), {'status': 'admitted'})[1])
        with pytest.raises(SafetyStop, match='request_parameters'):
            transport.sdk({**REQ, **override}, lambda: (callbacks.append(1), response())[1], fake_attribution())
        assert not admissions and not callbacks
        assert not any(e['kind'] in {'reserve', 'dispatch'} for e in ledger.events())


def test_prefix03_missing_output_limit_never_uses_provider_default(tmp_path):
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path)
        request = {k: v for k, v in REQ.items() if k != 'max_tokens'}
        with pytest.raises(SafetyStop, match='request_parameters'):
            transport.sdk(request, lambda: pytest.fail('provider entered'), fake_attribution())
        assert not any(e['kind'] == 'reserve' for e in ledger.events())


def test_prefix03_requested_output_must_fit_frozen_bound(tmp_path):
    tariffs = fake_tariffs(); tariffs['models'][ULTRA]['billable_output_bound'] = 100
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path, tariffs)
        with pytest.raises(SafetyStop, match='request_parameters'):
            transport.sdk(REQ, lambda: pytest.fail('provider entered'), fake_attribution())
        assert not any(e['kind'] == 'reserve' for e in ledger.events())


@pytest.mark.parametrize('limit', [0, 4096])
def test_prefix03_supported_explicit_limits_dispatch_once(tmp_path, limit):
    calls = []
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path)
        request = {**REQ, 'max_tokens': limit, 'n': 1, 'stream': False}
        def call():
            calls.append(copy.deepcopy(request)); return response()
        transport.sdk(request, call, fake_attribution())
        assert calls == [request]
        assert len([e for e in ledger.events() if e['kind'] == 'reserve']) == 1
        assert len([e for e in ledger.events() if e['kind'] == 'dispatch']) == 1


def policy_client(create, **overrides):
    values = {'max_retries': 0, 'timeout': 90,
              'base_url': 'https://api.tokenfactory.nebius.com/v1/',
              '_client': SimpleNamespace(follow_redirects=False),
              'chat': SimpleNamespace(completions=SimpleNamespace(create=create))}
    return SimpleNamespace(**{**values, **overrides})


@pytest.mark.parametrize('policy', [
    {'max_retries': 2}, {'max_retries': True}, {'max_retries': None},
    {'timeout': 300}, {'timeout': None}, {'timeout': float('nan')}, {'timeout': -1},
    {'timeout': SimpleNamespace(connect=90, read=None, write=90, pool=90)},
    {'base_url': 'https://wrong.example/v1/'},
    {'base_url': 'https://api.tokenfactory.us-central1.nebius.com/v1/'},
    {'base_url': 'https://api.tokenfactory.nebius.com/v1/?route=other'},
    {'_client': SimpleNamespace(follow_redirects=True)}, {'_client': None},
])
@pytest.mark.parametrize('role', ['principal', 'reviewer'])
def test_prefix06_bad_policy_never_dispatches_role(tmp_path, policy, role):
    from bench.cost_pilot.agent import run_agent
    from bench.cost_pilot.prompts import extract_prompts
    from tests.cost_pilot.test_agent import setup
    client, tools, calls = setup(tmp_path)
    original = client.chat.completions.create
    configured = policy_client(original)
    if role == 'principal':
        for key, value in policy.items(): setattr(configured, key, value)
    else:
        def create(**request):
            result = original(**request)
            # Drift after the draft: Super must not use an unbounded client.
            if len(calls) == 2:
                for key, value in policy.items(): setattr(configured, key, value)
            return result
        configured.chat.completions.create = create
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path)
        result = run_agent('c0', 'security', tools, transport, configured,
            extract_prompts(Path('docs/superpowers/specs/2026-10-12-whole-system-cost-benchmark-design.md')), tmp_path / 'agent')
        assert result.workflow == 'partial'
        assert len(calls) == (0 if role == 'principal' else 2)
        assert not any(request['model'] == SUPER for request in calls)
        assert len([e for e in ledger.events() if e['kind'] == 'dispatch']) == len(calls)


@pytest.mark.parametrize('missing', ['max_retries', 'timeout', 'base_url', '_client'])
def test_prefix06_missing_policy_refused_before_direct_attempt(tmp_path, missing):
    from bench.cost_pilot.agent import run_agent
    from bench.cost_pilot.prompts import extract_prompts
    from tests.cost_pilot.test_agent import setup
    client, tools, calls = setup(tmp_path); client = policy_client(client.chat.completions.create)
    delattr(client, missing)
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path)
        result = run_agent('c0', 'security', tools, transport, client,
            extract_prompts(Path('docs/superpowers/specs/2026-10-12-whole-system-cost-benchmark-design.md')), tmp_path / 'agent')
        assert result.workflow == 'partial' and result.raw['attempts'] == 0 and not calls
        assert not any(e['kind'] in {'reserve', 'dispatch'} for e in ledger.events())


@pytest.mark.parametrize('endpoint', ['https://api.tokenfactory.nebius.com/v1/',
    'https://api.tokenfactory.us-central1.nebius.com/v1/'])
def test_prefix06_real_sdk_safe_policy_is_accepted_without_network(tmp_path, endpoint):
    from openai import OpenAI, DefaultHttpxClient
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0')
        transport = guarded(ledger, tmp_path, keys=CredentialSet(base_url=endpoint))
        with OpenAI(api_key='FAKE-ONLY', base_url=endpoint, max_retries=0, timeout=90,
                    http_client=DefaultHttpxClient(timeout=90, follow_redirects=False, trust_env=False)) as client:
            wrapped = transport.sdk_proxy(client, fake_attribution())
            assert wrapped.base_url == client.base_url
        assert not any(e['kind'] in {'reserve', 'dispatch'} for e in ledger.events())


def test_prefix06_native_proxy_rechecks_changed_policy_before_reservation(tmp_path):
    calls = []
    client = policy_client(lambda **kw: (calls.append(kw), response())[1])
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path)
        wrapped = transport.sdk_proxy(client, fake_attribution('fugu'))
        client._client.follow_redirects = True
        with pytest.raises(SafetyStop, match='sdk_redirect_policy'):
            wrapped.chat.completions.create(**REQ)
        assert not calls and not any(e['kind'] == 'reserve' for e in ledger.events())


def source_tools(tmp_path, text='ordinary\r\n', web=None):
    from bench.cost_pilot.tools import ToolRegistry
    from bench.cost_pilot.freeze import tree_manifest
    source = tmp_path / 'source'; source.mkdir(); (source / 'a.py').write_bytes(text.encode())
    journal = tmp_path / 'tools'; manifest = tree_manifest(source)
    def fresh(): return ToolRegistry(source, 'c0', manifest['sha256'], journal, web or (lambda q: {'results': []}))
    return fresh, journal


@pytest.mark.parametrize('mutation', ['text', 'range', 'line', 'file_hash', 'path',
    'next_cursor', 'total_lines', 'evidence_id', 'self_declared_hash', 'malformed'])
def test_prefix05_cached_source_tamper_never_returns_or_earns_coverage(tmp_path, mutation):
    fresh, journal = source_tools(tmp_path); tool = fresh()
    first = tool.dispatch('read_file', {'path': 'a.py'})
    path = journal / 'replies' / (first.evidence_id + '.json'); value = json.loads(path.read_bytes())
    if mutation == 'text': value['segments'][0]['text'] = 'FORGED!!\r\n'
    elif mutation == 'range': value['segments'][0]['char_end'] = 100000
    elif mutation == 'line': value['segments'][0]['line'] = 2
    elif mutation == 'file_hash': value['file_hash'] = 'f' * 64
    elif mutation == 'path': value['path'] = '../other'
    elif mutation == 'next_cursor': value['next_cursor'] = 'f' * 32
    elif mutation == 'total_lines': value['total_lines'] = 0
    elif mutation == 'evidence_id': value['evidence_id'] = 'f' * 64
    elif mutation == 'self_declared_hash':
        value['segments'][0]['text'] = 'FORGED!!\r\n'
        value['payload_sha256'] = hashlib.sha256(json.dumps(value).encode()).hexdigest()
    path.write_text('not JSON' if mutation == 'malformed' else json.dumps(value))
    tool = fresh()
    with pytest.raises(SafetyStop): tool.dispatch('read_file', {'path': 'a.py'})
    assert tool.coverage()['fully_read_paths'] == []
    assert tool.coverage()['returned_ranges'] == {}
    assert tool.coverage()['incomplete']


def test_prefix05_repeat_and_reopen_idempotent_web_no_redispatch(tmp_path):
    web_calls = []
    fresh, journal = source_tools(tmp_path, 'α😀' * 7000 + '\r\n',
        lambda q: (web_calls.append(q), {'results': [{'title': 'advisory'}]})[1])
    tool = fresh(); args = {'path': 'a.py'}; first = tool.dispatch('read_file', args)
    second = tool.dispatch('read_file', {**args, 'cursor': first.payload['next_cursor']})
    assert first.payload['next_cursor'] is not None
    assert fresh().dispatch('read_file', args) == first
    assert fresh().dispatch('read_file', {**args, 'cursor': first.payload['next_cursor']}) == second
    web = tool.dispatch('search_web', {'query': 'ordinary advisory'})
    assert fresh().dispatch('search_web', {'query': 'ordinary advisory'}) == web
    assert web_calls == ['ordinary advisory']


def test_prefix05_changed_owner_cursor_rejected_without_coverage(tmp_path):
    fresh, journal = source_tools(tmp_path, 'x' * 18000); tool = fresh()
    first = tool.dispatch('read_file', {'path': 'a.py'}); cursor = first.payload['next_cursor']
    path = journal / 'cursors' / (cursor + '.json'); entry = json.loads(path.read_bytes())
    entry['state']['offset'] += 10; path.write_text(json.dumps(entry))
    tool = fresh()
    with pytest.raises(SafetyStop): tool.dispatch('read_file', {'path': 'a.py', 'cursor': cursor})
    assert not tool.coverage()['returned_ranges']


def resign_owned_fixture(journal, payload, evidence, cursor=None):
    """Fixture simulates owner cache corruption; source checks must be independent."""
    import hmac
    from bench.cost_pilot.freeze import canonical
    owner = json.loads((journal / 'owner-integrity.json').read_bytes())
    binding = {'snapshot': 'c0', 'hash': owner['hash'], 'name': 'read_file',
               'arguments': {'path': 'a.py', 'start_line': 1, 'end_line': 200}}
    body = {'binding': binding, 'cursor': cursor, 'evidence_id': evidence, 'payload': payload}
    mac = hmac.new(bytes.fromhex(owner['key']), canonical(body), hashlib.sha256).hexdigest()
    (journal / 'replies' / (evidence + '.json')).write_text(json.dumps(payload))
    (journal / 'integrity' / (evidence + '.json')).write_text(json.dumps({'mac': mac}))


@pytest.mark.parametrize('mutation', ['text', 'gap', 'overlap', 'range', 'file_hash',
    'range_complete', 'eof', 'total_lines', 'cursor_state'])
def test_prefix05_source_validation_independent_of_cache_signature(tmp_path, mutation):
    fresh, journal = source_tools(tmp_path, 'x' * 18000 + '\r\n'); tool = fresh()
    first = tool.dispatch('read_file', {'path': 'a.py'}); payload = copy.deepcopy(first.payload)
    if mutation == 'text': payload['segments'][0]['text'] = 'FORGED'
    elif mutation == 'gap': payload['segments'][0]['char_start'] += 1
    elif mutation == 'overlap': payload['segments'].append(copy.deepcopy(payload['segments'][0]))
    elif mutation == 'range': payload['segments'][0]['char_end'] = 18003
    elif mutation == 'file_hash': payload['file_hash'] = 'f' * 64
    elif mutation == 'range_complete': payload['range_complete'] = True
    elif mutation == 'eof': payload['eof'] = True
    elif mutation == 'total_lines': payload['total_lines'] = 2
    elif mutation == 'cursor_state':
        # Valid owner-issued cursor from a later page still cannot skip source.
        second = tool.dispatch('read_file', {'path': 'a.py', 'cursor': first.payload['next_cursor']})
        payload['next_cursor'] = second.payload['next_cursor']
    resign_owned_fixture(journal, payload, first.evidence_id)
    tool = fresh()
    with pytest.raises(SafetyStop): tool.dispatch('read_file', {'path': 'a.py'})
    assert tool.coverage()['returned_ranges'] == {}


def test_prefix05_owner_integrity_permissions_rechecked_on_live_registry(tmp_path):
    fresh, journal = source_tools(tmp_path); tool = fresh()
    tool.dispatch('read_file', {'path': 'a.py'})
    (journal / 'owner-integrity.json').chmod(0o644)
    with pytest.raises(SafetyStop, match='journal_integrity'):
        tool.dispatch('read_file', {'path': 'a.py'})


def test_prefix05_nonfinite_cache_is_safe_integrity_error(tmp_path):
    fresh, journal = source_tools(tmp_path); tool = fresh()
    first = tool.dispatch('read_file', {'path': 'a.py'})
    path = journal / 'replies' / (first.evidence_id + '.json')
    path.write_text('{"invalid":NaN}')
    with pytest.raises(SafetyStop): fresh().dispatch('read_file', {'path': 'a.py'})


@pytest.mark.parametrize('directory', ['replies', 'cursors', 'integrity'])
def test_prefix05_owner_journal_never_writes_through_symlink(tmp_path, directory):
    fresh, journal = source_tools(tmp_path, 'x' * 18000); tool = fresh()
    outside = tmp_path / 'outside'; outside.mkdir()
    (journal / directory).symlink_to(outside, target_is_directory=True)
    with pytest.raises(SafetyStop, match='journal_integrity'):
        tool.dispatch('read_file', {'path': 'a.py'})
    assert list(outside.iterdir()) == []


def test_prefix05_recomputed_cursor_digest_not_owner_issued(tmp_path):
    from bench.cost_pilot.freeze import canonical
    fresh, journal = source_tools(tmp_path, 'x' * 18000); tool = fresh()
    first = tool.dispatch('read_file', {'path': 'a.py'})
    entry = json.loads((journal / 'cursors' / (first.payload['next_cursor'] + '.json')).read_bytes())
    entry['state']['offset'] += 1
    forged = hashlib.sha256(canonical(entry)).hexdigest()[:32]
    path = journal / 'cursors' / (forged + '.json'); path.write_text(json.dumps(entry)); path.chmod(0o600)
    with pytest.raises(SafetyStop):
        fresh().dispatch('read_file', {'path': 'a.py', 'cursor': forged})


def test_prefix07_final_history_keeps_each_original_tool_pair_once(tmp_path):
    from bench.cost_pilot.agent import run_agent
    from bench.cost_pilot.prompts import extract_prompts
    from tests.cost_pilot.test_agent import setup
    client, tools, calls = setup(tmp_path)
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path)
        result = run_agent('c0', 'security', tools, transport, client,
            extract_prompts(Path('docs/superpowers/specs/2026-10-12-whole-system-cost-benchmark-design.md')), tmp_path / 'agent')
    assert result.workflow == 'complete'
    messages = calls[-1]['messages']
    assert [m['tool_call_id'] for m in messages if m['role'] == 'tool'] == ['call-1']
    assert [c['id'] for m in messages for c in (m.get('tool_calls') or [])] == ['call-1']
    assert messages[2:4] == calls[1]['messages'][2:4]


def test_prefix07_super_new_tools_and_critique_append_in_exact_order(tmp_path):
    from bench.cost_pilot.agent import run_agent
    from bench.cost_pilot.prompts import extract_prompts
    from tests.cost_pilot.test_agent import final
    fresh, journal = source_tools(tmp_path, 'value=1\n'); tools = fresh(); calls = []; responses = []
    def create(**request):
        calls.append(copy.deepcopy(request)); n = len(calls)
        if n in (1, 3):
            message = {'role': 'assistant', 'content': None, 'reasoning_content': 'preserve-' + str(n),
                'tool_calls': [{'id': 'principal-1' if n == 1 else 'super-1', 'type': 'function',
                    'function': {'name': 'read_file' if n == 1 else 'search_files',
                        'arguments': json.dumps({'path': 'a.py'} if n == 1 else {'query': 'value'})}}]}
        else:
            value = {'critiques': [], 'additional_candidates': [], 'unknowns': [],
                     'coverage': {'reviewed_search': True}} if n == 4 else final()
            message = {'role': 'assistant', 'content': json.dumps(value)}
        result = {'model': request['model'], 'id': 'r' + str(n),
            'choices': [{'finish_reason': 'tool_calls' if n in (1, 3) else 'stop', 'message': message}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 5}}
        responses.append(copy.deepcopy(result)); return result
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path)
        result = run_agent('c0', 'security', tools, transport, policy_client(create),
            extract_prompts(Path('docs/superpowers/specs/2026-10-12-whole-system-cost-benchmark-design.md')), tmp_path / 'agent')
    assert result.workflow == 'complete' and len(calls) == 5
    messages = calls[-1]['messages']
    assert [m['role'] for m in messages] == ['system', 'user', 'assistant', 'tool', 'assistant',
        'user', 'assistant', 'tool', 'assistant', 'user']
    assert [m['tool_call_id'] for m in messages if m['role'] == 'tool'] == ['principal-1', 'super-1']
    assert [c['id'] for m in messages for c in (m.get('tool_calls') or [])] == ['principal-1', 'super-1']
    assert messages[:4] == calls[1]['messages']
    assert messages[4] == responses[1]['choices'][0]['message']
    assert messages[5:8] == calls[3]['messages'][5:8]
    assert messages[8] == responses[3]['choices'][0]['message']
    evidence = [json.loads(m['content'])['evidence_id'] for m in messages if m['role'] == 'tool']
    assert len(set(evidence)) == 2 and set(evidence) == set(result.raw['evidence_ids'])
    assert json.dumps(result.raw['critique']) in messages[-1]['content']


def endpoint_tariffs(tmp_path, endpoint):
    authority = tmp_path / 'authority.txt'
    authority.write_text('SYNTHETIC structural fixture; not real account or public tariff evidence')
    tariffs = fake_tariffs()
    tariffs.update(account_verified=True, verified_at='SYNTHETIC-ONLY', endpoint=endpoint,
        authority_documents=[{'url': 'https://example.org/synthetic', 'path': str(authority),
                              'sha256': hashlib.sha256(authority.read_bytes()).hexdigest()}])
    for model in tariffs['models'].values():
        model.update(authority='SYNTHETIC UNIT STRUCTURE ONLY', context_unit='tokens',
            output_unit='billable_tokens', reasoning_contract_verified=True, cache_contract_verified=True)
    return tariffs


@pytest.mark.parametrize('endpoint', ['https://api.tokenfactory.nebius.com/v1/',
    'https://api.tokenfactory.us-central1.nebius.com/v1/'])
def test_prefix04_official_origins_consistent_across_pricing_credentials_transport(tmp_path, endpoint):
    from fugu.credentials import validated_base_url
    assert validated_base_url({'NEBIUS_BASE_URL': endpoint}) == endpoint
    pricing = Pricing(endpoint_tariffs(tmp_path, endpoint))
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0')
        transport = GuardedTransport(ledger, pricing, tmp_path / 'e',
                                    CredentialSet(base_url=endpoint), lambda: {'status': 'admitted'})
        transport.validate_client(policy_client(lambda **kw: pytest.fail('outbound forbidden'), base_url=endpoint))
        assert not any(e['kind'] == 'dispatch' for e in ledger.events())


@pytest.mark.parametrize('endpoint', [
    'https://api.tokenfactory.us.nebius.com/v1/',
    'https://user@api.tokenfactory.nebius.com/v1/',
    'https://api.tokenfactory.nebius.com:443/v1/',
    'https://api.tokenfactory.nebius.com/v1/?x=1',
    'https://api.tokenfactory.nebius.com/v1/#x',
    'https://api.tokenfactory.nebius.com/v1//',
    'http://api.tokenfactory.nebius.com/v1/',
])
def test_prefix04_altered_origins_rejected_consistently_without_callbacks(tmp_path, endpoint):
    from fugu.credentials import validated_base_url, CredentialError
    with pytest.raises(CredentialError): validated_base_url({'NEBIUS_BASE_URL': endpoint})
    with pytest.raises(SafetyStop, match='tariff_endpoint'): Pricing(endpoint_tariffs(tmp_path, endpoint))
    with Ledger(tmp_path / 'ledger') as ledger:
        ledger.open_pair('c0'); transport = guarded(ledger, tmp_path, keys=CredentialSet(base_url=endpoint))
        with pytest.raises(SafetyStop, match='sdk_endpoint'):
            transport.sdk_proxy(policy_client(lambda **kw: pytest.fail('provider entered'), base_url=endpoint), fake_attribution())
        assert not any(e['kind'] in {'reserve', 'dispatch'} for e in ledger.events())


def test_prefix05_missing_reply_does_not_redispatch_cached_web(tmp_path):
    calls = []
    fresh, journal = source_tools(tmp_path, web=lambda q: (calls.append(q), {'results': []})[1])
    first = fresh().dispatch('search_web', {'query': 'ordinary advisory'})
    (journal / 'replies' / (first.evidence_id + '.json')).unlink()
    with pytest.raises(SafetyStop): fresh().dispatch('search_web', {'query': 'ordinary advisory'})
    assert calls == ['ordinary advisory']


def test_prefix05_missing_owner_key_never_reinitializes_existing_evidence(tmp_path):
    fresh, journal = source_tools(tmp_path)
    first = fresh().dispatch('read_file', {'path': 'a.py'})
    original = (journal / 'replies' / (first.evidence_id + '.json')).read_bytes()
    (journal / 'owner-integrity.json').unlink()
    with pytest.raises(SafetyStop, match='journal_integrity'): fresh()
    assert not (journal / 'owner-integrity.json').exists()
    assert (journal / 'replies' / (first.evidence_id + '.json')).read_bytes() == original
