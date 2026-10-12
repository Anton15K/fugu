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
