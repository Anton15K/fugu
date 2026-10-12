import pytest
from bench.cost_pilot.contracts import ULTRA, SafetyStop
from bench.cost_pilot.pricing import Pricing, token_charge
from tests.cost_pilot.support import fake_tariffs


def test_reasoning_is_billed_not_visible_text():
    p = Pricing(fake_tariffs(), test_only=True)
    bound = p.bound('nebius', ULTRA)
    assert bound.microdollars == 17000
    assert p.settle(bound, {'prompt_tokens': 200, 'completion_tokens': 4500,
        'completion_tokens_details': {'reasoning_tokens': 4499}}, ULTRA) == 13700


@pytest.mark.parametrize('usage,reason', [({}, 'usage_unknown'),
    ({'prompt_tokens': True, 'completion_tokens': 1}, 'usage_unknown'),
    ({'prompt_tokens': 200, 'completion_tokens': 5001}, 'usage_exceeds_bound'),
    ({'prompt_tokens': 1001, 'completion_tokens': 1}, 'usage_exceeds_bound')])
def test_unknown_and_out_of_contract_usage_blocks(usage, reason):
    p = Pricing(fake_tariffs(), test_only=True)
    with pytest.raises(SafetyStop, match=reason): p.settle(p.bound('nebius', ULTRA), usage, ULTRA)


def test_cached_partition_is_not_double_charged():
    tariff = fake_tariffs(); tariff['models'][ULTRA]['cache_micro_per_million'] = 500000
    p = Pricing(tariff, test_only=True)
    assert p.settle(p.bound('nebius', ULTRA), {'prompt_tokens': 200, 'completion_tokens': 1,
        'prompt_tokens_details': {'cached_tokens': 100}}, ULTRA) == 153


def test_separately_billed_reasoning_requires_rate_and_bound():
    tariff = fake_tariffs(); model = tariff['models'][ULTRA]
    model['reasoning_in_output_total'] = False
    with pytest.raises(SafetyStop, match='reasoning_contract'): Pricing(tariff, test_only=True)
    model.update(reasoning_micro_per_million=4000000, reasoning_bound=1000)
    p = Pricing(tariff, test_only=True)
    assert p.settle(p.bound('nebius', ULTRA), {'prompt_tokens': 100, 'completion_tokens': 20,
        'completion_tokens_details': {'reasoning_tokens': 500}}, ULTRA) == 2160


def test_unknown_models_services_and_model_tariff_drift():
    p = Pricing(fake_tariffs(), test_only=True); bound = p.bound('nebius', ULTRA)
    with pytest.raises(SafetyStop): p.bound('nebius', 'unknown')
    with pytest.raises(SafetyStop): p.bound('paid-scanner')
    with pytest.raises(SafetyStop, match='model_drift'): p.settle(bound, {}, 'different')
    p.tariffs['models'][ULTRA]['output_micro_per_million'] += 1
    with pytest.raises(SafetyStop, match='tariff_drift'): p.settle(bound, {}, ULTRA)


def test_tavily_credit_contract_and_missing_usage():
    p = Pricing(fake_tariffs(), test_only=True); bound = p.bound('tavily')
    assert bound.microdollars == 8000
    assert p.settle(bound, {'credits': 1}, '') == 8000
    with pytest.raises(SafetyStop, match='usage_unknown'): p.settle(bound, {}, '')
    with pytest.raises(SafetyStop, match='usage_exceeds_bound'): p.settle(bound, {'credits': 2}, '')


def test_live_authority_never_accepts_test_tariffs_or_estimates():
    with pytest.raises(SafetyStop, match='tariff_authority'): Pricing(fake_tariffs())
    p = Pricing(fake_tariffs(), test_only=True)
    with pytest.raises(SafetyStop, match='input_bound_authority'): p.bound('nebius', ULTRA, input_bound=10)


@pytest.mark.parametrize('tokens', [True, -1, 0.1, float('nan')])
def test_integer_rounding_rejects_unsafe_numbers(tokens):
    with pytest.raises((ValueError, SafetyStop)): token_charge(tokens, 300000)


def test_rounds_one_fractional_token_up():
    assert token_charge(1, 300000) == 1


def test_unpriced_extra_fee_blocks():
    t=fake_tariffs();t['extra_fee_bound_micro']=1
    with pytest.raises(SafetyStop,match='extra_fee_contract'):Pricing(t,test_only=True)


def test_live_official_us_endpoint(tmp_path):
    import hashlib
    p=tmp_path/'authority';p.write_text('FAKE local authority boundary, no live account verification')
    t=fake_tariffs();t.update(account_verified=True,verified_at='2026-10-12',endpoint='https://api.tokenfactory.us-central1.nebius.com/v1/',authority_documents=[{'url':'https://docs.nebius.com/pricing','path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}])
    for m in t['models'].values():m.update(authority='https://docs.nebius.com/pricing',context_unit='tokens',output_unit='billable_tokens',reasoning_contract_verified=True,cache_contract_verified=True)
    assert Pricing(t).bound('nebius',ULTRA).microdollars>0
