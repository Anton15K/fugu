from bench.cost_pilot.contracts import Attribution, ULTRA, SUPER


def fake_tariffs():
    return {'schema_version': 1, 'models': {model: {
        'input_micro_per_million': 1000000, 'output_micro_per_million': 3000000,
        'cache_micro_per_million': 1000000, 'input_bound': 1000,
        'billable_output_bound': 5000, 'context_tokens': 6000,
        'reasoning_in_output_total': True, 'cache_partition': 'separate',
        'authority': 'FAKE-TEST-NOT-LIVE'} for model in (ULTRA, SUPER)},
        'tavily_micro_per_credit': 8000, 'basic_credit_bound': 1,
        'extra_fee_bound_micro': 0, 'account_verified': False}


def fake_attribution(arm='agent'):
    return Attribution('c0', arm, 'root', 'test', 'principal', 1)
