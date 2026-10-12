from __future__ import annotations

import copy
from pathlib import Path
from .contracts import Record, RequestBound, SafetyStop, ULTRA, SUPER
from .freeze import digest, byte_hash


def integer(value, reason='usage_unknown') -> int:
    if type(value) is not int or value < 0:
        raise SafetyStop(reason)
    return value


def token_charge(tokens: int, rate_micro_per_million: int) -> int:
    return (integer(tokens) * integer(rate_micro_per_million, 'tariff_invalid') + 999999) // 1000000


class Pricing:
    def __init__(self, tariffs: Record, *, test_only: bool = False):
        self.tariffs = copy.deepcopy(tariffs)
        self.test_only = test_only
        self._validate()
        self.hash = digest(self.tariffs)

    def _validate(self) -> None:
        t = self.tariffs
        if t.get('schema_version') != 1 or set(t.get('models', {})) != {ULTRA, SUPER}:
            raise SafetyStop('tariff_models')
        if not self.test_only:
            if t.get('account_verified') is not True or not t.get('verified_at'):
                raise SafetyStop('tariff_authority')
            documents = t.get('authority_documents', [])
            if not documents or not all(d.get('url', '').startswith('https://') and
                    byte_hash(Path(d['path'])) == d['sha256'] for d in documents):
                raise SafetyStop('tariff_authority')
            if t.get('endpoint') not in {'https://api.tokenfactory.nebius.com/v1/',
                                         'https://api.tokenfactory.us.nebius.com/v1/'}:
                raise SafetyStop('tariff_endpoint')
        for model in t['models'].values():
            if not self.test_only and ('FAKE' in model.get('authority', '') or
                    model.get('context_unit') != 'tokens' or model.get('output_unit') != 'billable_tokens' or
                    model.get('reasoning_contract_verified') is not True or model.get('cache_contract_verified') is not True):
                raise SafetyStop('tariff_authority')
            for key in ('input_micro_per_million', 'output_micro_per_million',
                        'cache_micro_per_million', 'context_tokens', 'billable_output_bound'):
                integer(model.get(key), 'tariff_bounds')
            if not model['context_tokens'] or not model['billable_output_bound']:
                raise SafetyStop('tariff_bounds')
            if model.get('cache_partition') not in {'separate', 'included'}:
                raise SafetyStop('cache_contract')
            if model.get('reasoning_in_output_total') is False:
                integer(model.get('reasoning_bound'), 'reasoning_contract')
                integer(model.get('reasoning_micro_per_million'), 'reasoning_contract')
            elif model.get('reasoning_in_output_total') is not True:
                raise SafetyStop('reasoning_contract')
        for key in ('tavily_micro_per_credit', 'basic_credit_bound', 'extra_fee_bound_micro'):
            integer(t.get(key), 'tariff_bounds')
        if t['basic_credit_bound'] != 1:
            raise SafetyStop('tavily_contract')

    def _unchanged(self) -> None:
        if digest(self.tariffs) != self.hash:
            raise SafetyStop('tariff_drift')

    def bound(self, service: str, model: str = '', *, input_bound: int | None = None) -> RequestBound:
        self._unchanged()
        if input_bound is not None:
            raise SafetyStop('input_bound_authority')
        t = self.tariffs
        if service == 'tavily':
            return RequestBound(service, '', 0, 0, 0, 1, t['tavily_micro_per_credit'] + t['extra_fee_bound_micro'], self.hash)
        if service != 'nebius' or model not in t['models']:
            raise SafetyStop('unpriced_service_or_model')
        m = t['models'][model]
        maximum_input = m.get('input_bound', m['context_tokens']) if self.test_only else m['context_tokens']
        maximum_input = integer(maximum_input, 'tariff_bounds')
        maximum_output = m['billable_output_bound']
        charge = token_charge(maximum_input, m['input_micro_per_million'])
        if m['cache_partition'] == 'separate':
            charge += token_charge(maximum_input, m['cache_micro_per_million'])
        charge += token_charge(maximum_output, m['output_micro_per_million'])
        if not m['reasoning_in_output_total']:
            charge += token_charge(m['reasoning_bound'], m['reasoning_micro_per_million'])
        charge += t['extra_fee_bound_micro']
        return RequestBound(service, model, maximum_input, maximum_output, maximum_input, 0, charge, self.hash)

    def settle(self, bound: RequestBound, usage: Record, served_model: str) -> int:
        self._unchanged()
        if bound.tariff_hash != self.hash:
            raise SafetyStop('tariff_drift')
        if not isinstance(usage, dict): raise SafetyStop('usage_unknown')
        if bound.service == 'tavily':
            credits = integer(usage.get('credits'))
            if credits > bound.max_credits: raise SafetyStop('usage_exceeds_bound')
            return credits * self.tariffs['tavily_micro_per_credit']
        if served_model != bound.model and served_model not in self.tariffs['models'][bound.model].get('served_aliases', []):
            raise SafetyStop('model_drift')
        m = self.tariffs['models'][bound.model]
        prompt = integer(usage.get('prompt_tokens')); completion = integer(usage.get('completion_tokens'))
        cached = integer((usage.get('prompt_tokens_details') or {}).get('cached_tokens', 0))
        reasoning = integer((usage.get('completion_tokens_details') or {}).get('reasoning_tokens', 0))
        if prompt > bound.max_input or completion > bound.max_output or cached > prompt:
            raise SafetyStop('usage_exceeds_bound')
        if m['reasoning_in_output_total'] and reasoning > completion:
            raise SafetyStop('usage_exceeds_bound')
        if any(usage.get(key) for key in ('tool_cost', 'extra_fees', 'unpriced_tokens')):
            raise SafetyStop('usage_unknown')
        cost = token_charge(prompt - cached if m['cache_partition'] == 'separate' else prompt,
                            m['input_micro_per_million'])
        if m['cache_partition'] == 'separate': cost += token_charge(cached, m['cache_micro_per_million'])
        cost += token_charge(completion, m['output_micro_per_million'])
        if not m['reasoning_in_output_total']:
            if reasoning > m['reasoning_bound']: raise SafetyStop('usage_exceeds_bound')
            cost += token_charge(reasoning, m['reasoning_micro_per_million'])
        cost += self.tariffs['extra_fee_bound_micro']
        if cost > bound.microdollars: raise SafetyStop('usage_exceeds_bound')
        return cost
