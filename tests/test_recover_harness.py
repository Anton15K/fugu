import asyncio
import hashlib
import importlib
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest


def module():
    return importlib.import_module('bench.recover_harness')


def record(raw='original valid answer', model='Ultra', system='system', user='user', number=1, **extra):
    return {'number':number,'requested_model':model,'prompt_sha256':hashlib.sha256((system+'\n'+user).encode()).hexdigest(),'raw_response':raw,'duration_s':1,'usage':{'prompt_tokens':4,'completion_tokens':5},**extra}


class Budget:
    stop_reason = None
    def __init__(self, answer='recovered answer'):
        self.requests=[]; self.answer=answer
    def request(self, model, system, user, maximum):
        self.requests.append((model,system,user,maximum))
        return self.answer, record(self.answer,model,system,user)


@pytest.mark.parametrize('model,system,user',[('Super','system','user'),('Ultra','changed','user'),('Ultra','system','changed')])
def test_exact_model_and_prompt_guard_precedes_api(model,system,user):
    budget=Budget(); replay=module().Replay([record(raw='')],budget)
    with pytest.raises(ValueError,match='replay mismatch'):
        replay.caller(model)(system,user)
    assert budget.requests==[]


def test_valid_original_response_is_unchanged_without_api():
    budget=Budget(); replay=module().Replay([record()],budget)
    text,call=replay.caller('Ultra')('system','user')
    assert text=='original valid answer'
    assert call.usage=={'prompt_tokens':4,'completion_tokens':5}
    assert budget.requests==[]
    replay.assert_consumed()


def test_empty_arm_gets_exactly_one_bounded_retry_even_if_still_empty():
    budget=Budget(''); replay=module().Replay([record(raw='')],budget)
    assert replay.caller('Ultra')('system','user')[0]==''
    assert budget.requests==[('Ultra','system','user',4096)]
    replay.assert_consumed()
    with pytest.raises(ValueError,match='replay exhausted'):
        replay.caller('Ultra')('system','user')
    assert len(budget.requests)==1


def test_structured_red_attempts_collapse_and_reparse_without_api():
    records=[record(raw='{"probes":[',structured_retry_index=0,parse_valid=False),record(raw='```json\n{"probes":["unchanged",],}\n```',number=2,structured_retry_index=1,parse_valid=True)]
    budget=Budget(); slots=module().collapse_records(records)
    assert len(slots)==1
    replay=module().Replay(slots,budget)
    text,call=replay.caller('Ultra')('system','user')
    assert json.loads(text)=={'probes':['unchanged']}
    assert call.usage=={'prompt_tokens':8,'completion_tokens':10}
    assert budget.requests==[]


def test_empty_red_or_provider_error_is_not_retried():
    for row in [record(raw='',structured_retry_index=0,parse_valid=False),record(raw='',error='provider_quota_exhausted')]:
        budget=Budget(); replay=module().Replay(module().collapse_records([row]),budget)
        try:
            replay.caller('Ultra')('system','user')
        except RuntimeError:
            pass
        assert budget.requests==[]


def test_actual_harness_reuses_probes_and_valid_arms(tmp_path):
    from fugu.pipeline.stages.harness import HarnessStage
    from fugu.pipeline.stages.semantic import JudgeCall
    from fugu.types import AuditJob
    (tmp_path/'SKILL.md').write_text('Translate user text.')
    captured=[]; everyday_count=0
    def capture(model):
        def call(system,user):
            nonlocal everyday_count
            raw='{"probes":[]}' if '"probes"' in system else 'Here is the direct answer.'
            if model=='Super':
                everyday_count+=1
                if everyday_count==2: raw=''
            extra={'structured_retry_index':0,'parse_valid':True} if '"probes"' in system else {}
            captured.append(record(raw,model,system,user,number=len(captured)+1,**extra))
            return raw,JudgeCall(model=model,latency_s=1,prompt_chars=len(system)+len(user),completion_chars=len(raw),usage={})
        return call
    class Original(HarnessStage):
        def _everyday_call(self,call,*,injected):return capture('Super')
    job=AuditJob(id='offline',source=str(tmp_path),depth='full')
    initial=asyncio.run(Original(make_call=capture('Ultra')).run(job,tmp_path))
    assert initial.metrics['comparisons_completed']==11
    budget=Budget(); replay=module().Replay(module().collapse_records(captured),budget)
    recovered=asyncio.run(module().ReplayHarness(replay,'Ultra','Super').run(job,tmp_path))
    replay.assert_consumed()
    assert recovered.metrics['comparisons_completed']==12
    assert not recovered.metrics.get('coverage_incomplete')
    assert len(budget.requests)==1
    assert budget.requests[0][0]=='Super' and budget.requests[0][3]==4096


def test_exhausted_provider_is_never_requested_and_valid_slots_still_replay():
    budget=Budget(); budget.stop_reason='provider_quota_exhausted'
    replay=module().Replay([record(raw=''),record(number=2)],budget)
    with pytest.raises(RuntimeError,match='provider_quota_exhausted'):
        replay.caller('Ultra')('system','user')
    assert replay.caller('Ultra')('system','user')[0]=='original valid answer'
    assert budget.requests==[]
    replay.assert_consumed()
