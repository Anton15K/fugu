"""Frozen source-only S0/S1/S2 showcase; no auditee imports or target execution."""
from __future__ import annotations
import argparse
import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time

HERE = Path(__file__).resolve().parent


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_engine() -> dict:
    import fugu
    base = Path(fugu.__file__).parent
    actual = {'src/fugu/' + str(p.relative_to(base)): digest(p.read_bytes()) for p in base.rglob('*.py')}
    expected = json.loads((HERE / 'engine-manifest.json').read_text())['engine_source_hashes']
    if actual != expected:
        raise ValueError('Frozen engine hash mismatch')
    return actual


class BudgetedCaller:
    def __init__(self, private_calls: Path):
        from dotenv import load_dotenv
        # A /tmp engine changes dotenv's automatic upward search. Load the
        # authorized project configuration without printing its contents.
        load_dotenv(HERE.parents[2] / '.env', override=False)
        from fugu.config import get_settings
        from fugu.client import make_client
        from fugu.model_router import pick_model
        settings = get_settings()
        if not settings.has_api_key:
            raise RuntimeError('No inference credential configured; no paid requests made')
        self.client = make_client(settings)
        self.model = pick_model('audit semantic security analysis')
        self.attempts = 0
        self.limit = 24
        self.stop_reason = None
        self.calls = []
        self.private_calls = private_calls
        self.artifact = None
        self.budget_path = HERE / 'budget-state.json'
        if self.budget_path.exists() and json.loads(self.budget_path.read_text()).get('attempts', 0):
            raise RuntimeError('This assignment already consumed paid requests; no automatic rerun')

    def __call__(self, system: str, user: str):
        from fugu.pipeline.stages.semantic import JudgeCall
        if self.stop_reason or self.attempts >= self.limit:
            self.stop_reason = self.stop_reason or 'hard24_request_limit'
            raise RuntimeError('Paid requests stopped: ' + self.stop_reason)
        self.attempts += 1
        self.budget_path.write_text(json.dumps({'attempts': self.attempts, 'limit': self.limit,
            'scope': 'Cumulative showcase assignment requests; includes repairs/retries'}, indent=2) + '\n')
        start = time.perf_counter()
        row = {'attempt': self.attempts, 'artifact': self.artifact, 'model': self.model,
               'system_chars': len(system), 'user_chars': len(user),
               'system_sha256': digest(system.encode()), 'user_sha256': digest(user.encode()),
               'unit_label': user.split('\n')[0], 'max_completion_tokens': 4096,
               'timeout_s': 90, 'sdk_retries': 0}
        try:
            response = self.client.chat.completions.create(model=self.model,
                messages=[{'role': 'system', 'content': system}, {'role': 'user', 'content': user}],
                temperature=0.1, max_tokens=4096)
            text = (response.choices[0].message.content or '').strip()
            usage = {}
            if response.usage is not None:
                usage = {'prompt_tokens': response.usage.prompt_tokens,
                         'completion_tokens': response.usage.completion_tokens}
            row.update(finish_reason=response.choices[0].finish_reason,
                       response_chars=len(text), response_sha256=digest(text.encode()),
                       raw_response=text, usage=usage, state='response_received')
            latency = round(time.perf_counter() - start, 3)
            return text, JudgeCall(self.model, latency, len(system) + len(user), len(text), usage)
        except Exception as exc:
            status = getattr(exc, 'status_code', None)
            message = str(exc).lower()  # inspect locally; never retain provider message/headers
            exhausted = any(term in message for term in ('insufficient_quota','quota exhausted','exceeded your current quota','insufficient balance','not enough credits'))
            self.stop_reason = ('provider_quota_exhausted' if exhausted else
                                'provider_auth_error' if status in (401, 403) else
                                'provider_error_stop')
            row.update(state='request_failed', error_type=type(exc).__name__, http_status=status,
                       stop_reason=self.stop_reason, usage={})
            raise RuntimeError(self.stop_reason) from None
        finally:
            row['latency_s'] = round(time.perf_counter() - start, 3)
            self.calls.append(row)
            self.private_calls.write_text(json.dumps(self.calls, indent=2) + '\n')
            print('call', self.attempts, self.artifact, row['state'], row['latency_s'], flush=True)


async def run(args):
    from fugu.pipeline import build_stages, run_stages
    from fugu.pipeline.stages.semantic import SemanticStage
    from fugu.types import AuditJob, JobStatus
    before = check_engine()
    plan = json.loads((HERE / 'measurement-plan.json').read_text())
    assert len(plan['artifacts']) <= 5 and plan['calls_limit_total'] == 24
    result = {'started_utc': datetime.now(timezone.utc).isoformat(), 'engine_hashes_before': before,
              'plan_sha256': digest((HERE / 'measurement-plan.json').read_bytes()),
              'mode': 'S0/S1 plus optional S2; source text only', 'target_executions': 0,
              'rows': [], 'unmeasured_semantic_artifacts': []}
    caller = None
    if args.semantic:
        try:
            caller = BudgetedCaller(args.private_calls)
        except RuntimeError as exc:
            result['inference_unavailable'] = str(exc)
    for artifact in plan['artifacts']:
        with tempfile.TemporaryDirectory(prefix='fugu-showcase-input-') as tmp:
            target = Path(tmp)
            for rel, expected in artifact['input_sha256'].items():
                source = args.cache / artifact['repository'].replace('/', '--') / rel
                if source.is_symlink() or digest(source.read_bytes()) != expected:
                    raise ValueError('Pinned regular source mismatch')
                dest = target / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, dest)
            job = AuditJob(id='source-showcase', source=str(target), status=JobStatus.running)
            stages = build_stages(include_semantic=False, include_harness=False,
                                  include_detonation=False, include_reputation=False)
            if caller and not caller.stop_reason and caller.attempts < caller.limit:
                caller.artifact = artifact['id']
                stages.append(SemanticStage(make_call=caller))
            elif args.semantic:
                result['unmeasured_semantic_artifacts'].append(artifact['id'])
            results = await run_stages(job, target, stages)
            result['rows'].append({'id': artifact['id'], 'repository': artifact['repository'],
                'commit': artifact['commit'], 'input_sha256': artifact['input_sha256'],
                'stages': [asdict(r) for r in results]})
        result['engine_hashes_after'] = check_engine()
        result['engine_changed'] = before != result['engine_hashes_after']
        if caller:
            result['live'] = {'attempts': caller.attempts, 'limit': caller.limit,
                'model': caller.model, 'stop_reason': caller.stop_reason,
                'calls': [{k:v for k,v in c.items() if k != 'raw_response'} for c in caller.calls]}
        args.out.write_text(json.dumps(result, indent=2) + '\n')
        print('artifact', artifact['id'], 'stages', len(results), 'findings', sum(len(r.findings) for r in results), flush=True)
    result['finished_utc'] = datetime.now(timezone.utc).isoformat()
    args.out.write_text(json.dumps(result, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--semantic', action='store_true')
    parser.add_argument('--private-calls', type=Path, default=Path('/tmp/fugu-showcase-private-calls.json'))
    args = parser.parse_args()
    if args.out.exists() or (args.semantic and args.private_calls.exists()):
        parser.error('Choose fresh result/call paths; refusing overwrite')
    asyncio.run(run(args))


if __name__ == '__main__':
    main()
