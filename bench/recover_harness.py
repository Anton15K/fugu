"""Replay frozen harness calls; retry only empty A/B responses once at 4096 tokens.

Run only after the initial full-capability evaluation finishes. Original evidence
is immutable. --check validates the replay locally without inference or results.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import defaultdict
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path

from bench.full_capabilities import (
    ROOT, OUT, MEDPLUS, InferenceBudget, cohort_score, composition_score,
    digest, engine_hashes, input_hashes, recover_json, stage_state, write_json,
)
from fugu.pipeline.stages.harness import HarnessStage
from fugu.pipeline.stages.semantic import JudgeCall
from fugu.types import AuditJob, EvidenceSnippet, Finding, StageResult


def collapse_records(records: list[dict]) -> list[dict]:
    """Collapse the original structured RED retries into one logical call."""
    groups: list[list[dict]] = []
    for record in sorted(records, key=lambda r: r['number']):
        if record.get('structured_retry_index', 0) > 0:
            if not groups or any(record[k] != groups[-1][0][k]
                                 for k in ('requested_model', 'prompt_sha256')):
                raise ValueError('structured retry does not match preceding prompt')
            groups[-1].append(record)
        else:
            groups.append([record])
    slots = []
    for group in groups:
        selected = group[-1]
        structured = any('structured_retry_index' in r for r in group)
        if structured:
            for record in group:
                normalized, _ = recover_json(record.get('raw_response', ''))
                doc = json.loads(normalized) if normalized else None
                if record.get('parse_valid') and isinstance(doc, dict) and isinstance(doc.get('probes'), list):
                    selected = dict(record, raw_response=normalized)
                    break
        slot = deepcopy(selected)
        slot['structured'] = structured
        slot['original_numbers'] = [r['number'] for r in group]
        slot['usage'] = {k: sum(r.get('usage', {}).get(k) or 0 for r in group)
                         for k in ('prompt_tokens', 'completion_tokens')}
        slot['duration_s'] = sum(r.get('duration_s', 0) for r in group)
        slots.append(slot)
    return slots


class Replay:
    """One shared ordered queue across Ultra and Super, guarded before any API."""
    def __init__(self, slots: list[dict], budget):
        self.slots, self.budget = slots, budget
        self.index = 0
        self.evidence: list[dict] = []
        self.guard_errors: list[str] = []

    def caller(self, model: str):
        def call(system: str, user: str):
            if self.index >= len(self.slots):
                self.guard_errors.append('replay exhausted')
                raise ValueError('replay exhausted')
            slot = self.slots[self.index]
            if model != slot['requested_model'] or digest((system + '\n' + user).encode()) != slot['prompt_sha256']:
                self.guard_errors.append(f'replay mismatch at slot {self.index}')
                raise ValueError(self.guard_errors[-1])
            self.index += 1
            if slot.get('error'):
                raise RuntimeError(slot['error'])
            raw = slot.get('raw_response', '')
            usage = dict(slot.get('usage') or {})
            latency = slot.get('duration_s', 0)
            # Structured RED is replayed only; its existing probes must not change.
            if not raw.strip() and not slot.get('structured', 'structured_retry_index' in slot):
                evidence = {'original_numbers': slot.get('original_numbers', [slot['number']]),
                            'requested_model': model, 'prompt_sha256': slot['prompt_sha256'],
                            'max_tokens': 4096}
                self.evidence.append(evidence)
                try:
                    if self.budget.stop_reason:
                        raise RuntimeError(self.budget.stop_reason)
                    raw, retry = self.budget.request(model, system, user, 4096)
                    evidence.update(recovery_number=retry['number'], nonempty=bool(raw.strip()))
                    latency += retry.get('duration_s', 0)
                    usage = {k: (usage.get(k) or 0) + (retry.get('usage', {}).get(k) or 0)
                             for k in ('prompt_tokens', 'completion_tokens')}
                except Exception:
                    evidence['error'] = self.budget.stop_reason or 'recovery_request_failed'
                    # A failure ends affected paid work; later valid slots still replay.
                    self.budget.stop_reason = evidence['error']
                    raise RuntimeError(evidence['error']) from None
            return raw, JudgeCall(model=model, latency_s=latency,
                                  prompt_chars=len(system)+len(user), completion_chars=len(raw), usage=usage)
        return call

    def assert_consumed(self):
        if self.guard_errors or self.index != len(self.slots):
            raise ValueError(f'unsafe replay: {self.guard_errors}; consumed {self.index}/{len(self.slots)}')


class ReplayHarness(HarnessStage):
    def __init__(self, replay: Replay, ultra: str, super_model: str):
        super().__init__(make_call=replay.caller(ultra))
        self.everyday = replay.caller(super_model)

    def _everyday_call(self, call, *, injected):
        return self.everyday


def deserialize_stage(value: dict) -> StageResult:
    findings = [Finding(**{**f, 'evidence': [EvidenceSnippet(**e) for e in f.get('evidence', [])]})
                for f in value['findings']]
    return StageResult(stage=value['stage'], ok=value['ok'], findings=findings,
                       metrics=deepcopy(value['metrics']), error=value.get('error'))


def serialize_stages(results: list[StageResult]) -> list[dict]:
    values = [asdict(result) for result in results]
    for value in values:
        value['state'] = stage_state(value)
    return values


class CheckBudget:
    stop_reason = None
    def __init__(self):
        self.attempts = 0
        self.calls = []
    def request(self, model, system, user, maximum):
        # Preflight never executes paid requests; retain original empty response.
        return '', {'number': 0, 'duration_s': 0, 'usage': {}}


async def run(out: Path, *, check: bool = False) -> None:
    from fugu.config import ULTRA_MODEL, SUPER_MODEL
    from fugu.dedupe import dedupe_findings
    from fugu.pipeline.stages.composition import CompositionStage, MemberResult
    from fugu.server.composition_jobs import harvest_tool_names
    from fugu.verdict import aggregate_verdict

    original = json.loads((out/'fugu.json').read_text())
    if not original.get('finished_utc'):
        raise RuntimeError('initial benchmark has not finished')
    manifest = json.loads((out/'cases.json').read_text())
    before = engine_hashes()
    assert before == manifest['engine_hashes'], 'engine differs from frozen benchmark'
    immutable = [out/'fugu.json', out/'cases.json', *sorted((out/'audits').glob('*.json')),
                 *sorted((out/'calls').glob('*.json'))]
    original_hashes = {str(p.relative_to(out)): digest(p.read_bytes()) for p in immutable}
    calls = [json.loads(p.read_text()) for p in sorted((out/'calls').glob('*.json'))]
    initial_attempts = max(original['attempts'], max((r['number'] for r in calls), default=0))
    blocked = original.get('inference_stop_reason') or original.get('stop_reason')
    recovery = out/'recovery'
    if not check and ((out/'fugu-recovered.json').exists() or list((recovery/'calls').glob('*.json'))):
        raise RuntimeError('recovery evidence already exists; refusing repeated paid retries')
    budget = CheckBudget() if check or blocked else InferenceBudget(recovery, limit=max(0, 1800-initial_attempts))
    if blocked:
        budget.stop_reason = blocked
    targets = {}
    for case in manifest['cases']:
        target = ROOT/case['target']
        assert input_hashes(target) == case['input_sha256'], 'frozen target changed'
        if case['cohort'] == 'composition':
            targets.update({case['id']+'/'+m['dir']: target/m['dir'] for m in case['members']})
        else:
            targets[case['id']] = target
    audits, attempts = {}, []
    for path in sorted((out/'audits').glob('*.json')):
        audit = json.loads(path.read_text())
        results = [deserialize_stage(s) for s in audit['stages']]
        harness = next(s for s in results if s.stage == 'harness')
        records = [c for c in calls if c['context'] == audit['context'] and c['stage'] == 'harness']
        slots = collapse_records(records)
        eligible = [s for s in slots if not s.get('structured') and not s.get('error') and not s.get('raw_response', '').strip()]
        if eligible and stage_state(asdict(harness)) in ('partial', 'failed') and not blocked:
            target = targets[audit['context']]
            assert input_hashes(target) == audit['input_sha256']
            print('REPLAY', audit['context'], 'empty arms', len(eligible), flush=True)
            budget.context, budget.stage = audit['context'], 'harness'
            replay = Replay(slots, budget)
            replacement = await ReplayHarness(replay, ULTRA_MODEL, SUPER_MODEL).run(
                AuditJob(id='full-benchmark', source=str(target), depth='full'), target)
            replay.assert_consumed()
            evidence = {'fingerprint': path.stem, 'context': audit['context'],
                        'initial_state': stage_state(asdict(harness)),
                        'replacement_state': stage_state(asdict(replacement)),
                        'retry_evidence': replay.evidence}
            attempts.append(evidence)
            if not check:
                results = [replacement if s.stage == 'harness' else s for s in results]
                write_json(recovery/'audits'/path.name, {**audit, 'stages': [asdict(s) for s in results],
                           'recovery': evidence})
                write_json(recovery/'progress.json', {'audits': attempts, 'attempts': budget.attempts,
                           'stop_reason': budget.stop_reason})
        audits[path.stem] = results
    assert engine_hashes() == before
    assert all(digest((out/p).read_bytes()) == h for p,h in original_hashes.items()), 'original evidence changed'
    if check:
        write_json(recovery/'preflight.json', {'checked_audits': len(audits), 'eligible_audits': attempts,
                   'engine_unchanged': True, 'originals_unchanged': True, 'api_attempts': 0,
                   'original_stop_reason': blocked})
        print('Offline replay verified',len(attempts),'eligible audits',flush=True)
        return

    def lookup(target: Path):
        fingerprint = digest(json.dumps(input_hashes(target), sort_keys=True).encode())
        return audits[fingerprint]
    rows = []
    for initial in original['rows']:
        row = deepcopy(initial)
        row['initial_exclusions'] = deepcopy(initial['exclusions'])
        target = ROOT/row['target']
        if row['cohort'] == 'composition':
            results, findings, children, members = [], [], [], []
            for member in row['members']:
                directory = target/member['dir']
                child = lookup(directory)
                child_findings = dedupe_findings([f for s in child for f in s.findings])
                old = next(c for c in initial['members_results'] if c['member'] == member['dir'])
                children.append({**old,'stages':serialize_stages(child)})
                results.extend(child); findings.extend(child_findings)
                members.append(MemberResult(label=member.get('label') or member['dir'], slug=member['dir'],
                               findings=child_findings, tool_names=harvest_tool_names(directory), target_dir=directory))
            composition = CompositionStage(); composition._member_results = members
            comp = await composition.run(AuditJob(id='full-composition', source=str(target), depth='full'), target)
            results.append(comp); findings.extend(comp.findings)
            findings = dedupe_findings(findings)
            row['members_results'] = children
            row['composition_score'] = composition_score([asdict(f) for f in findings], row['expected'])
            row['detected'] = row['composition_score']['detected']
        else:
            results = lookup(target)
            findings = dedupe_findings([f for s in results for f in s.findings])
            row['detected'] = any(f.severity in MEDPLUS for f in findings)
        row['stages'], row['findings'] = serialize_stages(results), [asdict(f) for f in findings]
        row['verdict'] = aggregate_verdict(findings, results)
        row['exclusions'] = [{'stage':s['stage'],'state':s['state'],'error':s.get('error'),
                             'reason':s.get('metrics',{}).get('coverage_incomplete')}
                            for s in row['stages'] if s['state'] not in ('completed','not_applicable')]
        row['complete'] = not row['exclusions']
        row['recovery'] = {'initial_complete':initial['complete'], 'initial_detected':initial['detected'],
                           'initial_verdict':initial['verdict'], 'initial_elapsed_s':initial['elapsed_s']}
        rows.append(row)
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row['cohort'], row['kind'])].append(row)
    combined_usage = {k:(original.get('usage',{}).get(k) or 0)+sum(c.get('usage',{}).get(k) or 0 for c in budget.calls)
                      for k in ('prompt_tokens','completion_tokens')}
    after = engine_hashes(); assert before == after
    assert all(digest((out/p).read_bytes()) == h for p,h in original_hashes.items())
    result = {**original, 'finished_utc':datetime.now(timezone.utc).isoformat(), 'rows':rows,
              'summary':[{'cohort':c,'kind':k,**cohort_score(v)} for (c,k),v in sorted(grouped.items())],
              'attempts':initial_attempts+budget.attempts, 'total_attempts':initial_attempts+budget.attempts,
              'usage':combined_usage, 'engine_hashes_after':after, 'engine_unchanged':before==after,
              'recovery':{'initial_incomplete':sum(not r['complete'] for r in original['rows']),
                  'recovered_audits':len(attempts), 'retried_empty_responses':budget.attempts,
                  'unresolved':sum(not r['complete'] for r in rows), 'initial_attempts':initial_attempts,
                  'initial_finished_utc':original['finished_utc'], 'stop_reason':budget.stop_reason,
                  'initial_stop_reason':blocked,'audits':attempts,
                  'original_artifact_sha256':original_hashes, 'engine_hashes_before':before,
                  'policy':'exact original model/prompts; one 4096-token retry only for empty A/B arms; valid responses replay unchanged; no new probes'}}
    write_json(out/'fugu-recovered.json', result)
    print(json.dumps(result['recovery'],indent=2),flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=OUT)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    asyncio.run(run(args.out,check=args.check))


if __name__ == '__main__':
    main()
