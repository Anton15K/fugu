"""Thin CLI profile/report adapter over canonical jobs, intake and policy.

No persistent history, target imports, alternate verdict rules or provider
selection. Offline constructs only production local scanners.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from fugu.cli_output import CliError, error_report, exit_for_report, sanitize_public
from fugu.credentials import CredentialSet


def _build_stages(mode: str, keys: CredentialSet, detonate: bool) -> list[Any]:
    from fugu.pipeline.stages.concealment import ConcealmentStage
    from fugu.pipeline.stages.static_scan import StaticScanStage

    static = StaticScanStage(surface_scanner=False) if mode == 'offline' else StaticScanStage()
    stages: list[Any] = [ConcealmentStage(), static]
    if mode == 'full':
        from fugu.pipeline.stages.semantic import SemanticStage
        from fugu.pipeline.stages.harness import HarnessStage
        stages.extend([SemanticStage(), HarnessStage()])
        if keys.tavily:
            from fugu.pipeline.stages.reputation import ReputationStage
            stages.append(ReputationStage())
        if detonate:
            from fugu.detonation.docker_driver import DockerDriver
            from fugu.pipeline.stages.detonation_stage import DetonationStage
            stages.append(DetonationStage(DockerDriver()))
    return stages


def _coverage(snap: Any, required: list[str], excluded: list[str]) -> dict[str, Any]:
    by_name = {result.stage: result for result in snap.stages}
    records = []
    for name in required:
        result = by_name.get(name)
        metrics = result.metrics if result is not None else {}
        if result is None:
            state = 'missing'
        elif not result.ok:
            state = 'failed'
        elif 'skipped' in metrics:
            state = 'skipped'
        elif (metrics.get('coverage_incomplete') or metrics.get('call_errors')
              or metrics.get('rule_errors') or metrics.get('omitted_units')
              or any(metrics.get(key, 0) for key in ('skipped_large', 'skipped_unreadable', 'skipped_undecodable', 'skipped_max_files', 'skipped_binary'))):
            state = 'partial'
        elif name == 'detonation' and not metrics.get('executed'):
            state = 'not_executed'
        else:
            state = 'completed'
        records.append({'stage': name, 'state': state})
    return {'required_stages': list(required), 'excluded_stages': list(excluded),
        'records': records,
        'incomplete': snap.job.status.value != 'done' or any(r['state'] != 'completed' for r in records)}


def _snapshot_public(snap: Any, required: list[str], excluded: list[str]) -> dict[str, Any]:
    from fugu.server.jobs import finding_public, stage_public
    # The terminal canonical verdict is authoritative; do not synthesize one
    # for extraction failures or cancellation.
    verdict = next((event.data['verdict'] for event in reversed(snap.events)
                    if event.type == 'verdict'), None)
    return {'job_id': snap.job.id, 'audit_status': snap.job.status.value,
        'verdict': verdict, 'stages': [stage_public(r) for r in snap.stages],
        'findings': [finding_public(f) for f in snap.findings],
        'coverage': _coverage(snap, required, excluded)}


async def _run(source: str, mode: str, keys: CredentialSet, detonate: bool) -> dict[str, Any]:
    from fugu.server import composition_jobs
    from fugu.server.jobs import JobStore, new_job_id
    from fugu.types import AuditJob

    required = ['concealment', 'static']
    excluded = []
    if mode == 'full':
        required.extend(['semantic', 'harness'])
        (required if keys.tavily else excluded).append('reputation')
        (required if detonate else excluded).append('detonation')
    else:
        excluded = ['semantic', 'harness', 'reputation', 'detonation', 'tool_surface']
    store = JobStore()  # process-local, no operator database/SQLite persistence
    # Trailing slash prevents canonical .git URL heuristics from cloning an
    # existing local directory whose name happens to end in .git.
    local = Path(source).expanduser()
    intake_source = str(local.resolve()) + '/' if local.is_dir() else source
    job = AuditJob(id=new_job_id(), source=intake_source, depth='full')
    snap = store.create(job)
    error = None
    try:
        stages = _build_stages(mode, keys, detonate)
        if mode == 'full' and any(getattr(stage, 'name', '') == 'static' and
                                  getattr(stage, 'surface_scanner', None) is None for stage in stages):
            excluded.append('tool_surface')
        await composition_jobs.run_auto_job(job, intake_source, stages, store)
    except (asyncio.CancelledError, KeyboardInterrupt):
        error = CliError('cancelled', 'Audit cancelled; owned cleanup attempted.')
    except Exception:
        error = CliError('audit', 'Audit did not complete; private error detail withheld.')
    children = [store.get(jid) for jid in store.all_ids() if jid != job.id]
    own_required = ['composition'] if children else required
    report = _snapshot_public(snap, own_required, excluded)
    report.update(schema_version=1, mode=mode, source=source, children=[])
    for child in children:
        if child is None:
            continue
        member = _snapshot_public(child, required, excluded)
        member.update(label=Path(child.job.source).name, status=child.job.status.value,
                      findings_count=len(child.findings))
        report['children'].append(member)
        report['coverage']['records'].extend(
            {**record, 'member': member.get('label', child.job.id), 'job_id': child.job.id}
            for record in member['coverage']['records'])
        report['coverage']['incomplete'] |= member['coverage']['incomplete'] or member['verdict'] is None
    if children:
        report['coverage']['required_stages'] = [*required, 'composition']
    report['coverage']['omitted_units'] = sum(r.metrics.get('omitted_units', 0) for r in snap.stages)
    report['coverage']['omitted_unit_labels'] = [label for r in snap.stages
        for label in r.metrics.get('omitted_unit_labels', [])]
    report['coverage']['incomplete'] |= report['verdict'] is None or bool(report['coverage']['omitted_units'])
    if error is None and job.status.value == 'failed':
        # Only intake failures before fan-out/execution are exit 2. A failed
        # requested member/workflow remains exit 3 even with an extraction label.
        intake = not children and any(r.stage == 'extraction' for r in snap.stages)
        error = CliError('intake' if intake else 'audit',
            'Source intake failed; check the directory or public HTTPS Git selection.' if intake else 'Requested audit failed; inspect coverage.')
    report['error'] = {'category': error.category, 'message': str(error)} if error else None
    if error and error.category == 'audit':
        report['audit_status'] = 'failed'
    if error and error.category == 'cancelled':
        report['audit_status'] = 'cancelled'
        report['coverage']['incomplete'] = True
    report['exit_code'] = exit_for_report(report)
    return sanitize_public(report, (keys.nebius, keys.tavily))


def run_cli_audit(source: str, mode: str, keys: CredentialSet, *, detonate: bool = False) -> dict[str, Any]:
    """Synchronous CLI contract; asyncio.run cancels/drains owned async work."""
    os.environ["FUGU_NO_DOTENV"] = "1"
    from fugu.config import credential_scope
    # Direct adapter callers also retain CLI endpoint/dotenv/input boundaries.
    from fugu.cli import _validate_audit_source
    _validate_audit_source(source, mode)
    if mode == 'offline' and detonate:
        raise CliError('usage', 'Offline mode excludes detonation.')
    if mode == 'full':
        from fugu.credentials import validated_base_url
        validated_base_url({'NEBIUS_BASE_URL': keys.base_url})
        if not keys.nebius:
            raise CliError('credential', 'Set NEBIUS_API_KEY or run fugu configure before a full audit.')
    with credential_scope(keys if mode == 'full' else CredentialSet()):
        try:
            return asyncio.run(_run(source, mode, keys, detonate))
        except KeyboardInterrupt:
            return error_report(source, mode, CliError('cancelled', 'Audit cancelled; owned cleanup attempted.'))
