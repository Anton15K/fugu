"""Secret-safe CLI messages, independent of the audit engine."""
from __future__ import annotations

import json
from typing import Any, Mapping, Sequence


class CliError(Exception):
    """A categorized, authored message safe to show instead of raw exceptions."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


def redact(text: str, secrets: Sequence[str] = ()) -> str:
    """Remove known runtime credentials while retaining synthetic canary evidence."""
    for secret in sorted({value for value in secrets if value}, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


def exit_for_report(report: Mapping[str, Any]) -> int:
    """CI severity is subordinate to requested execution coverage."""
    error = report.get('error') or {}
    category = error.get('category')
    if category == 'cancelled':
        return 130
    if category in {'usage', 'configuration', 'credential', 'intake', 'consent'}:
        return 2
    verdict = report.get('verdict')
    if (error or report.get('audit_status') != 'done' or not verdict
            or report.get('coverage', {}).get('incomplete')):
        return 3
    status = verdict.get('status')
    return 0 if status == 'pass' else 1 if status in {'warn', 'fail'} else 3


def public_source(source: str) -> str:
    """Rejected URL credentials must never be repeated in an error report."""
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(source)
        # Queries/fragments may carry credentials unrelated to provider keys.
        # Local paths can contain literal ?/#, so apply this only to URLs.
        if (parts.username is not None or parts.password is not None
                or ((parts.scheme or parts.netloc) and (parts.query or parts.fragment))):
            return '<rejected source URL>'
    except ValueError:
        return '<invalid source URL>'
    return source


def error_report(source: str, mode: str, error: CliError | None, *,
                 verdict: dict[str, Any] | None = None,
                 audit_status: str = 'failed') -> dict[str, Any]:
    report = {'schema_version': 1, 'mode': mode, 'audit_status': audit_status,
        'source': public_source(source), 'verdict': verdict, 'stages': [], 'findings': [],
        'children': [], 'coverage': {'required_stages': [], 'excluded_stages': [],
        'incomplete': error is not None},
        'error': {'category': error.category, 'message': str(error)} if error else None}
    report['exit_code'] = exit_for_report(report)
    return report


def sanitize_public(value: Any, secrets: Sequence[str] = ()) -> Any:
    """Redact before JSON escaping and replace untrusted stage error bodies."""
    if isinstance(value, str):
        return redact(value, secrets)
    if isinstance(value, (list, tuple)):
        return [sanitize_public(item, secrets) for item in value]
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            safe_key = redact(str(key), secrets)
            if key == 'error' and isinstance(item, str) and item:
                result[safe_key] = 'Check failed; private error detail withheld.'
            elif key == 'reason' and value.get('state') == 'failed':
                result[safe_key] = 'Check failed; private error detail withheld.'
            elif key == 'call_errors' and item:
                result[safe_key] = ['Provider request failed; private error detail withheld.' for _ in item]
            else:
                result[safe_key] = sanitize_public(item, secrets)
        return result
    return value


def render_report(report: Mapping[str, Any], format: str,
                  secrets: Sequence[str] = ()) -> str:
    safe = sanitize_public(report, secrets)
    if format == 'json':
        return json.dumps(safe, ensure_ascii=True, separators=(',', ':')) + '\n'
    if format != 'text':
        raise CliError('usage', 'Unsupported report format.')
    verdict = safe.get('verdict') or {}
    status = str(verdict.get('status', 'no verdict')).upper()
    coverage = safe.get('coverage', {})
    incomplete = coverage.get('incomplete', True)
    action = ('Correct the error and retry.' if safe.get('error') else
              'Complete missing checks before deciding.' if incomplete else
              'Investigate findings before installing.' if status != 'PASS' else
              'Review evidence and exclusions before deciding to install.')
    lines = [f"Verdict: {status} | Mode: {safe.get('mode')}",
             f"Coverage: {'incomplete' if incomplete else 'chosen profile complete'}",
             'Excluded: ' + (', '.join(coverage.get('excluded_stages', [])) or 'none'),
             'Next action: ' + action]
    if safe.get('mode') == 'offline':
        lines.append('Local checks only; hosted inference, reputation, execution and external scanner excluded. PASS does not certify safety.')
    if safe.get('error'):
        lines.append(f"{safe['error']['category']}: {safe['error']['message']}")
    lines.extend('Reason: ' + reason for reason in verdict.get('reasons', []))
    for record in coverage.get('records', []):
        lines.append(f"Check {record.get('member', 'source')} / {record['stage']}: {record['state']}")
    for finding in safe.get('findings', []):
        lines.append(f"[{finding['severity']}/{finding['confidence']}] {finding['title']}")
        lines.append(finding['detail'])
        lines.extend(f"  {e['source']}: {e['excerpt']}" for e in finding.get('evidence', []))
    return '\n'.join(lines) + '\n'
