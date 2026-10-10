"""Bounded tool/instruction-surface analysis within S1.

Runs only an operator-installed, trusted static scanner. Auditee commands and
Python imports are never executed. User-facing findings use Fugu terminology;
engine provenance lives in evidence metadata and third-party notices.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import shutil
import tempfile
import time
import uuid

from fugu.pipeline.stages.concealment import collect_text_files
from fugu.source_safety import validate_source_tree
from fugu.types import EvidenceSnippet, Finding
from fugu.subprocess_env import credential_free_env

ENGINE_PIN = 'f739e120cd7dc253fead2a1f13668f9535e4d8a5'
MAX_TOOLS = 256
MAX_PACKET_BYTES = 4_000_000


def redact_evidence(text: str) -> str:
    """Apply Fugu's existing secret masking to upstream match excerpts."""
    from fugu.pipeline.stages.static_scan import (
        _AWS_KEY_RE, _GITHUB_TOKEN_RE, _SLACK_TOKEN_RE, _redact,
    )
    for pattern in (_AWS_KEY_RE, _GITHUB_TOKEN_RE, _SLACK_TOKEN_RE):
        text = pattern.sub(lambda match: _redact(match.group(0)), text)
    assignment = re.compile(
        r"(?i)((?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*[\"']?)([A-Za-z0-9_+./=-]{8,})"
    )
    return assignment.sub(lambda match: match.group(1) + _redact(match.group(2)), text)


@dataclass
class Surface:
    token: str
    source: str
    tool: dict


def collect_surfaces(target: Path, max_file_bytes: int, max_files: int):
    """Literal JSON/Python inventories and skill instructions, never imports."""
    target = validate_source_tree(target)
    files, collection = collect_text_files(target, max_file_bytes, max_files)
    surfaces = []
    errors = []
    omitted = 0

    def add(doc, source):
        nonlocal omitted
        if not (isinstance(doc, dict) and isinstance(doc.get('name'), str)
                and isinstance(doc.get('description'), str) and isinstance(doc.get('inputSchema'), dict)):
            return
        if len(surfaces) >= MAX_TOOLS:
            omitted += 1
            return
        packet = {k: doc[k] for k in ('name', 'description', 'inputSchema')}
        if isinstance(doc.get('annotations'), dict):
            packet['annotations'] = doc['annotations']
        surfaces.append(Surface(f't{len(surfaces)}', source, packet))

    def walk(doc, source):
        if isinstance(doc, dict):
            if all(k in doc for k in ('name', 'description', 'inputSchema')):
                add(doc, source)
            else:
                for value in doc.values():
                    walk(value, source)
        elif isinstance(doc, list):
            for value in doc:
                walk(value, source)

    for tf in files:
        path = Path(tf.rel)
        try:
            if path.name.lower() == 'skill.md':
                add({'name': tf.rel, 'description': tf.text, 'inputSchema': {}}, tf.rel)
            elif path.suffix.lower() == '.json':
                walk(json.loads(tf.text), tf.rel)
            elif path.suffix.lower() == '.py':
                tree = ast.parse(tf.text)
                # Only top-level assignments; literal_eval has no execution path.
                for node in tree.body:
                    if isinstance(node, (ast.Assign, ast.AnnAssign)):
                        try:
                            walk(ast.literal_eval(node.value), tf.rel)
                        except (ValueError, TypeError, SyntaxError, RecursionError):
                            pass
        except (ValueError, SyntaxError, RecursionError):
            if path.name.lower() in ('tools.json', 'skill.md'):
                errors.append(tf.rel)
    incomplete = omitted or errors or any(collection.get(k) for k in (
        'skipped_large', 'skipped_unreadable', 'skipped_max_files', 'skipped_undecodable'))
    return surfaces, {'tools': len(surfaces), 'omitted_tools': omitted,
                      'parse_errors': errors, 'coverage_incomplete': bool(incomplete)}


class ToolSurfaceScanner:
    def __init__(self, *, binary: Path, image: str | None = None,
                 expected_sha256: str | None = None, timeout_s: int = 30):
        self.binary = Path(binary).resolve()
        self.image = image
        self.expected_sha256 = expected_sha256
        self.timeout_s = timeout_s

    @classmethod
    def from_environment(cls):
        """Configuration belongs to the operator, never an audited repo."""
        installed = Path(__file__).resolve().parents[2] / '_bin' / 'static-rules'
        configured = os.environ.get('FUGU_STATIC_RULES_BINARY')
        if not configured and not installed.is_file():
            return None
        return cls(binary=Path(configured) if configured else installed,
                   image=os.environ.get('FUGU_STATIC_RULES_IMAGE') or None,
                   expected_sha256=os.environ.get('FUGU_STATIC_RULES_SHA256') or None)

    def scan(self, target: Path, max_file_bytes: int, max_files: int):
        start = time.perf_counter()
        surfaces, metrics = collect_surfaces(target, max_file_bytes, max_files)
        metrics.update(enabled=True, engine_pin=ENGINE_PIN, suppressed=0)
        if not surfaces:
            metrics['skipped'] = 'no supported tool or skill instruction surface'
            return [], metrics
        try:
            if not self.binary.is_file() or self.binary.is_relative_to(target.resolve()):
                raise RuntimeError('scanner_unavailable')
            binary_sha = hashlib.sha256(self.binary.read_bytes()).hexdigest()
            if self.expected_sha256 and binary_sha != self.expected_sha256:
                raise RuntimeError('scanner_integrity_mismatch')
            metrics['binary_sha256'] = binary_sha
            packet = {'tools': [{**s.tool, 'name': s.token} for s in surfaces]}
            encoded = json.dumps(packet, ensure_ascii=False).encode()
            if len(encoded) > MAX_PACKET_BYTES:
                raise RuntimeError('tool_surface_budget_exceeded')
            with tempfile.TemporaryDirectory(prefix='fugu-static-') as tmp:
                directory = Path(tmp)
                schema = directory / 'tools.json'
                schema.write_bytes(encoded)
                environment = {'PATH': os.defpath, 'HOME': tmp, 'TMPDIR': tmp}
                if self.image:
                    name = 'fugu-static-' + uuid.uuid4().hex
                    docker = shutil.which('docker') or 'docker'
                    command = [docker, 'run', '--rm', '--name', name, '--network', 'none',
                               '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                               '--pids-limit', '32', '--memory', '256m', '--cpus', '1',
                               '--user', '65534:65534', '-v', f'{self.binary}:/scanner:ro',
                               '-v', f'{schema}:/tools.json:ro', '--workdir', '/',
                               self.image, '/scanner', 'scan', '--schema', '/tools.json', '--output', 'json']
                    # Docker configuration is owner infrastructure, not target data.
                    environment['HOME'] = os.environ.get('HOME', tmp)
                    schema.chmod(0o644)
                else:
                    command = [str(self.binary), 'scan', '--schema', str(schema), '--output', 'json']
                try:
                    result = subprocess.run(command, cwd=tmp, env=credential_free_env(environment),
                                            capture_output=True, text=True, timeout=self.timeout_s)
                finally:
                    if self.image:
                        subprocess.run([docker, 'rm', '-f', name], capture_output=True,
                                       env=credential_free_env(environment), timeout=10, check=False)
            if result.returncode not in (0, 1) or len(result.stdout) > 16_000_000:
                raise RuntimeError('scanner_execution_failed')
            doc = json.loads(result.stdout)
            if (not isinstance(doc, dict) or type(doc.get('tools_scanned')) is not int
                    or doc['tools_scanned'] != len(surfaces) or not isinstance(doc.get('findings'), list)):
                raise RuntimeError('scanner_output_invalid')
            by_token = {s.token: s for s in surfaces}
            findings = []
            for row in doc['findings']:
                if (not isinstance(row, dict) or row.get('tool') not in by_token
                        or row.get('severity') not in ('critical', 'high', 'medium', 'low', 'info')
                        or not isinstance(row.get('signal'), str) or not isinstance(row.get('detail'), str)
                        or not isinstance(row.get('matched'), str) or type(row.get('suppressed')) is not bool):
                    raise RuntimeError('scanner_output_invalid')
                if row['suppressed']:
                    metrics['suppressed'] += 1
                    continue
                surface = by_token[row['tool']]
                findings.append(Finding(
                    stage='static', title='Tool surface: ' + row['signal'].replace('_', ' '),
                    detail=row['detail'] + ' Rule match requires contextual confirmation.',
                    severity='high' if row['severity'] == 'critical' else row['severity'],
                    confidence='advisory', owasp_ids=['LLM01', 'MCP03'], evidence=[EvidenceSnippet(
                        source=surface.source, excerpt=redact_evidence(row['matched'])[:500], meta={
                            'tool': redact_evidence(surface.tool['name'])[:256], 'signal': row['signal'],
                            'engine_pin': ENGINE_PIN, 'engine_sha256': binary_sha,
                            'upstream_severity': row['severity'], 'corpus_refs': row.get('corpus_refs', []),
                        })]))
            metrics.update(findings=len(findings), duration_s=round(time.perf_counter() - start, 4))
            return findings, metrics
        except Exception as exc:
            # No subprocess stderr, credentials or provider bodies in findings.
            error = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
            metrics.update(error=error, coverage_incomplete=True,
                           duration_s=round(time.perf_counter() - start, 4))
            return [], metrics
