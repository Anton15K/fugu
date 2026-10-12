from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import random
import stat
import subprocess
from typing import Any

from .contracts import FrozenRun, Record, SafetyStop


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def byte_hash(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise SafetyStop('reference_not_regular')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def immutable_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SafetyStop('artifact_exists') from None
    try:
        data = canonical(value) + b'\n'
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        # Partial bytes are evidence of failed persistence, never rewritten.
        raise


def tree_manifest(root: Path) -> Record:
    if root.is_symlink() or not root.is_dir():
        raise SafetyStop('source_not_directory')
    records = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs.sort(); files.sort()
        for name in list(dirs):
            path = Path(directory) / name
            if path.is_symlink():
                raise SafetyStop('source_symlink')
            if name == '.git':
                dirs.remove(name)
        for name in files:
            path = Path(directory) / name
            if path.is_symlink():
                raise SafetyStop('source_symlink')
            if not stat.S_ISREG(path.stat().st_mode):
                raise SafetyStop('source_not_regular')
            data = path.read_bytes()
            records.append({'path': path.relative_to(root).as_posix(), 'bytes': len(data),
                            'sha256': hashlib.sha256(data).hexdigest()})
    records.sort(key=lambda item: item['path'])
    return {'files': records, 'sha256': digest(records), 'omissions': []}


def engine_identity(engine_root: Path) -> Record:
    def git(*args: str) -> bytes:
        return subprocess.check_output(['git', '-C', str(engine_root), *args], stderr=subprocess.DEVNULL)
    if git('diff', '--name-only') or git('diff', '--cached', '--name-only'):
        raise SafetyStop('engine_dirty')
    files = git('ls-files', '-z').split(b'\0')
    records = []
    for name in files:
        if not name: continue
        relative = name.decode('utf-8', 'strict')
        path = engine_root / relative
        records.append({'path': relative, 'sha256': byte_hash(path)})
    return {'commit': git('rev-parse', 'HEAD').decode().strip(),
            'tree_hash': git('rev-parse', 'HEAD^{tree}').decode().strip(),
            'source_sha256': digest(records)}


def pair_order(cases: list[Record], seed: int) -> list[Record]:
    if type(seed) is not int or len({c['id'] for c in cases}) != len(cases):
        raise SafetyStop('order_invalid')
    for c in cases:
        if c['lane'] not in {'security', 'functional'}: raise SafetyStop('lane_invalid')
    smoke = []
    for label in ('benign', 'adverse'):
        matches = [c for c in cases if c['lane'] == 'security' and c.get('smoke') == label]
        if len(matches) != 1: raise SafetyStop('smoke_invalid')
        smoke.extend(matches)
    rng = random.Random(seed)
    remaining = sorted([c for c in cases if c not in smoke and c['lane'] == 'security'], key=lambda c: c['id'])
    functional = sorted([c for c in cases if c['lane'] == 'functional'], key=lambda c: c['id'])
    rng.shuffle(remaining); rng.shuffle(functional)
    flip = rng.randrange(2)
    return [{**c, 'arms': ['agent', 'fugu'] if (i + flip) % 2 else ['fugu', 'agent']}
            for i, c in enumerate(smoke + remaining + functional)]


def _validate(doc: Record) -> None:
    if doc.get('schema_version') != 1 or doc.get('kind') != 'frozen_run':
        raise SafetyStop('freeze_schema')
    if any(type(doc.get(k)) is not int or doc[k] != v for k, v in
           [('cap_micro', 10000000), ('arm_cap_micro', 2000000), ('pair_cap_micro', 4000000)]):
        raise SafetyStop('cap_invalid')
    if not isinstance(doc.get('sources'), list) or not isinstance(doc.get('references'), list):
        raise SafetyStop('freeze_schema')
    tariffs = doc.get('tariffs')
    if tariffs is not None and (tariffs.get('account_verified') is not True or
            any('FAKE' in m.get('authority', '') for m in tariffs.get('models', {}).values())):
        raise SafetyStop('tariff_authority')


def _verify_inputs(doc: Record) -> None:
    roots = []
    for source in doc['sources']:
        root = Path(source['root'])
        if tree_manifest(root)['sha256'] != source['manifest']['sha256']:
            raise SafetyStop('source_drift')
        roots.append(root.resolve())
    for ref in doc['references']:
        path = Path(ref['path'])
        if ref['kind'] in {'truth', 'approval'} and any(path.resolve().is_relative_to(root) for root in roots):
            raise SafetyStop('truth_inside_source')
        if byte_hash(path) != ref['sha256']:
            raise SafetyStop(ref['kind'] + '_drift')
    for key in ('engine', 'harness'):
        if key in doc and engine_identity(Path(doc[key]['root'])) != doc[key]['identity']:
            raise SafetyStop(key + '_drift')


def freeze_run(path: Path, doc: Record) -> FrozenRun:
    _validate(doc)
    _verify_inputs(doc)
    immutable_json(path, doc)
    return load_frozen(path)


def load_frozen(path: Path) -> FrozenRun:
    try:
        doc = json.loads(path.read_bytes())
        _validate(doc)
        return FrozenRun(path, doc)
    except (OSError, ValueError, TypeError, KeyError):
        raise SafetyStop('freeze_schema') from None


def verify_frozen(run: FrozenRun) -> None:
    disk = load_frozen(run.path)
    if canonical(disk.doc) != canonical(run.doc):
        raise SafetyStop('freeze_drift')
    _verify_inputs(disk.doc)
