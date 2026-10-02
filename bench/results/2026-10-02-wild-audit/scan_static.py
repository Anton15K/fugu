"""Run frozen Fugu S0/S1 over exact pinned source scope; never import auditees."""
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


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def scan(cache: Path) -> dict:
    import fugu
    from fugu.pipeline import build_stages, run_stages
    from fugu.types import AuditJob, JobStatus
    expected = json.loads((HERE / 'engine-manifest.json').read_text())['source_hashes']
    base = Path(fugu.__file__).parent
    observed = {'src/fugu/' + str(p.relative_to(base)): sha(p) for p in base.rglob('*.py')}
    if observed != expected:
        raise ValueError('Engine differs from frozen hash manifest')
    acquisition = {p['repository']: p for p in json.loads((HERE / 'acquisition.json').read_text())['projects']}
    scope = json.loads((HERE / 'scope.json').read_text())['files']
    rows = []
    start = time.perf_counter()
    for repo, files in scope.items():
        inputs = {}
        with tempfile.TemporaryDirectory(prefix='fugu-wild-static-') as tmp:
            target = Path(tmp)
            for rel in files:
                original = cache / repo.replace('/', '--') / rel
                if original.is_symlink() or not original.is_file():
                    raise ValueError('Source must be a regular file')
                actual = sha(original)
                if actual != acquisition[repo]['files_sha256'][rel]:
                    raise ValueError('Pinned source hash mismatch')
                dest = target / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, dest)
                inputs[rel] = actual
            job = AuditJob(id='wild-static', source=str(target), status=JobStatus.running)
            stages = build_stages(include_detonation=False, include_semantic=False,
                                  include_harness=False, include_reputation=False)
            results = await run_stages(job, target, stages)
        rows.append({'repository': repo, 'commit': acquisition[repo]['commit'],
                     'input_sha256': inputs, 'stages': [asdict(r) for r in results]})
        print(repo, 'files', len(inputs), 'findings', sum(len(r.findings) for r in results), flush=True)
    return {'measured_utc': datetime.now(timezone.utc).isoformat(),
            'scope': 'S0 concealment + S1 static on 44 selected files; no auditee execution',
            'engine_hashes_verified': True, 'source_snapshot': str(base),
            'paid_model_calls': 0, 'rows': rows, 'elapsed_s': round(time.perf_counter() - start, 3)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error('Refusing to overwrite measurement')
    result = asyncio.run(scan(args.cache))
    args.out.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
