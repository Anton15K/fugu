"""Acquire pinned public sources as inert regular files in a local-only cache."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request

MANIFEST = Path(__file__).with_name('shortlist.json')
LIMIT = 80_000_000


def acquire(project: dict, cache: Path) -> dict:
    repo, commit = project['repository'], project['commit']
    target = cache / repo.replace('/', '--')
    if target.exists():
        raise ValueError(f'Refusing existing cache: {target}')
    url = f'https://codeload.github.com/{repo}/tar.gz/{commit}'
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError(f'Archive exceeds cap: {repo}')
    files, skipped = {}, []
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            relative = PurePosixPath(*path.parts[1:])
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe archive path')
            if not member.isfile():
                if not member.isdir():
                    skipped.append({'path': str(relative), 'reason': 'nonregular'})
                continue
            if member.size > 2_000_000:
                skipped.append({'path': str(relative), 'reason': 'large'})
                continue
            total += member.size
            if total > LIMIT:
                raise ValueError('Extracted source cap exceeded')
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError('Regular member unreadable')
            content = handle.read()
            dest = target / str(relative)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
            files[str(relative)] = hashlib.sha256(content).hexdigest()
    return {'repository': repo, 'commit': commit, 'archive_url': url,
            'archive_sha256': hashlib.sha256(data).hexdigest(), 'archive_bytes': len(data),
            'cache_directory': str(target), 'files_sha256': files, 'skipped': skipped}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error('Refusing to overwrite acquisition evidence')
    projects = json.loads(MANIFEST.read_text())['projects']
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda p: acquire(p, args.cache), projects))
    args.out.write_text(json.dumps({'projects': rows}, indent=2) + '\n')
    for row in rows:
        print(row['repository'], len(row['files_sha256']), 'regular files;', len(row['skipped']), 'omitted')


if __name__ == '__main__':
    main()
