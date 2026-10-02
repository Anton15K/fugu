"""Reconstruct the hash-pinned Fugu engine using read-only local Git objects."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    manifest = json.loads((here / 'engine-manifest.json').read_text())
    if args.out.exists() or args.out.is_symlink():
        parser.error('Use a fresh engine directory; existing paths are preserved')
    files = {}
    for rel, expected in manifest['engine_source_hashes'].items():
        path = PurePosixPath(rel)
        if path.parts[:2] != ('src', 'fugu') or '..' in path.parts or path.suffix != '.py':
            raise ValueError('Unexpected engine manifest path')
        data = subprocess.run(
            ['git', 'show', f"{manifest['baseline_commit']}:{rel}"],
            cwd=here.parents[2], check=True, capture_output=True,
        ).stdout
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'Baseline source mismatch: {rel}')
        files[str(PurePosixPath(*path.parts[1:]))] = data
    args.out.mkdir(parents=True)
    for rel, data in files.items():
        dest = args.out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    print(f'Restored {len(files)} verified Fugu Python files; no Git mutation')


if __name__ == '__main__':
    main()
