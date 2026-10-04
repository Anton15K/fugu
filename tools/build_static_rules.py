"""Build the pinned, MIT-licensed static analysis component for this host.

Requires an existing Rust toolchain. Does not install system dependencies,
touch shared environments, or execute any audited extension. Attribution and
source/build hashes are retained in repository notices and the build manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

PIN = 'f739e120cd7dc253fead2a1f13668f9535e4d8a5'
URL = f'https://codeload.github.com/ksek87/fuzzd/tar.gz/{PIN}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'src/fugu/_bin/static-rules')
    args = parser.parse_args()
    cargo = shutil.which('cargo')
    if not cargo:
        raise SystemExit('An existing Rust toolchain is required; no dependencies were installed.')
    with urllib.request.urlopen(URL, timeout=60) as response:
        archive = response.read(15_000_001)
    if len(archive) > 15_000_000:
        raise SystemExit('Source archive exceeded the bounded acquisition limit.')
    with tempfile.TemporaryDirectory(prefix='fugu-rules-build-') as temp:
        root = Path(temp)
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
            for member in tar.getmembers():
                parts = Path(member.name).parts[1:]
                if not parts or any(p in ('..', '/') for p in parts) or not member.isfile():
                    continue
                destination = root.joinpath(*parts)
                if not destination.is_relative_to(root) or member.size > 10_000_000:
                    raise SystemExit('Unexpected source archive entry.')
                stream = tar.extractfile(member)
                if stream:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(stream.read())
        subprocess.run([cargo, 'build', '--locked', '--release'], cwd=root, check=True, timeout=1800)
        artifact = root / 'target/release/fuzzd'
        args.destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(artifact, args.destination)
        args.destination.chmod(0o755)
        manifest = {'upstream': 'https://github.com/ksek87/fuzzd', 'pin': PIN,
                    'license': 'MIT', 'source_archive_sha256': hashlib.sha256(archive).hexdigest(),
                    'binary_sha256': hashlib.sha256(args.destination.read_bytes()).hexdigest(),
                    'build': 'cargo build --locked --release', 'platform': 'native host'}
        args.destination.with_suffix('.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Static analysis component installed. Restart Fugu to activate it.')


if __name__ == '__main__':
    main()
