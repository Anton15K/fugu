"""Install Fugu's dedicated Codex profile-v2 files (Python 3.11+)."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tomllib


PROFILE_NAMES = ("fugu-rig-high.config.toml", "fugu-rig-medium.config.toml")


def _check_existing(destination: Path, content: bytes) -> bool:
    if destination.is_symlink():
        raise ValueError(f"Refusing symlinked profile: {destination}")
    if not destination.exists():
        return False
    if not destination.is_file() or destination.read_bytes() != content:
        raise ValueError(f"Existing profile differs; left unchanged: {destination}")
    return True


def install_profiles(source: Path, target: Path) -> list[Path]:
    """Validate both files before writing; never replace existing profiles."""
    pending: list[tuple[Path, bytes]] = []
    for name in PROFILE_NAMES:
        content = (source / name).read_bytes()
        tomllib.loads(content.decode("utf-8"))
        destination = target / name
        if not _check_existing(destination, content):
            pending.append((destination, content))

    target.mkdir(parents=True, exist_ok=True)
    installed: list[Path] = []
    for destination, content in pending:
        try:
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            _check_existing(destination, content)
            continue
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
        installed.append(destination)
    return installed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-home", type=Path)
    args = parser.parse_args()
    target = args.codex_home or Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    source = Path(__file__).resolve().parent / "runtime"
    try:
        installed = install_profiles(source, target)
    except (OSError, ValueError) as error:
        print(f"Profile installation failed: {error}", file=sys.stderr)
        return 1
    for name in PROFILE_NAMES:
        destination = target / name
        status = "Installed" if destination in installed else "Unchanged"
        print(f"{status}: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
