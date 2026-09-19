"""Fetch real-world skill samples for external-validity benchmarking.

Clones public skill collections (shallow) and wraps each skill folder as a
labeled benign sample (manifest.json schema matches corpus/). Re-runnable;
clones live in bench/real/ (gitignored - regenerate anytime).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent
REAL = BENCH / "real"

SOURCES = {
    "anthropic-skills": "https://github.com/anthropics/skills",
}


def sh(*args: str, cwd: Path | None = None) -> str:
    r = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}\n{r.stderr}")
    return r.stdout


def fetch(name: str, url: str) -> Path:
    dest = REAL / name
    if dest.exists():
        print(f"{name}: already present")
        return dest
    REAL.mkdir(parents=True, exist_ok=True)
    print(f"{name}: cloning {url} ...")
    sh("git", "clone", "--depth", "1", url, str(dest))
    return dest


def wrap_samples(repo: Path, name: str) -> int:
    """Turn each skill folder under <repo>/skills into a labeled sample."""
    out_root = REAL / f"{name}-samples"
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True)
    skills_dir = repo / "skills"
    n = 0
    for skill_dir in sorted(skills_dir.iterdir()):
        if not skill_dir.is_dir() or not (skill_dir / "SKILL.md").is_file():
            continue
        sample = out_root / skill_dir.name
        shutil.copytree(skill_dir, sample)
        (sample / "manifest.fugu.json").write_text(
            json.dumps(
                {
                    "name": f"real-{skill_dir.name}",
                    "kind": "benign",
                    "expected_owasp_ids": [],
                    "description": f"Real-world skill from {name} (external validity set)",
                    "provenance": "real",
                },
                indent=2,
            )
            + "\n"
        )
        n += 1
    return n


def main() -> int:
    total = 0
    for name, url in SOURCES.items():
        repo = fetch(name, url)
        n = wrap_samples(repo, name)
        print(f"{name}: {n} skill samples wrapped")
        total += n
    print(f"TOTAL real-world samples: {total} in {REAL}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
