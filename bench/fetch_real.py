"""Fetch real-world skill samples for external-validity benchmarking.

Clones public skill collections (shallow) and wraps each skill folder as a
labeled benign sample (manifest.fugu.json schema matches corpus/). Re-runnable;
clones live in bench/real/ (gitignored - regenerate anytime).

Sources must be PUBLIC, third-party, benign collections with per-skill
folders containing SKILL.md (attack corpora belong in corpus/, not here).

Layouts supported:

  skills_dir - skill folders live under one subdir of the repo (usually
               ``skills/``); used by anthropics/skills, obra/superpowers,
               skillsdirectory/claude-skills.
  root       - skill folders are direct children of the repo root; used by
               claude-office-skills/skills. Dot/underscore-prefixed dirs and
               dirs without SKILL.md are ignored.

Per-source caps keep the real set balanced (no single repo dominates):
  MAX_PER_SOURCE = 25 samples, skills larger than MAX_SKILL_BYTES are skipped.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

BENCH = Path(__file__).resolve().parent
REAL = BENCH / "real"

MAX_PER_SOURCE = 25                        # samples wrapped per source repo
MAX_SKILL_BYTES = 2 * 1024 * 1024          # skip individual skills > 2 MB


@dataclass(frozen=True)
class Source:
    """One public skill collection and how to read skill folders from it."""

    url: str
    layout: str = "skills_dir"             # "skills_dir" | "root"
    subdir: str = "skills"                 # base dir when layout == "skills_dir"
    include: tuple[str, ...] = field(default_factory=tuple)  # optional allowlist


SOURCES: dict[str, Source] = {
    # Reference set: Anthropic's official example skills (first-party).
    "anthropic-skills": Source(
        url="https://github.com/anthropics/skills",
        layout="skills_dir",
        subdir="skills",
    ),
    # Third-party: Jesse Vincent's widely-used dev-methodology skill library.
    "superpowers": Source(
        url="https://github.com/obra/superpowers",
        layout="skills_dir",
        subdir="skills",
    ),
    # Third-party: community office/business task pack (~136 skills; capped).
    "office-skills": Source(
        url="https://github.com/claude-office-skills/skills",
        layout="root",
    ),
    # Third-party: small community catalog, CC0 originals + MIT re-distributions.
    "skillsdirectory": Source(
        url="https://github.com/skillsdirectory/claude-skills",
        layout="skills_dir",
        subdir="skills",
    ),
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


def discover_skill_dirs(repo: Path, cfg: Source) -> list[Path]:
    """Return sorted skill dirs (folders containing SKILL.md) for a layout."""
    base = repo / cfg.subdir if cfg.layout == "skills_dir" else repo
    if not base.is_dir():
        return []
    out: list[Path] = []
    for d in sorted(base.iterdir()):
        if not d.is_dir() or d.name.startswith((".", "_")):
            continue
        if cfg.include and d.name not in cfg.include:
            continue
        if (d / "SKILL.md").is_file():
            out.append(d)
    return out


def dir_size_bytes(d: Path) -> int:
    return sum(f.stat().st_size for f in d.rglob("*") if f.is_file())


def wrap_samples(
    repo: Path,
    name: str,
    cfg: Source,
    cap: int = MAX_PER_SOURCE,
    out_root: Path | None = None,
) -> int:
    """Turn each discovered skill folder into a labeled benign sample.

    Sample manifests are named ``real-<source>-<skill>`` so names stay unique
    across sources (run_bench keys runs by manifest name).
    """
    out = out_root if out_root is not None else REAL / f"{name}-samples"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    n = 0
    for skill_dir in discover_skill_dirs(repo, cfg)[:cap]:
        size = dir_size_bytes(skill_dir)
        if size > MAX_SKILL_BYTES:
            print(f"  skip {name}/{skill_dir.name}: {size} bytes > {MAX_SKILL_BYTES}")
            continue
        sample = out / skill_dir.name
        shutil.copytree(skill_dir, sample)
        (sample / "manifest.fugu.json").write_text(
            json.dumps(
                {
                    "name": f"real-{name}-{skill_dir.name}",
                    "kind": "benign",
                    "expected_owasp_ids": [],
                    "description": f"Real-world skill from {name} ({cfg.url}); external validity set",
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
    for name, cfg in SOURCES.items():
        repo = fetch(name, cfg.url)
        n = wrap_samples(repo, name, cfg)
        print(f"{name}: {n} skill samples wrapped")
        total += n
    print(f"TOTAL real-world samples: {total} in {REAL}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
