"""Trigger derivation: which lifecycle commands should we detonate?

`derive_triggers(target_dir)` returns shell command strings that reproduce how
a real agent/user would first execute the extension under audit. Rationale:

- ``install`` — package install hooks are the classic rug-pull moment
  (npm postinstall, setup.py, install.sh). Commands, in priority order:
    * ``install.sh`` present        -> ``bash /opt/target/install.sh``
    * ``setup.py`` present          -> ``python /opt/target/setup.py install``
    * ``package.json`` with a
      ``scripts.postinstall`` field  -> ``npm install --prefix /opt/target``
- ``import`` — Python packages get imported (module dirs / .py files):
    ``python -c "import <pkg>"`` for every top-level package/module found
    (skips ``setup.py``, ``test*``, names with invalid identifier chars).
- ``invoke`` — MCP-server-shaped extensions get booted for 3s so startup-time
  behavior runs (dot-separated command from package.json ``bin`` / mcp config
  ``main`` / ``server.py|main.py|__main__.py`` entrypoints), then SIGKILLed.
  Exit code is recorded as 0 for these (boot success isn't the signal).
- ``readme`` — fetch-and-run INSTALL INSTRUCTIONS in README/SKILL.md are the
  markdown-skill execution vector (a victim agent follows the docs). We
  detonate the documented command itself — inside the canaried sandbox —
  so payload-in-docs attacks get empirical evidence instead of an advisory.
  Only target-owned URLs qualify (same repo host/path prefix); third-party
  tool installs (e.g. uv's astral.sh installer) are skipped — executing a
  live third-party supply chain adds canary noise, not signal.

Multiple triggers stack (an npm package can be both installed and imported).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

__all__ = ["derive_triggers"]

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")

# Where the victim image copies target_dir (see docker_driver._write_victim_dockerfile)
TARGET_MOUNT = "/opt/target"


def derive_triggers(target_dir: Path, source: str | None = None) -> list[str]:
    """Return trigger commands for a target dir (deterministic, ordered)."""
    tdir = Path(target_dir)
    triggers: list[str] = []

    # --- install -----------------------------------------------------------
    if (tdir / "install.sh").is_file():
        triggers.append(f"bash {TARGET_MOUNT}/install.sh")
    if (tdir / "setup.py").is_file():
        triggers.append(f"python {TARGET_MOUNT}/setup.py install")
    pkg_json = tdir / "package.json"
    if pkg_json.is_file():
        try:
            scripts = json.loads(pkg_json.read_text(errors="replace")).get("scripts", {})
            if isinstance(scripts, dict) and scripts.get("postinstall"):
                triggers.append(f"npm install --prefix {TARGET_MOUNT}")
        except (ValueError, OSError):
            pass

    # --- import (python package) --------------------------------------------
    py_top = _top_py_modules(tdir)
    triggers.extend(f'python -c "import {m}"' for m in py_top[:10])

    # --- invoke (MCP server entrypoint) --------------------------------------
    entry = _mcp_entrypoint(tdir)
    if entry:
        triggers.append(f"timeout 3 {entry} || test $? -eq 124")

    # --- readme (documented fetch-and-run install) ----------------------------
    triggers.extend(_readme_fetch_run_triggers(tdir, source))

    # --- nested sub-projects (monorepo layouts) --------------------------------
    if not triggers or not _mcp_entrypoint(tdir):
        for sub in _nested_project_dirs(tdir):
            rel = f"{TARGET_MOUNT}/{sub.name}"
            entry = _mcp_entrypoint(sub)
            if entry:
                triggers.append(entry.replace(f"{TARGET_MOUNT}/", f"{rel}/", 1))
            mods = _top_py_modules(sub)
            if mods:
                joined = ", ".join(mods[:5])
                triggers.append(
                    f"python -c \"import sys; sys.path.insert(0, '{rel}'); import {joined}\""
                )

    return triggers


_PROJECT_MARKERS = ("pyproject.toml", "package.json", "requirements.txt", "setup.py")


def _nested_project_dirs(tdir: Path) -> list[Path]:
    """Immediate subdirectories that look like standalone projects."""
    out = []
    for child in sorted(tdir.iterdir()):
        if child.is_dir() and any((child / m).is_file() for m in _PROJECT_MARKERS):
            out.append(child)
    return out


def _top_py_modules(tdir: Path) -> list[str]:
    """Top-level python module names of a directory (shared helper)."""
    mods: list[str] = []
    for child in sorted(tdir.iterdir()):
        name = child.name
        if name == "setup.py" or name.startswith("test"):
            continue
        if child.is_dir() and (child / "__init__.py").is_file() and _IDENT.match(name):
            mods.append(name)
        elif child.is_file() and name.endswith(".py") and _IDENT.match(name[: -3]):
            mods.append(name[: -3])
    return mods


# ``curl|sh``-style one-liners in docs. Captures http(s) URLs from curl/wget
# fetch-and-run lines; the |sh / |bash tail and quoting are dropped.
_FETCH_RUN = re.compile(
    r"(?:curl|wget)[^`\n|;]*?https?://[^`\s|;]+"
)


def _readme_fetch_run_triggers(tdir: Path, source: str | None = None) -> list[str]:
    """Detonate fetch-and-run install instructions from README/SKILL.md.

    The trigger reproduces the documented victim action: fetch the remote
    script and pipe it to a shell inside the sandbox, with canaries set and
    egress captured. Only URLs plausibly owned by the target are detonated
    (see module docstring) — installing third-party tooling is noise.
    """
    owned = _owned_url_prefixes(tdir, source)
    out: list[str] = []
    for name in ("README.md", "README", "SKILL.md"):
        f = tdir / name
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for m in _FETCH_RUN.finditer(text):
            url = m.group(0)
            url = re.sub(r"^(?:curl|wget)[^h]*", "", url)  # strip cmd prefix
            # keep only target-owned URLs
            if owned and not url.startswith(tuple(owned)):
                continue
            cmd = f"curl -fsSL {url} | sh"
            if cmd not in out:
                out.append(cmd)
        if out:
            break  # README/SKILL.md both hit? first file with hits wins
    return out[:3]  # cap: 3 remote detonations per audit


def _owned_url_prefixes(tdir: Path, source: str | None = None) -> list[str]:
    """URL prefixes plausibly owned by the target.

    Sources, in order: the job's git source URL (a repo owns its own GitHub
    host/raw/codeload/releases URLs — this is what makes real-world repos
    derivable), the eval corpus host, and manifest metadata. A URL that is
    not under any of these belongs to a third party and is never detonated.
    """
    prefixes: list[str] = ["https://fugu-test.example"]  # eval corpus host
    src = (source or "").strip()
    if src.startswith(("http://", "https://")):
        prefixes.extend(_source_url_prefixes(src))
    mf = tdir / "manifest.json"
    if mf.is_file():
        try:
            data = json.loads(mf.read_text(errors="replace"))
            for k in ("homepage", "repository", "source"):
                v = data.get(k)
                if isinstance(v, str) and v.startswith("http"):
                    prefixes.append(v.rstrip("/"))
                elif isinstance(v, dict) and isinstance(v.get("url"), str):
                    prefixes.append(v["url"].rstrip("/"))
        except (ValueError, OSError):
            pass
    return prefixes


def _source_url_prefixes(url: str) -> list[str]:
    """URL prefixes a git source URL owns (repo + its raw/codeload/releases)."""
    from urllib.parse import urlsplit

    u = url.strip().rstrip("/")
    if u.endswith(".git"):
        u = u[: -len(".git")]
    out = [u]
    try:
        parts = urlsplit(u)
        host = parts.netloc.lower()
        path = parts.path.strip("/")
    except ValueError:
        return out
    if host.endswith("github.com") and path.count("/") >= 1:
        owner, repo = path.split("/")[:2]
        out.append(f"https://raw.githubusercontent.com/{owner}/{repo}")
        out.append(f"https://codeload.github.com/{owner}/{repo}")
        out.append(f"https://github.com/{owner}/{repo}/releases/download")
    return out


def _mcp_entrypoint(tdir: Path) -> str | None:
    """Best-effort MCP server entrypoint command (dot-form for module mains)."""
    pkg_json = tdir / "package.json"
    if pkg_json.is_file():
        try:
            pkg = json.loads(pkg_json.read_text(errors="replace"))
            bin_ = pkg.get("bin")
            if isinstance(bin_, str):
                return f"node {TARGET_MOUNT}/{bin_}"
            if isinstance(bin_, dict) and bin_:
                return f"node {TARGET_MOUNT}/{next(iter(bin_.values()))}"
        except (ValueError, OSError):
            pass
    for mcp_name in (".mcp.json", "mcp.json", ".cursor/mcp.json"):
        f = tdir / mcp_name
        if not f.is_file():
            continue
        try:
            servers = json.loads(f.read_text(errors="replace")).get("mcpServers", {})
            if isinstance(servers, dict) and servers:
                srv = next(iter(servers.values()))
                if isinstance(srv, dict) and srv.get("main"):
                    return f"node {TARGET_MOUNT}/{srv['main']}"
        except (ValueError, OSError):
            pass
    for cand in ("server.py", "main.py", "__main__.py"):
        f = tdir / cand
        if f.is_file():
            return f"python {TARGET_MOUNT}/{cand}"
    return None
