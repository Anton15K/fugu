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


def derive_triggers(target_dir: Path) -> list[str]:
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
    py_top: list[str] = []
    for child in sorted(tdir.iterdir()):
        name = child.name
        if name == "setup.py" or name.startswith("test"):
            continue
        if child.is_dir() and (child / "__init__.py").is_file() and _IDENT.match(name):
            py_top.append(name)
        elif child.is_file() and name.endswith(".py") and _IDENT.match(name[: -len(".py")]):
            py_top.append(name[: -len(".py")])
    triggers.extend(f'python -c "import {m}"' for m in py_top[:10])

    # --- invoke (MCP server entrypoint) --------------------------------------
    entry = _mcp_entrypoint(tdir)
    if entry:
        triggers.append(f"timeout 3 {entry} || test $? -eq 124")

    return triggers


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
