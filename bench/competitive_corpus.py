"""Deterministic, label-free input preparation; no detector or target execution."""
from __future__ import annotations

import argparse
import ast
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

METADATA_NAMES = {"manifest.json", "manifest.fugu.json", "set.json", "_expected.json"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tool_packet(original: dict) -> dict:
    """Keep original MCP fields; absence of a schema remains absence."""
    for field in ("name", "description"):
        if not isinstance(original.get(field), str) or not original[field]:
            raise ValueError(f"missing MCP {field}")
    tool = {field: original[field] for field in ("name", "description")}
    if "inputSchema" in original:
        if not isinstance(original["inputSchema"], dict):
            raise ValueError("invalid original schema")
        tool["inputSchema"] = json.loads(json.dumps(original["inputSchema"]))
    return {"tools": [tool]}


def content_hash(tool: dict) -> str:
    """Name/description identity also detects older invented-schema wrappers."""
    return sha256(json.dumps({k: tool[k] for k in ("name", "description")},
                             sort_keys=True, ensure_ascii=False).encode())


def select_stratified(rows: list[dict], count: int, *, seed: str,
                      exclude_ids=(), exclude_content=()) -> list[dict]:
    if type(count) is not int or count < 0:
        raise ValueError("invalid selection count")
    if len({r["id"] for r in rows}) != len(rows):
        raise ValueError("duplicate candidate identity")
    excluded_ids, excluded_content = set(exclude_ids), set(exclude_content)
    groups = defaultdict(list)
    for row in rows:
        if row["id"] in excluded_ids or row.get("content_hash") in excluded_content:
            continue
        groups[str(row.get("stratum", "all"))].append(row)
    def rank(value):
        return sha256((seed + "\0" + value).encode())
    for group in groups.values():
        group.sort(key=lambda r: (rank(r["id"]), r["id"]))
    strata = sorted(groups, key=lambda s: (rank(s), s))
    chosen = []
    while len(chosen) < count:
        added = False
        for stratum in strata:
            if groups[stratum] and len(chosen) < count:
                chosen.append(groups[stratum].pop(0))
                added = True
        if not added:
            raise ValueError("insufficient eligible pool")
    return chosen


def input_hashes(target: Path) -> dict[str, str]:
    target = Path(target)
    if target.is_symlink() or not target.is_dir():
        raise ValueError("symlink or missing input root")
    result = {}
    for path in sorted(target.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink input descendant")
        if path.is_file() and path.name not in METADATA_NAMES:
            result[path.relative_to(target).as_posix()] = sha256(path.read_bytes())
        elif not path.is_file() and not path.is_dir():
            raise ValueError("nonregular input")
    return result


def fingerprint(hashes: dict) -> str:
    return sha256(json.dumps(hashes, sort_keys=True).encode())


def copy_input(source: Path, target: Path, hashes: dict) -> None:
    source, target = Path(source), Path(target)
    actual = input_hashes(source)
    if any(actual.get(name) != digest for name, digest in hashes.items()):
        raise ValueError("source input hash mismatch")
    if target.exists() or target.is_symlink():
        if input_hashes(target) != hashes:
            raise ValueError("existing target hash mismatch; refusing overwrite")
        return
    target.mkdir(parents=True)
    for name, expected in hashes.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative.name in METADATA_NAMES:
            raise ValueError("invalid input filename")
        data = (source / relative).read_bytes()
        if sha256(data) != expected:
            raise ValueError("input hash changed while copying")
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


def validate_sources(target: Path) -> list[dict]:
    """Parse syntax only. Never import modules or invoke a target entry point."""
    input_hashes(target)  # Reject symlinks before any parser reads.
    results = []
    for p in sorted(Path(target).rglob("*")):
        if not p.is_file() or p.suffix not in {".py", ".js", ".sh", ".json"}:
            continue
        row = {"path": p.relative_to(target).as_posix(), "sha256": sha256(p.read_bytes()),
               "status": "valid", "parser": None, "imports": []}
        try:
            if p.suffix == ".py":
                row["parser"] = "ast.parse:Python3.10"
                tree = ast.parse(p.read_text(), feature_version=(3, 10))
                if any(isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                       and n.id in {"false", "true", "null"} for n in ast.walk(tree)):
                    raise ValueError("JSON Boolean/null name in Python source")
                row["imports"] = sorted({n.names[0].name.split(".")[0] if isinstance(n, ast.Import)
                                         else (n.module or "").split(".")[0]
                                         for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))})
            elif p.suffix == ".json":
                row["parser"] = "json.loads"
                json.loads(p.read_text())
            else:
                executable = shutil.which("node" if p.suffix == ".js" else "bash")
                row["parser"] = "node --check" if p.suffix == ".js" else "bash -n"
                if not executable:
                    row["status"] = "unavailable"
                else:
                    result = subprocess.run([executable, "--check" if p.suffix == ".js" else "-n", str(p.resolve())],
                                            capture_output=True, timeout=15,
                                            env={"PATH": os.defpath, "LANG": "C.UTF-8"})
                    if result.returncode:
                        row.update(status="invalid", error="parser_rejected_source")
        except (SyntaxError, ValueError, UnicodeError, subprocess.TimeoutExpired) as exc:
            row.update(status="invalid", error=type(exc).__name__)
        results.append(row)
    return results


def prepare(spec: dict, target_root: Path) -> dict:
    """A private candidate index supplies sources; public output contains hashes."""
    cases = []
    for group in spec["groups"]:
        selected = select_stratified(group["candidates"], group["count"], seed=spec["seed"],
                                     exclude_ids=group.get("exclude_ids", []),
                                     exclude_content=group.get("exclude_content", []))
        for candidate in selected:
            target = Path(target_root) / f"{len(cases):04d}"
            if "tool" in candidate:
                data = (json.dumps(tool_packet(candidate["tool"]), ensure_ascii=False, indent=2) + "\n").encode()
                hashes = {"tools.json": sha256(data)}
                if target.exists():
                    if input_hashes(target) != hashes:
                        raise ValueError("existing packet hash mismatch")
                else:
                    target.mkdir(parents=True)
                    (target / "tools.json").write_bytes(data)
            else:
                hashes = candidate["source_hashes"]
                copy_input(Path(candidate["source_directory"]), target, hashes)
            row = {k: candidate[k] for k in ("id", "cohort", "kind", "provenance", "overlap")}
            resolved, cwd = target.resolve(), Path.cwd().resolve()
            portable = resolved.relative_to(cwd).as_posix() if resolved.is_relative_to(cwd) else str(resolved)
            row.update(target=portable, input_sha256=hashes)
            if "expected" in candidate:
                row["expected"] = candidate["expected"]
            if "members" in candidate:
                row["members"] = candidate["members"]
            cases.append(row)
    if len({row["id"] for row in cases}) != len(cases):
        raise ValueError("duplicate selected case identity")
    return {"schema": 1, "status": "NOT RELEASED", "seed": spec["seed"],
            "selection_protocol": spec["selection_protocol"], "cases": cases}


def append_metadata(original: dict, candidates: list[dict], *, count: int, seed: str,
                    target_root: Path, exclude_ids=(), exclude_content=()) -> dict:
    """Append hash-ranked metadata attacks while preserving every original row/input."""
    if original.get("schema") != 1:
        raise ValueError("unsupported original manifest")
    ids, content = set(exclude_ids), set(exclude_content)
    destination = Path(target_root).resolve()
    for row in original["cases"]:
        target = Path(row["target"])
        if input_hashes(target) != row["input_sha256"]:
            raise ValueError("original input hash drift")
        resolved = target.resolve()
        if resolved == destination or resolved in destination.parents or destination in resolved.parents:
            raise ValueError("extra targets overlap original input")
        ids.add(row["id"])
        if row["cohort"] == "mcp_metadata":
            for tool in json.loads((target / "tools.json").read_text())["tools"]:
                content.add(content_hash(tool))
    for candidate in candidates:
        if candidate["cohort"] != "mcp_metadata" or candidate["kind"] != "malicious":
            raise ValueError("extra candidate is not a metadata attack")
        if candidate["content_hash"] != content_hash(candidate["tool"]):
            raise ValueError("candidate content fingerprint drift")
    spec = {"seed": seed, "selection_protocol": "SHA256(seed+NUL+id), round-robin hash-ranked strata; no detector results",
            "groups": [{"count": count, "candidates": candidates,
                        "exclude_ids": sorted(ids), "exclude_content": sorted(content)}]}
    extra = prepare(spec, target_root)
    result = json.loads(json.dumps(original))
    result["cases"].extend(extra["cases"])
    result["extension"] = {"seed": seed, "selection_protocol": spec["selection_protocol"],
                           "original_count": len(original["cases"]), "appended_count": count}
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = prepare(json.loads(args.spec.read_text()), args.targets)
    data = json.dumps(manifest, sort_keys=True, indent=2) + "\n"
    if args.output.exists() and args.output.read_text() != data:
        raise ValueError("refusing to overwrite a different manifest")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(data)


if __name__ == "__main__":
    main()
