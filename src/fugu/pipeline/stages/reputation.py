"""Stage 5 (S5) - reputation: web lookups on the extension's identifiers.

Extracts identifiers a reviewer would check (package names from manifests,
dependency names, outbound domains/hosts) and asks Tavily about each:
vulnerabilities, typosquat reports, malware write-ups, project health.

Findings are advisory and always cite their sources (url + title); the
Tavily bonus prize requires a runtime call, which this stage makes when
TAVILY_API_KEY is set. Offline: no-op like the other live stages.
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

from fugu.pipeline.stages.concealment import collect_text_files
from fugu.source_safety import validate_source_tree
from fugu.types import AuditJob, EvidenceSnippet, Finding, StageResult

MAX_QUERIES = 4
_RESULT_MARKER = "tavily.result"

SearchFn = Callable[[str, str], dict[str, Any]]  # (api_key, query) -> tavily response


def osv_query(package: str, version: str, ecosystem: str = "PyPI") -> list[dict[str, Any]]:
    """Authoritative vulnerability check: OSV.dev structured affected-ranges
    for the EXACT version pinned in the codebase. Free, no key. Returns the
    raw vuln entries (id, summary, aliases, affected)."""
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(
            {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
        ).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read()).get("vulns", [])


def _osv_finding(pkg: str, version: str, vulns: list[dict[str, Any]]) -> Finding:
    ids = [v.get("id") or "" for v in vulns]
    aliases = sorted({a for v in vulns for a in v.get("aliases", []) if a.startswith("GHSA") or a.startswith("CVE")})
    summary = str(vulns[0].get("summary") or "known vulnerability")[:140]
    return Finding(
        owasp_ids=["MCP04", "LLM03"],
        title=f"{len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'} in '{pkg}' @ {version}",
        detail=(
            f"OSV.dev reports {len(vulns)} vulnerabilit{'y' if len(vulns) == 1 else 'ies'} "
            f"affecting {pkg} at exactly {version} - the version pinned in the "
            f"codebase lock/manifest. {summary}. Verified against structured "
            "affected-ranges, not web text. "
            + (f"Identifiers: {', '.join((aliases + ids)[:4])}. " if ids else "")
            + "Advisory: upgrade the pin."
        ),
        severity="medium",
        confidence="measured",
        stage="reputation",
        evidence=[
            EvidenceSnippet(
                source=f"osv.dev/{i or 'vuln'}",
                excerpt=str(v.get("summary") or v.get("id", ""))[:160],
                meta={"package": pkg, "version": version, "id": v.get("id")},
            )
            for v, i in zip(vulns[:3], ids[:3])
        ],
    )


def _default_search(api_key: str, query: str) -> dict[str, Any]:
    req = urllib.request.Request(
        "https://api.tavily.com/search",
        data=json.dumps(
            {
                "query": query,
                "max_results": 5,
                "search_depth": "basic",
                "include_answer": False,
            }
        ).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


_MANIFEST_NAME_RE = re.compile(r"\"name\"\s*:\s*\"([A-Za-z0-9_.@/-]+)\"")
_DEPENDENCY_KEYS = ("dependencies", "devDependencies", "requires", "install_requires")
_DOMAIN_RE = re.compile(r"\bhttps?://([a-z0-9.-]+\.[a-z]{2,})\b", re.I)
_GENERIC_IDENTIFIERS = {
    "mcp", "http", "https", "cli", "sdk", "api", "core", "utils", "tools",
    "server", "client", "common", "types", "config", "test", "docs",
}
_SKIP_DOMAINS = {
    "example.com", "example.org", "example.net", "localhost", "schema.org",
    "www.w3.org", "json-schema.org", "github.com", "npmjs.com", "pypi.org",
}
_PYPI_SETUP_NAME = re.compile(r"name\s*=\s*[\"']([A-Za-z0-9_.-]+)[\"']")

# exact pinned versions from uv.lock / poetry.lock (codebase truth, better
# than manifest floors):  name = "httpx"\nversion = "0.28.1"
_LOCK_ENTRY = re.compile(r'(?m)^name = "([A-Za-z0-9_.-]+)"\nversion = "([^"]+)"')
# npm lockfiles: "httpx": {"version": "1.2.3"}
_NPM_LOCK_ENTRY = re.compile(r'"([@A-Za-z0-9_./-]+)":\s*\{\s*"version":\s*"([^"]+)"')
# first version-ish token in a spec: >=0.28.1, ~=1.6, ==2.0.0
_DEP_VERSION = re.compile(r"[=<>~!^]*\s*(\d[\w.*-]*)")
_DEP_NAME = re.compile(r"[\"']([A-Za-z0-9_][A-Za-z0-9_.-]*)[!<>~=@;\[ ]")


def extract_identifiers(target: Path, max_files: int = 200) -> dict[str, list[str]]:
    """Package names, dependencies and outbound domains worth searching."""
    target = validate_source_tree(target)
    packages: list[str] = []
    domains: list[str] = []
    dep_versions: dict[str, str | None] = {}
    try:
        files, _ = collect_text_files(target, 1_000_000, max_files)
    except Exception:
        return {"packages": [], "domains": [], "dep_versions": {}}

    # Lock files are the strongest signal: the EXACT version the target runs.
    # Walk root + nested project dirs.
    for mdir in [target] + [
        c for c in sorted(target.iterdir()) if c.is_dir()
    ]:
        for lock_name in ("uv.lock", "poetry.lock", "package-lock.json", "npm-shrinkwrap.json"):
            lock = mdir / lock_name
            if not lock.is_file():
                continue
            try:
                text = lock.read_text(errors="replace")
            except OSError:
                continue
            for nm, ver in _LOCK_ENTRY.findall(text):
                dep_versions[nm] = ver
            for nm, ver in _NPM_LOCK_ENTRY.findall(text):
                dep_versions.setdefault(nm, ver)

    # manifest dirs: root + nested sub-projects (monorepo layouts — the
    # server commonly lives one level down, as in whatsapp-mcp)
    manifest_dirs = [target]
    try:
        for child in sorted(target.iterdir()):
            if child.is_dir() and any(
                (child / m).is_file() for m in ("package.json", "pyproject.toml", "setup.py")
            ):
                manifest_dirs.append(child)
    except OSError:
        pass

    for mdir in manifest_dirs:
        pkg_json = mdir / "package.json"
        if pkg_json.is_file():
            try:
                doc = json.loads(pkg_json.read_text(errors="replace"))
                if isinstance(doc.get("name"), str):
                    packages.append(doc["name"])
                for key in ("dependencies", "devDependencies"):
                    deps = doc.get(key)
                    if isinstance(deps, dict):
                        packages.extend(str(d) for d in deps)
            except ValueError:
                pass
        setup_py = mdir / "setup.py"
        pyproject = mdir / "pyproject.toml"
        for manifest in (setup_py, pyproject):
            if not manifest.is_file():
                continue
            text = manifest.read_text(errors="replace")
            if manifest.name == "pyproject.toml":
                # [project] name = "..."  (PEP 621)
                m = re.search(r'(?m)^\s*name\s*=\s*"([A-Za-z0-9_.-]+)"', text)
                if m:
                    packages.append(m.group(1))
                # dependencies = ["pkg>=1", ...]
                deps_m = re.search(r"(?ms)^dependencies\s*=\s*\[(.*?)\]", text)
                if deps_m:
                    for spec in re.findall(r'"([^"]+)"', deps_m.group(1)):
                        nm_m = _DEP_NAME.match(f'"{spec}"')
                        if not nm_m:
                            continue
                        nm = nm_m.group(1)
                        ver = _DEP_VERSION.search(spec)
                        if ver:
                            dep_versions.setdefault(nm, ver.group(1))
                        packages.append(nm)
            else:
                m = _PYPI_SETUP_NAME.search(text)
                if m:
                    packages.append(m.group(1))

    for tf in files:
        for m in _DOMAIN_RE.finditer(tf.text):
            host = m.group(1).lower()
            if host not in _SKIP_DOMAINS and host not in domains:
                domains.append(host)

    seen: set[str] = set()
    unique_pkgs = [p for p in packages if not (p in seen or seen.add(p))]
    return {
        "packages": unique_pkgs[:6],
        "domains": domains[:6],
        "dep_versions": {p: dep_versions.get(p) for p in unique_pkgs[:6]},
    }


class ReputationStage:
    """S5 - Tavily-backed reputation lookups (advisory, source-cited)."""

    name = "reputation"

    def __init__(self, search_fn: SearchFn | None = None, *, max_queries: int = MAX_QUERIES):
        self._search_fn = search_fn
        self.max_queries = max_queries

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        import os

        t0 = time.perf_counter()
        search = self._search_fn
        api_key = os.environ.get("TAVILY_API_KEY", "").strip()
        if search is None:
            if not api_key:
                return StageResult(
                    stage=self.name,
                    ok=True,
                    metrics={"skipped": "no TAVILY_API_KEY; reputation offline"},
                )
            search = _default_search

        ids = extract_identifiers(target)
        dep_versions: dict[str, str | None] = ids.get("dep_versions", {})
        queries: list[tuple[str, str, str | None]] = []
        for pkg in ids["packages"]:
            ver = dep_versions.get(pkg)
            # Codebase truth first: search the EXACT version the target pins
            # (lock file, else manifest floor). A CVE hit for an unpinned
            # name is likely stale for this target.
            if ver:
                queries.append((pkg, f'"{pkg}" {ver} vulnerability CVE', ver))
            else:
                queries.append((pkg, f'"{pkg}" package vulnerability OR typosquat OR malware report', None))
        for domain in ids["domains"]:
            queries.append((domain, f'"{domain}" domain malware OR data exfiltration report', None))
        queries = queries[: self.max_queries]
        if not queries:
            return StageResult(
                stage=self.name,
                ok=True,
                metrics={"skipped": "no searchable identifiers found"},
            )

        findings: list[Finding] = []
        call_errors: list[str] = []
        results_meta: list[dict[str, Any]] = []

        # --- authoritative CVE check: OSV vs codebase-pinned versions -------
        osv_meta: list[dict[str, Any]] = []
        if os.environ.get("FUGU_DISABLE_OSV"):
            osv_meta.append({"note": "disabled via FUGU_DISABLE_OSV"})
        else:
            for pkg, ver in (dep_versions or {}).items():
                if not ver or len(pkg) < 5 or pkg.lower() in _GENERIC_IDENTIFIERS:
                    continue
                eco = "npm" if any(
                    (Path(target) / l).is_file()
                    for l in ("package-lock.json", "npm-shrinkwrap.json")
                ) else "PyPI"
                try:
                    vulns = osv_query(pkg, ver, ecosystem=eco)
                except Exception as exc:  # noqa: BLE001 - OSV down = degraded, not failed
                    call_errors.append(f"osv:{pkg}: {type(exc).__name__}: {exc}")
                    continue
                osv_meta.append({"package": pkg, "version": ver, "vulns": len(vulns)})
                if vulns:
                    findings.append(_osv_finding(pkg, ver, vulns))
        for ident, q, ver in queries:
            try:
                resp = search(api_key, q)
            except Exception as exc:
                call_errors.append(f"{ident}: {type(exc).__name__}: {exc}")
                continue
            results = resp.get("results") or []
            results_meta.append({"identifier": ident, "version": ver, "results": len(results)})
            finding = self._reputation_finding(ident, results, version=ver)
            if finding:
                findings.append(finding)

        return StageResult(
            stage=self.name,
            ok=True,
            findings=findings,
            metrics={
                "identifiers": ids,
                "osv": osv_meta,
                "queries": len(queries),
                "results": results_meta,
                "call_errors": call_errors,
                "findings": len(findings),
                "duration_s": round(time.perf_counter() - t0, 3),
            },
        )

    _BAD_WORDS = re.compile(
        r"(?i)\b(malware|malicious|typosquat|vulnerabilit\w+|CVE-\d{4}-\d+|"
        r"backdoor|trojan|exfiltrat\w+|compromised|supply.chain attack)\b"
    )

    @classmethod
    def _reputation_finding(
        cls, ident: str, results: list[dict[str, Any]], *, version: str | None = None
    ) -> Finding | None:
        # Anti-crying-wolf: a hit requires BOTH (a) the identifier itself
        # appearing in the result text (not a keyword in a loosely-related
        # article) AND (b) a security word nearby. Searching "X package
        # vulnerability" returns security NEWS; only results that are
        # actually ABOUT the identifier count.
        ident_l = ident.lower()
        version_l = (version or "").lower()
        # Generic identifiers (short acronyms, common words) pollute results:
        # "mcp" matches every MCP-security news article ever written. Require
        # enough specificity for the web-reputation signal to be meaningful.
        if len(ident) < 5 or ident.lower() in _GENERIC_IDENTIFIERS:
            return None
        hits: list[tuple[str, str, str]] = []  # url, title, matched word
        for r in results:
            title = str(r.get("title") or "")
            url = str(r.get("url") or "")
            blob = f"{title} {r.get('content') or ''}"
            m = cls._BAD_WORDS.search(blob)
            if not (m and ident_l in blob.lower()):
                continue
            # CVE relevance is decided AUTHORITATIVELY by OSV against the
            # codebase-pinned version (structured affected-ranges), not by
            # text-matching search snippets — those proved unreliable both
            # ways (pages say "before 0.23.0" without naming the affected
            # version; unrelated pages name current versions incidentally).
            # So when we have a pinned version + OSV verdict, drop CVE-ish
            # web hits for that package; keep malware/typosquat/backdoor
            # signals (version-independent).
            if version and m.group(0).lower().startswith(("cve", "vulnerabilit")):
                continue
            hits.append((url, title, m.group(0)))
        if not hits:
            return None
        cve = any(h[2].startswith("CVE") for h in hits)
        return Finding(
            owasp_ids=["MCP04", "LLM03"],
            title=f"Adverse web reputation for '{ident}'" + (f" @ {version}" if version else ""),
            detail=(
                f"{len(hits)} search result(s) mention "
                + ("a CVE" if cve else "security keywords")
                + f" in connection with '{ident}'"
                + (f" at the version pinned in the codebase ({version})" if version else "")
                + ". Advisory signal only - verify the "
                "sources before acting (reputation is not proof of malice)."
            ),
            severity="medium" if cve else "low",
            confidence="advisory",
            stage="reputation",
            evidence=[
                EvidenceSnippet(
                    source=f"tavily:{u}",
                    excerpt=f"{t[:160]} (matched: {w})",
                    meta={"identifier": ident, "matched": w},
                )
                for u, t, w in hits[:3]
            ],
        )


__all__ = ["ReputationStage", "extract_identifiers"]
