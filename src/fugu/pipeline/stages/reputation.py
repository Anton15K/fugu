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
from fugu.types import AuditJob, EvidenceSnippet, Finding, StageResult

MAX_QUERIES = 4
_RESULT_MARKER = "tavily.result"

SearchFn = Callable[[str, str], dict[str, Any]]  # (api_key, query) -> tavily response


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
_SKIP_DOMAINS = {
    "example.com", "example.org", "example.net", "localhost", "schema.org",
    "www.w3.org", "json-schema.org", "github.com", "npmjs.com", "pypi.org",
}
_PYPI_SETUP_NAME = re.compile(r"name\s*=\s*[\"']([A-Za-z0-9_.-]+)[\"']")


def extract_identifiers(target: Path, max_files: int = 200) -> dict[str, list[str]]:
    """Package names, dependencies and outbound domains worth searching."""
    packages: list[str] = []
    domains: list[str] = []
    try:
        files, _ = collect_text_files(target, 1_000_000, max_files)
    except Exception:
        return {"packages": [], "domains": []}

    pkg_json = target / "package.json"
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
    setup_py = target / "setup.py"
    pyproject = target / "pyproject.toml"
    for manifest in (setup_py, pyproject):
        if manifest.is_file():
            text = manifest.read_text(errors="replace")
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
    return {"packages": unique_pkgs[:6], "domains": domains[:6]}


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
        queries: list[tuple[str, str]] = []
        for pkg in ids["packages"]:
            queries.append((pkg, f'"{pkg}" package vulnerability OR typosquat OR malware report'))
        for domain in ids["domains"]:
            queries.append((domain, f'"{domain}" domain malware OR data exfiltration report'))
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
        for ident, q in queries:
            try:
                resp = search(api_key, q)
            except Exception as exc:
                call_errors.append(f"{ident}: {type(exc).__name__}: {exc}")
                continue
            results = resp.get("results") or []
            results_meta.append({"identifier": ident, "results": len(results)})
            finding = self._reputation_finding(ident, results)
            if finding:
                findings.append(finding)

        return StageResult(
            stage=self.name,
            ok=True,
            findings=findings,
            metrics={
                "identifiers": ids,
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
    def _reputation_finding(cls, ident: str, results: list[dict[str, Any]]) -> Finding | None:
        hits: list[tuple[str, str, str]] = []  # url, title, matched word
        for r in results:
            title = str(r.get("title") or "")
            url = str(r.get("url") or "")
            blob = f"{title} {r.get('content') or ''}"
            m = cls._BAD_WORDS.search(blob)
            if m:
                hits.append((url, title, m.group(0)))
        if not hits:
            return None
        cve = any(h[2].startswith("CVE") for h in hits)
        return Finding(
            owasp_ids=["MCP04", "LLM03"],
            title=f"Adverse web reputation for '{ident}'",
            detail=(
                f"{len(hits)} search result(s) mention "
                + ("a CVE" if cve else "security keywords")
                + f" in connection with '{ident}'. Advisory signal only - verify the "
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
