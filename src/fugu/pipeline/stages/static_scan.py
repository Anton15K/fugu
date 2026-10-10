"""Stage 1 (S1) - deterministic regex/rule static scanner.

Second local stage after S0: scans every text file of an extension for
patterns that are dangerous regardless of interpretation:

* **Hardcoded secrets** - AWS access keys (``AKIA...``), GitHub tokens
  (``ghp_``/``gho_``/...), Slack tokens (``xox...``), and generic
  high-entropy base64 blobs (>= 32 chars) near key/token/secret words.
* **Dangerous patterns** - ``curl``/``wget`` piped into a shell or
  targeting raw IP addresses; access to ``~/.ssh``, ``~/.aws``,
  ``~/.netrc``, ``/etc/passwd``; env-var harvesting loops;
  base64-decode-then-eval/exec; fetching remote install scripts.
* **Packaging traps** - npm ``postinstall``/``preinstall`` hooks that run
  commands, ``setup.py`` shelling out via subprocess/os.system, and
  dependency typosquat hints (edit distance 1 from a hardcoded top-50
  package list).
* **Injection phrases** - best-effort regex list ("ignore previous
  instructions", "always call X first", ...) as a cheap deterministic
  pre-filter; the real judgement is Stage 2's job. In markdown files this
  maps to LLM01+MCP06, in source/tool descriptions to LLM01+MCP03+MCP06.

Secrets and dangerous/packaging patterns carry
``confidence="deterministic"``; the typosquat rule is ``advisory`` (it
hints, it does not prove).  Secret values are redacted in evidence (first
4 + last 2 chars kept).  Each rule groups its hits into a single finding
per file, so a 40-line curl loop stays one finding.

OWASP mapping:
  secrets                -> MCP01 + LLM02
  curl|wget to shell     -> MCP05 + LLM01
  curl|wget to raw IP    -> MCP05 + LLM01
  credential-file access -> MCP01 + LLM02
  env harvesting         -> MCP01 + LLM02
  base64 -> eval/exec    -> MCP05 + LLM01
  install-script fetch   -> MCP04 + LLM03
  npm install hooks      -> MCP04 + LLM03
  setup.py subprocess    -> MCP04 + LLM03
  typosquat dep          -> MCP04 + LLM03 (advisory)
  injection phrase (md)  -> LLM01 + MCP06
  injection phrase (src) -> LLM01 + MCP03 + MCP06
"""
from __future__ import annotations

import ast
import json
import math
import asyncio
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from fugu.pipeline.stages.concealment import collect_text_files
from fugu.pipeline.stages.static_context import file_role, source_context
from fugu.types import AuditJob, EvidenceSnippet, Finding, StageResult

# --- secret patterns -------------------------------------------------------------
_AWS_KEY_RE = re.compile(r"\b(A(?:KIA|SIA|BIA|CCA)[0-9A-Z]{16})\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b")
_SLACK_TOKEN_RE = re.compile(r"\b(xox[abprsso]-[0-9A-Za-z-]{10,250})\b")
_B64_BLOB_RE = re.compile(r"\b([A-Za-z0-9+/]{32,}={0,2})\b")
_SECRET_CONTEXT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:key|token|secret|password|passwd|pwd|credential"
    r"|apikey|auth)(?![A-Za-z0-9])"
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    ent = 0.0
    for c in counts.values():
        p = c / len(s)
        ent -= p * math.log2(p)
    return ent


def _redact(secret: str, keep: int = 4, keep_tail: int = 2) -> str:
    if len(secret) <= keep + keep_tail + 1:
        return secret[:1] + "*" * max(len(secret) - 1, 1)
    return secret[:keep] + "*" * (len(secret) - keep - keep_tail) + secret[-keep_tail:]


# --- dangerous patterns ------------------------------------------------------------
_PIPE_SHELL_RE = re.compile(
    r"\b(curl|wget)\b[^\n|;]*\|[^\n|;]*\b(?:sudo\s+)?(sh|bash|zsh|dash|ksh)\b",
    re.IGNORECASE,
)
_RAW_IP_RE = re.compile(
    r"\b(curl|wget)\b[^\n]*https?://\s*(?!0\.0\.0\.0|127\.|localhost)"
    r"(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:(?:~|\$HOME|\$\{HOME\}|/home/|/Users/)[^\"'`\n]{0,60}"
    r"|os\.path\.expanduser\([^)\n]{0,60}"
    r"|Path\.home\(\)[^\n]{0,60})"
    r"(\.ssh|\.aws|\.netrc)"
    r"|/etc/(?:passwd|shadow)"
    r"|\b(?:id_rsa|authorized_keys)\b"
)
_ENV_HARVEST_RE = re.compile(
    r"\bfor\s+\w+(?:\s*,\s*\w+)*\s+in\s+(?:os\.environ(?:\.items\(\))?|process\.env|\$\(env\)|env(?![\w-]))"
    r"|\bos\.environ\.items\(\)"
    r"|\b(?:printenv|env)\s*\|[^|!\n]{0,80}\b(?:curl|wget|nc|base64|xxd|logger)\b"
    r"|JSON\.stringify\(process\.env\)"
    r"|Object\.(?:entries|keys|values)\(process\.env\)"
)
# Safe pattern: building a FILTERED env for a subprocess (the recommended
# way to pass environments without leaking) - not harvesting.
_ENV_FILTER_SAFE_RE = re.compile(
    r"os\.environ\.items\(\)\s*if\s+\w+\s*!=|os\.environ\.items\(\)[^.\n]{0,60}\bif\b[^.\n]{0,40}not\s+in"
)
_B64_DECODE_EXEC_RE = re.compile(
    r"(?i)(?:base64\s+(?:-d|--decode)|atob\(|frombase64|b64decode|base64\.decode)"
    r"[^!\n]{0,120}\b(eval|exec)\b"
    r"|\b(eval|exec)\b[^!\n]{0,120}"
    r"(?:base64\s+(?:-d|--decode)|atob\(|frombase64|b64decode|base64\.decode)"
)
_INSTALL_SCRIPT_RE = re.compile(
    r"(?i)\b(curl|wget)\b[^\n]{0,160}?(?:install\.sh|setup\.sh|bootstrap(?:\.sh)?|\.sh\b)"
    r"[^\n]{0,40}\|\s*(?:sudo\s+)?(sh|bash)\b"
    r"|\b(curl|wget)\b[^\n]{0,120}(?:install\.sh|bootstrap\.sh)"
)

# --- packaging traps ----------------------------------------------------------------
_NPM_SCRIPT_HOOK_RE = re.compile(r"(?i)[\"']?(postinstall|preinstall)[\"']?\s*:\s*[\"'`]([^\n]{0,200})")
_SETUP_PY_SUBPROCESS_RE = re.compile(
    r"(?i)subprocess\.(?:run|call|check_output|check_call|Popen)\s*\([^)\n]{0,200}(?:install|curl|wget|http)"
    r"|os\.system\s*\("
)
_NPM_DEPS_BLOCK_RE = re.compile(
    r"(?s)[\"']?(?:devDependencies|dependencies|optionalDependencies)[\"']?\s*:\s*\{(.*?)\}"
)
_NPM_DEPS_LINE_RE = re.compile(r"[\"']([^\"'\n]+)[\"']\s*:")
_PYPI_DEP_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[=><~!\[]|$)")

# Top-50-ish PyPI packages (approximate, hardcoded - offline rule input).
TOP_50_PYPI = {
    "requests", "numpy", "pandas", "matplotlib", "scipy", "beautifulsoup4",
    "django", "flask", "fastapi", "httpx", "aiohttp", "urllib3", "certifi",
    "idna", "charset-normalizer", "python-dateutil", "pyyaml", "six", "tenacity",
    "click", "sqlalchemy", "pydantic", "openai", "anthropic", "langchain",
    "tiktoken", "rich", "tqdm", "colorama", "packaging", "wheel", "setuptools",
    "pip", "virtualenv", "pytest", "black", "isort", "mypy", "ruff", "uvicorn",
    "gunicorn", "celery", "redis", "pymongo", "psycopg2-binary", "boto3",
    "google-api-python-client", "azure-storage-blob", "pytz", "attrs",
}
TOP_50_NPM = {
    "express", "lodash", "axios", "chalk", "commander", "dotenv", "ws",
    "react", "vue", "typescript", "zod", "undici", "node-fetch", "got",
    "fs-extra", "glob", "minimatch", "micromatch", "cross-spawn", "execa",
    "ora", "inquirer", "yargs", "debug", "ms", "uuid", "nanoid", "dayjs",
    "moment", "jquery", "left-pad", "mkdirp", "rimraf", "semver", "tar",
    "extract-zip", "yauzl", "adm-zip", "jszip", "deepmerge", "fast-deep-equal",
    "json5", "strip-ansi", "ansi-styles", "isexe", "which", "signal-exit",
    "p-limit", "p-map", "bluebird", "preact",
}

# --- injection phrases (best-effort deterministic pre-filter) -----------------------
_INJECTION_PHRASES = [
    r"(?i)ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|initial|preceding)\s+"
    r"(?:instructions?|directions?|prompts?|rules?|context)",
    r"(?i)disregard\s+(?:all\s+|any\s+|your\s+)?(?:previous|prior|above|earlier|preceding\s+)?"
    r"(?:instructions?|directions?|rules?)",
    r"(?i)forget\s+(?:all\s+|any\s+|your\s+)?(?:previous|prior|above|earlier\s+)?"
    r"(?:instructions?|directions?|rules?)",
    r"(?i)do\s+not\s+(?:follow|obey|adhere\s+to)\s+(?:your|the|any|these)?\s*"
    r"(?:system\s+|original\s+|previous\s+|prior\s+|initial\s+)?(?:prompt|instructions?|rules?)",
    r"(?i)you\s+are\s+now\s+(?:a|an|the)\s",
    r"(?i)(?:new|updated)\s+(?:system|developer)\s+(?:prompt|instructions?)\s*:",
    r"(?i)reveal\s+(?:your|the)\s+(?:system\s+)?prompt",
    r"(?i)always\s+(?:call|invoke|run|use)\s+[`\"']?\w+[`\"']?\s+(?:first|before)",
    r"(?i)before\s+(?:answering|responding|replying|any\s+response)[^.\n]{0,100}?"
    r"(?:must\s+)?(?:call|invoke|run|use|send|include|read)",
]
# Doc-prose arms too weak for documentation (normal prose and operator
# guidance match them); source files keep the full set. Paraphrased
# injections in docs are S2's (semantic) job - static doc mode is
# high-precision only.
_INJECTION_DOC_PHRASES = [
    p for p in _INJECTION_PHRASES
    if not p.startswith(r"(?i)always\s+(?:call|invoke|run|use)")
    and not p.startswith(r"(?i)before\s+(?:answering|responding|replying|any\s+response)")
]
_INJECTION_DOC_RES = [re.compile(p) for p in _INJECTION_DOC_PHRASES]
_INJECTION_RES = [re.compile(p) for p in _INJECTION_PHRASES]

_MARKDOWN_SUFFIXES = (".md", ".markdown", ".txt")
_SRC_SUFFIXES = (".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".sh", ".json")


def _edit_distance_at_most_1(a: str, b: str) -> bool:
    """True when Damerau-Levenshtein(a, b) <= 1 (case-insensitive).

    Distance 1 covers substitution, insertion, deletion AND a single
    adjacent transposition ("requests" -> "reqeusts"), which is the most
    common real-world typosquat shape.
    """
    a, b = a.lower(), b.lower()
    if abs(len(a) - len(b)) > 1:
        return False
    if a == b:
        return True
    if len(a) == len(b):
        diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diffs) == 1:
            return True
        # single adjacent transposition
        return (
            len(diffs) == 2
            and diffs[1] == diffs[0] + 1
            and a[diffs[0]] == b[diffs[1]]
            and a[diffs[1]] == b[diffs[0]]
        )
    if len(a) > len(b):
        a, b = b, a
    # a is the shorter by one: single-pass delete check
    i = j = mismatches = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
        else:
            mismatches += 1
            if mismatches > 1:
                return False
        j += 1
    return True


# --- rule engine ---------------------------------------------------------------------

@dataclass
class RuleHit:
    rule_id: str
    lineno: int
    line: str
    match: str                      # raw matched substring (redacted for secrets)
    extra: dict = field(default_factory=dict)


@dataclass
class Rule:
    rule_id: str
    title: str
    detail: str
    severity: str
    owasp_ids: list[str]
    confidence: str = "deterministic"
    redact: bool = False
    apply: object = None            # callable[[str, str], list[RuleHit]]

    def finding_for(self, rel: str, hits: list[RuleHit], max_evidence: int) -> Finding:
        lines = sorted({h.lineno for h in hits})
        detail = self.detail
        if len(lines) > 1:
            detail += f" Observed on lines {lines[:12]}."
        evidence: list[EvidenceSnippet] = []
        for h in hits[:max_evidence]:
            line = h.line.strip()
            if self.redact and h.match and h.match in line:
                i = line.index(h.match)
                line = line[:i] + _redact(h.match) + line[i + len(h.match):]
            evidence.append(
                EvidenceSnippet(
                    source=f"file:{rel}:L{h.lineno}",
                    excerpt=f"L{h.lineno} {line}"[:400],
                    meta={"rule": self.rule_id, "line": h.lineno, **h.extra},
                )
            )
        return Finding(
            owasp_ids=list(self.owasp_ids),
            title=f"{self.title} in {rel}",
            detail=detail,
            severity=self.severity,          # type: ignore[arg-type]
            confidence=self.confidence,      # type: ignore[arg-type]
            stage="static",
            evidence=evidence,
        )


def _lines(text: str):
    return enumerate(text.splitlines(), start=1)


def _regex_hits(regex: re.Pattern, rule_id: str, text: str, group: int = 0) -> list[RuleHit]:
    return [
        RuleHit(rule_id=rule_id, lineno=n, line=line, match=m.group(group) or "", extra={"match_column": m.start(group)})
        for n, line in _lines(text)
        for m in regex.finditer(line)
    ]


# --- individual rule applicators ------------------------------------------------------

def _aws_hits(text: str, rel: str) -> list[RuleHit]:
    return _regex_hits(_AWS_KEY_RE, "secret_aws_key", text, group=1)


def _github_hits(text: str, rel: str) -> list[RuleHit]:
    return _regex_hits(_GITHUB_TOKEN_RE, "secret_github_token", text, group=1)


def _slack_hits(text: str, rel: str) -> list[RuleHit]:
    return _regex_hits(_SLACK_TOKEN_RE, "secret_slack_token", text, group=1)


def _b64_secret_hits(text: str, rel: str) -> list[RuleHit]:
    # Documentation legitimately contains code examples (auth snippets,
    # config tables); the secret heuristic is for real source files only.
    if rel.endswith(_MARKDOWN_SUFFIXES):
        return []
    hits: list[RuleHit] = []
    for n, line in _lines(text):
        for m in _B64_BLOB_RE.finditer(line):
            blob = m.group(1)
            if len(blob) > 200:       # very long runs are data, not keys
                continue
            # Exact lockfile integrity fields are data, not authentication.
            if file_role(rel) == "dependency_lock" and re.search(
                r'(?:hash|integrity)\s*[=:]\s*[\"\'](?:sha256:|sha512-)?$', line[:m.start()]
            ):
                continue
            ctx = line[max(0, m.start() - 60): m.end() + 60]
            if not _SECRET_CONTEXT_RE.search(ctx):
                continue
            ent = _shannon_entropy(blob)
            if ent < 3.5:
                continue
            hits.append(
                RuleHit(
                    rule_id="secret_high_entropy_b64",
                    lineno=n,
                    line=line,
                    match=blob,
                    extra={"entropy": round(ent, 2), "length": len(blob)},
                )
            )
    return hits


def _pipe_shell_hits(text: str, rel: str) -> list[RuleHit]:
    # curl examples in docs are documentation, not install-time execution
    if rel.endswith(_MARKDOWN_SUFFIXES):
        return []
    out = []
    for h in _regex_hits(_PIPE_SHELL_RE, "curl_pipe_shell", text):
        low = h.line.lower()
        if "localhost" in low or "127.0.0.1" in low or "0.0.0.0" in low:
            continue  # documented FP guard: loopback plumbing
        out.append(h)
    return out


def _raw_ip_hits(text: str, rel: str) -> list[RuleHit]:
    return [
        h for h in _regex_hits(_RAW_IP_RE, "curl_raw_ip", text, group=2)
        if not h.line.strip().startswith("#")
    ]


def _sensitive_path_hits(text: str, rel: str) -> list[RuleHit]:
    # Path MENTIONS in prose/docs (e.g. a security checklist telling you to
    # test against ../../etc/passwd) are not access. Deterministic path
    # rules are for code/config; prose judgement is S2's job.
    if rel.endswith(_MARKDOWN_SUFFIXES):
        return []
    return _regex_hits(_SENSITIVE_PATH_RE, "sensitive_path_access", text, group=0)


def _env_harvest_hits(text: str, rel: str) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for n, line in _lines(text):
        for m in _ENV_HARVEST_RE.finditer(line):
            ctx = line[max(0, m.start() - 80): m.end() + 80]
            if _ENV_FILTER_SAFE_RE.search(ctx):
                continue  # filtered subprocess env build, the safe idiom
            hits.append(RuleHit(rule_id="env_harvest", lineno=n, line=line, match=m.group(0)))
    return hits


def _b64_exec_hits(text: str, rel: str) -> list[RuleHit]:
    return _regex_hits(_B64_DECODE_EXEC_RE, "base64_decode_exec", text, group=0)


def _install_script_hits(text: str, rel: str) -> list[RuleHit]:
    return _regex_hits(_INSTALL_SCRIPT_RE, "install_script_fetch", text, group=0)


def _npm_hook_hits(text: str, rel: str) -> list[RuleHit]:
    if not rel.endswith("package.json"):
        return []
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return _regex_hits(_NPM_SCRIPT_HOOK_RE, "npm_install_hook", text)
    scripts = document.get("scripts", {}) if isinstance(document, dict) else {}
    if not isinstance(scripts, dict):
        return []
    hits: list[RuleHit] = []
    for hook in ("preinstall", "postinstall"):
        cmd = scripts.get(hook)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        cmd = cmd.strip()
        first = cmd.split()[0]
        simple_inert = first in ("echo", "exit") and not re.search(r"[\r\n;&|<>`$()]", cmd)
        if simple_inert or cmd in ("node --version", "npm --version", "node -v", "npm -v"):
            continue
        offset = re.search(r'"' + hook + r'"\s*:', text)
        line = text.count("\n", 0, offset.start()) + 1 if offset else 1
        hits.append(RuleHit("npm_install_hook", line, f'{hook}: {cmd}', cmd,
                            extra={"hook": hook, "command": cmd}))
    return hits


def _setup_py_hits(text: str, rel: str) -> list[RuleHit]:
    if not rel.endswith("setup.py"):
        return []
    return _regex_hits(_SETUP_PY_SUBPROCESS_RE, "setup_py_subprocess", text, group=0)


def _typosquat_hits(text: str, rel: str) -> list[RuleHit]:
    """Edit-distance-1 dependency names vs the hardcoded top-50 lists."""
    is_npm = rel.endswith("package.json")
    is_pypi = rel.startswith("requirements") and rel.endswith(".txt") or rel.endswith("pyproject.toml")
    if not is_npm and not is_pypi:
        return []
    dep_names: list[tuple[str, int]] = []
    if is_npm:
        for block in _NPM_DEPS_BLOCK_RE.finditer(text):
            for lm in _NPM_DEPS_LINE_RE.finditer(block.group(1)):
                dep_names.append((lm.group(1), 0))
    else:
        for n, line in _lines(text):
            if line.strip().startswith(("#", "http")):
                continue
            lm = _PYPI_DEP_LINE_RE.match(line)
            if lm:
                dep_names.append((lm.group(1), n))
    top = TOP_50_NPM if is_npm else TOP_50_PYPI
    hits: list[RuleHit] = []
    for name, lineno in dep_names:
        bare = name.split("/")[-1]          # @scope/pkg -> pkg
        if not bare or bare.lower() in top:
            continue
        for t in sorted(top):
            if bare.lower() == t:
                break
            if _edit_distance_at_most_1(bare, t):
                hits.append(
                    RuleHit(
                        rule_id="typosquat_hint",
                        lineno=lineno or 1,
                        line=name,
                        match=name,
                        extra={"near": t, "distance": 1, "registry": "npm" if is_npm else "pypi"},
                    )
                )
                break
    return hits


def _injection_hits_factory(rule_id: str, suffixes: tuple[str, ...]):
    doc_mode = suffixes == _MARKDOWN_SUFFIXES  # docs get the stricter arm set

    def apply(text: str, rel: str) -> list[RuleHit]:
        if not rel.lower().endswith(suffixes):
            return []
        regexes = _INJECTION_DOC_RES if doc_mode else _INJECTION_RES
        hits: list[RuleHit] = []
        if rel.lower().endswith(".json"):
            try:
                document = json.loads(text)
            except (ValueError, RecursionError):
                return []
            descriptions: list[str] = []
            def walk(value: object) -> None:
                if isinstance(value, dict):
                    if isinstance(value.get("name"), str) and "inputSchema" in value and isinstance(value.get("description"), str):
                        descriptions.append(value["description"])
                    for item in value.values():
                        walk(item)
                elif isinstance(value, list):
                    for item in value:
                        walk(item)
            walk(document)
            for description in descriptions:
                for rx in regexes:
                    match = rx.search(description)
                    if match:
                        # Locate the encoded original string, not fabricated line 1.
                        encoded = json.dumps(description, ensure_ascii=False)
                        offset = text.find(encoded)
                        if offset < 0:
                            offset = text.find(json.dumps(description, ensure_ascii=True))
                        line = text.count("\n", 0, offset) + 1 if offset >= 0 else 1
                        hits.append(RuleHit(rule_id, line, description, match.group(0),
                                            extra={"phrase": match.group(0)[:120], "source_context": "tool_description"}))
                        break
            return hits
        for n, line in _lines(text):
            for rx in regexes:
                m = rx.search(line)
                if m:
                    hits.append(
                        RuleHit(rule_id=rule_id, lineno=n, line=line, match=m.group(0),
                                extra={"phrase": m.group(0)[:120]})
                    )
                    break
        return hits
    return apply


# --- MCP metadata quality (arXiv 2609.10962, 2602.18914) ---------------------------
_MCP_SRC_SUFFIXES = (".py", ".js", ".ts", ".json", ".jsonc")
_RETURN_HINT_RE = re.compile(
    r"(?i)\b(returns?|responses?|outputs?|results?|echo|list|lists|listing|"
    r"show|shows|give|gives|yield|yields|provides?|emit|emits|prints?)\b"
)
_TOOL_NAME_RE = re.compile(r'"name"\s*:\s*"([A-Za-z0-9_.-]+)"')


def _window_until_next_tool(lines: list[str], start: int, cap: int = 30) -> str:
    """Lines from start until the next tool boundary (a following 'name' key)."""
    out = [lines[start]]
    for line in lines[start + 1 : start + cap]:
        if '"name"' in line and '"inputSchema"' not in line:
            break
        out.append(line)
    return "\n".join(out)


def _mcp_annotation_hits(text: str, rel: str) -> list[RuleHit]:
    """Tools whose dict lacks an annotations block (or any safety hint).

    Registry census (arXiv 2609.10962): 58.8% of tools on a random registry
    draw omit optional safety annotations - clients cannot apply
    least-privilege or confirmation behavior they cannot see.
    """
    if not rel.endswith(_MCP_SRC_SUFFIXES) or '"inputSchema"' not in text:
        return []
    lines = text.splitlines()
    hits: list[RuleHit] = []
    for n, line in enumerate(lines):
        if '"inputSchema"' not in line:
            continue
        window = _window_until_next_tool(lines, n)
        if '"annotations"' not in window:
            hits.append(RuleHit("mcp_missing_annotations", n + 1, line, "",
                                extra={"issue": "no annotations block"}))
        elif not re.search(r'"(readOnlyHint|destructiveHint|idempotentHint|openWorldHint)"', window):
            hits.append(RuleHit("mcp_missing_annotations", n + 1, line, "",
                                extra={"issue": "annotations without safety hints"}))
    return hits


def _mcp_dup_name_hits(text: str, rel: str) -> list[RuleHit]:
    """Collisions only within one syntactic list of actual tool definitions."""
    if not rel.endswith(_MCP_SRC_SUFFIXES) or '"inputSchema"' not in text:
        return []
    inventories: list[list[tuple[str, int]]] = []
    try:
        if rel.endswith(".json"):
            document = json.loads(text)
            def walk(value: object) -> None:
                if isinstance(value, list):
                    tools = [(item["name"], 1) for item in value if isinstance(item, dict)
                             and isinstance(item.get("name"), str) and "inputSchema" in item]
                    if tools:
                        inventories.append(tools)
                    for item in value:
                        walk(item)
                elif isinstance(value, dict):
                    for item in value.values():
                        walk(item)
            walk(document)
        elif rel.endswith(".py"):
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.List, ast.Tuple)):
                    continue
                tools = []
                for item in node.elts:
                    if not isinstance(item, ast.Dict):
                        continue
                    fields = {key.value: val for key, val in zip(item.keys, item.values)
                              if isinstance(key, ast.Constant) and isinstance(key.value, str)}
                    name = fields.get("name")
                    if "inputSchema" in fields and isinstance(name, ast.Constant) and isinstance(name.value, str):
                        tools.append((name.value, name.lineno))
                if tools:
                    inventories.append(tools)
        else:
            # No JS/JSONC parser: a name-only regex cannot prove a collision.
            return []
    except (SyntaxError, ValueError, RecursionError):
        return []
    hits: list[RuleHit] = []
    lines = text.splitlines()
    for index, inventory in enumerate(inventories):
        seen: dict[str, int] = {}
        for name, line in inventory:
            if name in seen:
                hits.append(RuleHit("mcp_duplicate_tool_names", line, lines[line - 1], name,
                                    extra={"first_defined_line": seen[name], "inventory": index,
                                           "source_context": "tool_inventory"}))
            else:
                seen[name] = line
    return hits


def _mcp_no_return_hits(text: str, rel: str) -> list[RuleHit]:
    """Tool descriptions that never say what they return - the dominant
    'description smell' (arXiv 2602.18914: missing return descriptions
    measurably degrade agent tool selection)."""
    if not rel.endswith(_MCP_SRC_SUFFIXES) or '"inputSchema"' not in text:
        return []
    lines = text.splitlines()
    hits: list[RuleHit] = []
    for n, line in enumerate(lines):
        if '"description"' not in line:
            continue
        window = _window_until_next_tool(lines, n, cap = 10)
        if not _RETURN_HINT_RE.search(window):
            hits.append(RuleHit("mcp_missing_return_description", n + 1, line.strip()[:80], ""))
    # only flag descriptions that belong to tool dicts (file has inputSchema)
    return hits


STATIC_RULES: list[Rule] = [
    Rule("secret_aws_key", "Hardcoded AWS access key",
         "AWS access key id hardcoded in extension source. Credentials must never ship inside an extension.",
         "critical", ["MCP01", "LLM02"], redact=True, apply=_aws_hits),
    Rule("secret_github_token", "Hardcoded GitHub token",
         "GitHub token hardcoded in extension source.", "critical", ["MCP01", "LLM02"],
         redact=True, apply=_github_hits),
    Rule("secret_slack_token", "Hardcoded Slack token",
         "Slack token hardcoded in extension source.", "critical", ["MCP01", "LLM02"],
         redact=True, apply=_slack_hits),
    Rule("secret_high_entropy_b64", "High-entropy secret-like blob",
         "A >=32-char high-entropy base64 blob appears near secret-naming words; likely a hardcoded credential.",
         "high", ["MCP01", "LLM02"], redact=True, apply=_b64_secret_hits),
    Rule("curl_pipe_shell", "curl/wget piped into a shell",
         "Remote content is executed directly by a shell. Piping curl to sh is the canonical remote-code-execution install pattern.",
         "high", ["MCP05", "LLM01"], apply=_pipe_shell_hits),
    Rule("curl_raw_ip", "curl/wget to a raw IP address",
         "Fetching from a raw IP skips DNS names and certificate validation - typical of hardcoded C2 or exfil endpoints.",
         "high", ["MCP05", "LLM01"], apply=_raw_ip_hits),
    Rule("sensitive_path_access", "Access to credential files",
         "The extension references SSH keys, cloud credentials, netrc or system password files.",
         "high", ["MCP01", "LLM02"], apply=_sensitive_path_hits),
    Rule("env_harvest", "Environment-variable harvesting",
         "Bulk collection of environment variables (iteration or piping env to a command) - the first step of credential exfiltration.",
         "high", ["MCP01", "LLM02"], apply=_env_harvest_hits),
    Rule("base64_decode_exec", "base64-decode then eval/exec",
         "Decoded base64 is passed to eval/exec - classic payload obfuscation.",
         "critical", ["MCP05", "LLM01"], apply=_b64_exec_hits),
    Rule("install_script_fetch", "Remote install script fetched and executed",
         "curl/wget fetches an install/bootstrap shell script - arbitrary code runs at install time.",
         "high", ["MCP04", "LLM03"], apply=_install_script_hits),
    Rule("npm_install_hook", "npm install-time hook runs commands",
         "package.json runs a command in postinstall/preinstall - arbitrary code executes on npm install without the user noticing.",
         "high", ["MCP04", "LLM03"], apply=_npm_hook_hits),
    Rule("setup_py_subprocess", "setup.py shells out during install",
         "setup.py invokes subprocess/os.system - arbitrary code runs at pip install time.",
         "high", ["MCP04", "LLM03"], apply=_setup_py_hits),
    Rule("typosquat_hint", "Dependency name near-miss (typosquat hint)",
         "A dependency is edit-distance 1 from a popular package name - possible typosquat. Verify spelling and provenance.",
         "medium", ["MCP04", "LLM03"], confidence="advisory", apply=_typosquat_hits),
    Rule("skill_injection_phrase", "Instruction-hijack phrase in documentation",
         "Documentation text contains classic instruction-hijack phrasing. The phrase is present for sure; hostile intent needs semantic review.",
         "high", ["LLM01", "MCP06"], apply=_injection_hits_factory("skill_injection_phrase", _MARKDOWN_SUFFIXES)),
    Rule("tool_description_injection", "Injection phrasing in code/tool descriptions",
         "Source or tool-description strings contain classic instruction-hijack phrasing - the tool-poisoning pattern.",
         "high", ["LLM01", "MCP03", "MCP06"], apply=_injection_hits_factory("tool_description_injection", _SRC_SUFFIXES)),
    Rule("mcp_missing_annotations", "MCP tool missing safety annotations",
         "A tool definition has no annotations block (or none with safety hints). Registry census: 58.8% of tools omit these (arXiv 2609.10962) - clients cannot apply least-privilege or confirmation behavior they cannot see.",
         "info", ["MCP08", "MCP02"], apply=_mcp_annotation_hits),
    Rule("mcp_duplicate_tool_names", "Duplicate MCP tool names in one server",
         "The same tool name is defined twice (73% of servers ship duplicates - arXiv 2602.18914). Name collisions enable tool shadowing and ambiguity for the calling agent.",
         "low", ["MCP03"], apply=_mcp_dup_name_hits),
    Rule("mcp_missing_return_description", "Tool description omits return semantics",
         "Tool descriptions that never state what the tool returns - the dominant 'description smell' (arXiv 2602.18914); measurably degrades agent tool selection.",
         "info", ["MCP08"], apply=_mcp_no_return_hits),
]


# --- the stage -------------------------------------------------------------------------

class StaticScanStage:
    """S1 - deterministic regex/rule scanner (secrets, patterns, packaging)."""

    name = "static"

    def __init__(
        self,
        *,
        max_file_bytes: int = 2_000_000,
        max_files: int = 2_000,
        max_evidence_per_finding: int = 5,
        rules: list[Rule] | None = None,
        surface_scanner=None,
    ) -> None:
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.max_evidence_per_finding = max_evidence_per_finding
        self.rules = rules if rules is not None else STATIC_RULES
        from fugu.pipeline.stages.tool_surface import ToolSurfaceScanner
        self.surface_scanner = (ToolSurfaceScanner.from_environment() if surface_scanner is None
                                else None if surface_scanner is False else surface_scanner)

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        t0 = time.perf_counter()
        try:
            files, stats = collect_text_files(target, self.max_file_bytes, self.max_files)
        except Exception as exc:
            return StageResult(stage=self.name, ok=False, error=f"{type(exc).__name__}: {exc}")
        findings: list[Finding] = []
        hits_total = 0
        context_counts: dict[str, int] = {}
        for tf in files:
            context = source_context(tf.text, tf.rel)
            role = file_role(tf.rel)
            for rule in self.rules:
                try:
                    hits = rule.apply(tf.text, tf.rel) if rule.apply else []
                except Exception as exc:  # a broken rule must not kill the stage
                    hits = []
                    stats.setdefault("rule_errors", {})[f"{rule.rule_id}:{tf.rel}"] = str(exc)
                if not hits:
                    continue
                hits_total += len(hits)
                references: list[RuleHit] = []
                actionable: list[RuleHit] = []
                for hit in hits:
                    column = hit.extra.get("match_column", hit.line.find(hit.match))
                    kind = next((kind for start, end, kind in context.get(hit.lineno, [])
                                 if start <= column < end), "unresolved")
                    hit.extra.setdefault("source_context", kind)
                    hit.extra["file_role"] = role
                    context_counts[kind] = context_counts.get(kind, 0) + 1
                    reference_only = (
                        (rule.rule_id == "sensitive_path_access" and kind in ("comment_reference", "denylist_reference"))
                        or (rule.rule_id == "tool_description_injection" and kind == "detector_vocabulary")
                        or (rule.rule_id == "env_harvest" and kind == "single_key_env_lookup")
                    )
                    if reference_only:
                        references.append(hit)
                    else:
                        actionable.append(hit)
                if actionable:
                    findings.append(rule.finding_for(tf.rel, actionable, self.max_evidence_per_finding))
                if references:
                    finding = rule.finding_for(tf.rel, references, self.max_evidence_per_finding)
                    finding.title = f"Source reference ({rule.title}) in {tf.rel}"
                    finding.detail = "The matched source is a comment, rejection-list reference, boolean detector vocabulary, or single-key environment lookup. The syntax does not establish the behavior named by this rule. Dynamic access and cross-file data flow are not resolved; review context before assigning malicious intent."
                    finding.severity = "info"
                    finding.confidence = "advisory"
                    finding.owasp_ids = []
                    findings.append(finding)
        if self.surface_scanner is not None:
            added, surface_metrics = await asyncio.to_thread(
                self.surface_scanner.scan, target, self.max_file_bytes, self.max_files,
            )
            findings.extend(added)
            stats['tool_surface'] = surface_metrics
            if surface_metrics.get('coverage_incomplete'):
                stats['coverage_incomplete'] = 'tool/instruction surface analysis incomplete'
        else:
            stats['tool_surface'] = {'enabled': False}
        stats.update(
            {
                "rules": len(self.rules),
                "match_contexts": context_counts,
                "hits": hits_total,
                "findings": len(findings),
                "duration_s": round(time.perf_counter() - t0, 4),
            }
        )
        return StageResult(stage=self.name, ok=not bool(stats.get('coverage_incomplete')),
                           findings=findings, metrics=stats)


__all__ = [
    "StaticScanStage",
    "Rule",
    "RuleHit",
    "STATIC_RULES",
    "TOP_50_PYPI",
    "TOP_50_NPM",
]
