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

import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from fugu.pipeline.stages.concealment import collect_text_files
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
    r"\bfor\s+\w+(?:\s*,\s*\w+)*\s+in\s+(?:os\.environ(?:\.items\(\))?|process\.env|\$\(env\)|env)"
    r"|\bos\.environ\.items\(\)"
    r"|\b(?:printenv|env)\s*\|[^|!\n]{0,80}\b(?:curl|wget|nc|base64|xxd|logger)\b"
    r"|JSON\.stringify\(process\.env\)"
    r"|Object\.(?:entries|keys|values)\(process\.env\)"
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
_INJECTION_RES = [re.compile(p) for p in _INJECTION_PHRASES]

_MARKDOWN_SUFFIXES = (".md", ".markdown", ".txt")
_SRC_SUFFIXES = (".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".sh")


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
        RuleHit(rule_id=rule_id, lineno=n, line=line, match=m.group(group) or "")
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
    hits: list[RuleHit] = []
    for n, line in _lines(text):
        for m in _B64_BLOB_RE.finditer(line):
            blob = m.group(1)
            if len(blob) > 200:       # very long runs are data, not keys
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
    return _regex_hits(_SENSITIVE_PATH_RE, "sensitive_path_access", text, group=0)


def _env_harvest_hits(text: str, rel: str) -> list[RuleHit]:
    return _regex_hits(_ENV_HARVEST_RE, "env_harvest", text, group=0)


def _b64_exec_hits(text: str, rel: str) -> list[RuleHit]:
    return _regex_hits(_B64_DECODE_EXEC_RE, "base64_decode_exec", text, group=0)


def _install_script_hits(text: str, rel: str) -> list[RuleHit]:
    return _regex_hits(_INSTALL_SCRIPT_RE, "install_script_fetch", text, group=0)


def _npm_hook_hits(text: str, rel: str) -> list[RuleHit]:
    if not rel.endswith("package.json"):
        return []
    hits: list[RuleHit] = []
    for n, line in _lines(text):
        for m in _NPM_SCRIPT_HOOK_RE.finditer(line):
            cmd = m.group(2).strip().strip("'\"`")
            first = cmd.split()[0] if cmd else ""
            trivial = (
                first in ("echo", "exit")
                or cmd in ("node --version", "npm --version", "node -v", "npm -v")
            )
            if not cmd or trivial:
                continue
            hits.append(
                RuleHit(
                    rule_id="npm_install_hook",
                    lineno=n,
                    line=line,
                    match=m.group(0),
                    extra={"hook": m.group(1).lower(), "command": cmd},
                )
            )
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
        if not bare:
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
    def apply(text: str, rel: str) -> list[RuleHit]:
        if not rel.lower().endswith(suffixes):
            return []
        hits: list[RuleHit] = []
        for n, line in _lines(text):
            for rx in _INJECTION_RES:
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
    """Duplicate tool names in one file (73% of servers ship dups -
    arXiv 2602.18914); name collisions enable tool shadowing (MCP09)."""
    if not rel.endswith(_MCP_SRC_SUFFIXES):
        return []
    seen: dict[str, int] = {}
    hits: list[RuleHit] = []
    for n, line in _lines(text):
        for m in _TOOL_NAME_RE.finditer(line):
            name = m.group(1)
            if name in seen:
                hits.append(RuleHit("mcp_duplicate_tool_names", n, line, name,
                                    extra={"first_defined_line": seen[name]}))
            else:
                seen[name] = n
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
         "low", ["MCP09"], apply=_mcp_dup_name_hits),
    Rule("mcp_missing_return_description", "Tool description omits return semantics",
         "Tool descriptions that never state what the tool returns - the dominant 'description smell' (arXiv 2602.18914); measurably degrades agent tool selection.",
         "info", ["MCP10"], apply=_mcp_no_return_hits),
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
    ) -> None:
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.max_evidence_per_finding = max_evidence_per_finding
        self.rules = rules if rules is not None else STATIC_RULES

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        t0 = time.perf_counter()
        try:
            files, stats = collect_text_files(target, self.max_file_bytes, self.max_files)
        except Exception as exc:
            return StageResult(stage=self.name, ok=False, error=f"{type(exc).__name__}: {exc}")
        findings: list[Finding] = []
        hits_total = 0
        for tf in files:
            for rule in self.rules:
                try:
                    hits = rule.apply(tf.text, tf.rel) if rule.apply else []
                except Exception as exc:  # a broken rule must not kill the stage
                    hits = []
                    stats.setdefault("rule_errors", {})[f"{rule.rule_id}:{tf.rel}"] = str(exc)
                if not hits:
                    continue
                hits_total += len(hits)
                findings.append(rule.finding_for(tf.rel, hits, self.max_evidence_per_finding))
        stats.update(
            {
                "rules": len(self.rules),
                "hits": hits_total,
                "findings": len(findings),
                "duration_s": round(time.perf_counter() - t0, 4),
            }
        )
        return StageResult(stage=self.name, ok=True, findings=findings, metrics=stats)


__all__ = [
    "StaticScanStage",
    "Rule",
    "RuleHit",
    "STATIC_RULES",
    "TOP_50_PYPI",
    "TOP_50_NPM",
]
