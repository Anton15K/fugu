"""Stage 0 (S0) - deterministic Unicode-concealment scanner.

Detects (and *decodes*) text hidden with Unicode steganography in agent
extensions (SKILL.md prose, tool descriptions, source code):

* Unicode Tags block      U+E0000..U+E007F  -> ASCII payload (cp - 0xE0000)
* Zero-width characters   U+200B, U+200C, U+200D, U+2060, U+FEFF
  (binary scheme: U+200B = 0, U+200C = 1, 8 bits per ASCII byte)
* Bidi controls           U+202A..U+202E, U+2066..U+2069 ("Trojan Source")
  plus directional marks  U+200E, U+200F, U+061C
* Variation selectors     U+FE00..U+FE0F, U+E0100..U+E01EF (byte smuggling:
  direct bytes in the VS-256 range, or high/low nibble pairs)
* Mixed-script homoglyphs (opt-in via ``detect_homoglyphs=True``)

Everything here is pure codepoint math, so every finding carries
``confidence="deterministic"``.  A single leading U+FEFF is treated as a
byte-order mark, not concealment.  Emoji-related codepoints are guarded
against false positives: U+200D (ZWJ) alone only counts in bulk (>= 4 per
line), lone VS-16 (U+FE0F) emoji modifiers never fire; a run of >= 8
FE00..FE0F or *any* VS-256 codepoint does.

OWASP mapping (subset of ``fugu.types.OWASP_IDS``):
  tags / zero-width / variation-selector payloads -> LLM01 + MCP03
  bidi controls & marks                          -> LLM01 + MCP03
  homoglyph script mixing                        -> LLM01

Later stages reuse ``strip_hidden()`` and the ``decode_*`` helpers to feed
the semantic judge raw + normalized + decoded views of the same text.

NOTE ON STYLE: concealment codepoints are built with ``chr(0x....)`` rather
than unicode-escape literals so the source itself stays smuggle-free and
diff-able (escaped literals render invisibly in some editors and can be
silently corrupted by copy/paste).
"""
from __future__ import annotations

import os
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from fugu.types import AuditJob, EvidenceSnippet, Finding, StageResult, OWASP_IDS

# --- codepoint constants (built via chr() on purpose) ---------------------------
ZWSP = chr(0x200B)    # zero width space          -> binary 0
ZWNJ = chr(0x200C)    # zero width non-joiner     -> binary 1
ZWJ = chr(0x200D)     # zero width joiner         (emoji ligatures)
WJ = chr(0x2060)      # word joiner
ZWNBSP = chr(0xFEFF)  # zero width no-break space ("BOM")
LRM = chr(0x200E)
RLM = chr(0x200F)
ALM = chr(0x061C)

TAGS_FIRST, TAGS_LAST = 0xE0000, 0xE007F
VS_LOW_FIRST, VS_LOW_LAST = 0xFE00, 0xFE0F
VS_HIGH_FIRST, VS_HIGH_LAST = 0xE0100, 0xE01EF

ZERO_WIDTH_CPS = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)
BIDI_CONTROL_CPS = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))
BIDI_MARK_CPS = frozenset((0x200E, 0x200F, 0x061C))
VS_LOW_RANGE = range(VS_LOW_FIRST, VS_LOW_LAST + 1)
VS_HIGH_RANGE = range(VS_HIGH_FIRST, VS_HIGH_LAST + 1)


def _cls(first: int, last: int) -> str:
    """Character-class body for an inclusive codepoint range."""
    return re.escape(chr(first)) + "-" + re.escape(chr(last))


TAGS_RE = re.compile("[" + _cls(TAGS_FIRST, TAGS_LAST) + "]+")
_ZW_BINARY_RE = re.compile("[" + re.escape(ZWSP) + re.escape(ZWNJ) + "]+")
VS_RE = re.compile(
    "[" + _cls(VS_LOW_FIRST, VS_LOW_LAST) + _cls(VS_HIGH_FIRST, VS_HIGH_LAST) + "]+"
)
_ALL_HIDDEN_CPS = (
    list(range(TAGS_FIRST, TAGS_LAST + 1))
    + list(ZERO_WIDTH_CPS)
    + sorted(BIDI_CONTROL_CPS)
    + sorted(BIDI_MARK_CPS)
    + list(VS_LOW_RANGE)
    + list(VS_HIGH_RANGE)
)
_HIDDEN_RE = re.compile("[" + "".join(re.escape(chr(cp)) for cp in _ALL_HIDDEN_CPS) + "]")

# Payloads that decode to something attack-flavoured escalate to critical.
_PAYLOAD_RISK_RE = re.compile(
    r"(?i)ignore|instruction|prompt|exfiltrat|credential|secret|token|password"
    r"|\.aws|\.ssh|netrc|api[_ ]?key|eval|exec|http"
)

_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".idea", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}
_SKIP_FILES = {".DS_Store"}

DEFAULT_MAX_FILE_BYTES = 2_000_000
DEFAULT_MAX_FILES = 2_000

# family -> (owasp_ids, default severity, title)
_FAMILY_META: dict[str, tuple[list[str], str, str]] = {
    "tags": (["LLM01", "MCP03"], "high", "Unicode Tags-block smuggling"),
    "zero_width_payload": (["LLM01", "MCP03"], "high", "Zero-width binary steganography"),
    "zero_width": (["LLM01"], "medium", "Zero-width characters"),
    "variation_selectors_payload": (["LLM01", "MCP03"], "high", "Variation-selector steganography"),
    "variation_selectors": (["LLM01"], "medium", "Variation-selector characters"),
    "bidi_control": (["LLM01", "MCP03"], "high", "Bidi control characters (Trojan Source)"),
    "bidi_marks": (["LLM01", "MCP03"], "medium", "Bidi directional marks"),
    "homoglyph": (["LLM01"], "low", "Mixed-script homoglyphs"),
}


# --- decoding helpers (pure, reusable) -------------------------------------------

def decode_tags_run(run: str) -> str:
    """Map U+E0020..U+E007E back to ASCII; U+E007F (CANCEL TAG) terminates."""
    chars: list[str] = []
    for ch in run:
        v = ord(ch) - TAGS_FIRST
        if v == 0x7F:  # CANCEL TAG terminator
            break
        if 0x20 <= v <= 0x7E:
            chars.append(chr(v))
        # v == 1 (LANGUAGE TAG) and friends carry no payload
    return "".join(chars)


def decode_tags_block(text: str) -> str:
    """Decode every Tags-block run in *text* into its hidden ASCII payload."""
    out: list[str] = []
    for m in TAGS_RE.finditer(text):
        payload = decode_tags_run(m.group())
        if payload:
            out.append(payload)
    return "".join(out)


def encode_tags_block(payload: str) -> str:
    """Inverse of :func:`decode_tags_run` (used by corpus/build.py + tests)."""
    return "".join(
        chr(TAGS_FIRST + ord(ch)) for ch in payload if 0x20 <= ord(ch) <= 0x7E
    )


def _decode_zw_run(run: str) -> str | None:
    if len(run) < 8:
        return None
    bits = "".join("0" if ch == ZWSP else "1" for ch in run)
    vals = [int(bits[i : i + 8], 2) for i in range(0, len(bits) - 7, 8)]
    printable = [v for v in vals if 0x20 <= v < 0x7F]
    if len(printable) < 2 or len(printable) < 0.6 * len(vals):
        return None
    return "".join(chr(v) for v in printable)


def decode_zero_width_binary(text: str) -> str:
    """Decode the ZWSP/ZWNJ bit-stream scheme (200B=0, 200C=1, 8 bits/byte)."""
    out: list[str] = []
    for m in _ZW_BINARY_RE.finditer(text):
        payload = _decode_zw_run(m.group())
        if payload:
            out.append(payload)
    return "".join(out)


def encode_zero_width_binary(payload: str) -> str:
    """Inverse of :func:`decode_zero_width_binary` (corpus builder helper)."""
    return "".join(
        (ZWSP if (ord(ch) >> i) & 1 == 0 else ZWNJ)
        for ch in payload
        for i in range(7, -1, -1)
    )


def _decode_vs_run(run: str) -> tuple[str | None, str | None]:
    types: list[str] = []
    vals: list[int] = []
    for ch in run:
        cp = ord(ch)
        if cp in VS_HIGH_RANGE:
            types.append("H")
            vals.append(cp - VS_HIGH_FIRST)
        elif cp in VS_LOW_RANGE:
            types.append("L")
            vals.append(cp - VS_LOW_FIRST)
        else:  # regex guarantees this cannot happen; be defensive anyway
            return None, None
    # Scheme A: a run made only of VS-256 codepoints, each one a full byte.
    if types and all(t == "H" for t in types):
        bs = [v for v in vals if v < 0x80]
        if len(bs) >= 2 and len(bs) >= 0.6 * len(vals):
            return "".join(chr(v) for v in bs), "vs_bytes"
    # Scheme B: alternating (VS-256 high nibble, VS-16 low nibble) pairs.
    if len(types) >= 2 and len(types) % 2 == 0:
        bs: list[int] = []
        ok = True
        for i in range(0, len(types), 2):
            a, b = vals[i], vals[i + 1]
            if types[i] == "H" and types[i + 1] == "L":
                bs.append((a << 4) | b)
            elif types[i] == "L" and types[i + 1] == "H":
                bs.append((b << 4) | a)
            else:
                ok = False
                break
        if ok:
            printable = [v for v in bs if 0x20 <= v < 0x7F]
            if len(printable) >= 2 and len(printable) >= 0.6 * len(bs):
                return "".join(chr(v) for v in printable), "vs_nibbles"
    return None, None


def encode_variation_selectors(payload: str) -> str:
    """Inverse of the VS-256 byte scheme (corpus builder / test helper)."""
    return "".join(
        chr(VS_HIGH_FIRST + ord(ch)) for ch in payload if ord(ch) < 0x100
    )


def decode_variation_selectors(text: str) -> str:
    """Decode variation-selector steganography (VS-256 bytes or nibble pairs)."""
    out: list[str] = []
    for m in VS_RE.finditer(text):
        payload, _scheme = _decode_vs_run(m.group())
        if payload:
            out.append(payload)
    return "".join(out)


def strip_hidden(text: str) -> str:
    """Remove every concealment codepoint (normalized view for later stages)."""
    return _HIDDEN_RE.sub("", text)


def hidden_codepoint_counts(text: str) -> dict[str, int]:
    """Count hidden codepoints by ``U+XXXX`` name (diagnostics / metrics)."""
    counts: dict[str, int] = {}
    for ch in text:
        if _HIDDEN_RE.match(ch):
            key = f"U+{ord(ch):04X}"
            counts[key] = counts.get(key, 0) + 1
    return counts


# --- file walking ---------------------------------------------------------------

@dataclass
class TextFile:
    path: Path
    rel: str   # path relative to the target, posix style
    text: str


def collect_text_files(
    target: Path,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
) -> tuple[list[TextFile], dict[str, int]]:
    """Return decodable text files under *target* plus skip metrics.

    Binaries (NUL byte in the first 4 KiB), oversized files and non-UTF-8
    (or non-UTF-16-with-BOM) files are skipped and counted.
    """
    stats = {
        "files_seen": 0, "files_scanned": 0, "skipped_binary": 0,
        "skipped_large": 0, "skipped_undecodable": 0,
        "skipped_unreadable": 0, "skipped_max_files": 0,
    }
    if not target.exists():
        raise FileNotFoundError(str(target))

    paths: list[Path] = []
    base = target
    if target.is_file():
        paths.append(target)
        base = target.parent
    else:
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = sorted(
                d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")
            )
            for fn in sorted(filenames):
                if fn in _SKIP_FILES:
                    continue
                paths.append(Path(dirpath) / fn)

    files: list[TextFile] = []
    for p in paths:
        stats["files_seen"] += 1
        if len(files) >= max_files:
            stats["skipped_max_files"] += 1
            continue
        try:
            if p.stat().st_size > max_file_bytes:
                stats["skipped_large"] += 1
                continue
            raw = p.read_bytes()
        except OSError:
            stats["skipped_unreadable"] += 1
            continue
        if b"\x00" in raw[:4096]:
            stats["skipped_binary"] += 1
            continue
        text: str | None = None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
                try:
                    text = raw.decode("utf-16")
                except UnicodeDecodeError:
                    pass
        if text is None:
            stats["skipped_undecodable"] += 1
            continue
        files.append(TextFile(path=p, rel=p.relative_to(base).as_posix(), text=text))
        stats["files_scanned"] += 1
    return files, stats


# --- per-file scanning -----------------------------------------------------------

@dataclass
class _Agg:
    family: str
    count: int = 0
    cps: dict[str, int] = field(default_factory=dict)
    lines: list[tuple[int, str]] = field(default_factory=list)  # (lineno, line)
    decoded: str | None = None
    scheme: str | None = None

    def bump(self, ch: str) -> None:
        key = f"U+{ord(ch):04X}"
        self.cps[key] = self.cps.get(key, 0) + 1
        self.count += 1

    def record_line(self, lineno: int, line: str, cap: int = 32) -> None:
        if len(self.lines) < cap:
            self.lines.append((lineno, line))


def _window(line: str, idx: int, span: int = 34) -> str:
    start = max(0, idx - span)
    end = min(len(line), idx + span)
    return line[start:end]


def _is_vs(ch: str) -> bool:
    return ord(ch) in VS_LOW_RANGE or ord(ch) in VS_HIGH_RANGE


def scan_file_text(text: str, *, detect_homoglyphs: bool = False) -> list[_Agg]:
    """Scan one file's text; return one _Agg per concealment family present."""
    aggs: dict[str, _Agg] = {}

    def agg(family: str) -> _Agg:
        if family not in aggs:
            aggs[family] = _Agg(family=family)
        return aggs[family]

    # A single leading BOM is a byte-order mark, not concealment.
    work = text[1:] if text.startswith(ZWNBSP) else text

    for lineno, line in enumerate(work.splitlines(), start=1):
        # -- Tags block: detect + decode payload
        for m in TAGS_RE.finditer(line):
            a = agg("tags")
            for ch in m.group():
                a.bump(ch)
            a.record_line(lineno, line)
            payload = decode_tags_run(m.group())
            if payload and len(payload) >= 2 and a.decoded is None:
                a.decoded = payload

        # -- zero-width characters: presence + binary payload
        zw_positions = [i for i, ch in enumerate(line) if ord(ch) in ZERO_WIDTH_CPS]
        if zw_positions:
            n_zwj = sum(1 for i in zw_positions if line[i] == ZWJ)
            n_feff = sum(1 for i in zw_positions if line[i] == ZWNBSP)
            n_rare = len(zw_positions) - n_zwj - n_feff  # ZWSP/ZWNJ/WJ: no legit prose use
            # presence heuristics that avoid emoji false positives:
            #   ZWSP/ZWNJ/WJ anywhere, >=2 BOM-in-middle, or >=4 ZWJ in one line
            if n_rare >= 1 or n_feff >= 2 or n_zwj >= 4:
                a = agg("zero_width")
                for i in zw_positions:
                    if n_rare >= 1 or n_feff >= 2 or line[i] == ZWJ:
                        a.bump(line[i])
                a.record_line(lineno, line)
            for m in _ZW_BINARY_RE.finditer(line):
                payload = _decode_zw_run(m.group())
                if payload:
                    a = agg("zero_width_payload")
                    for ch in m.group():
                        a.bump(ch)
                    if a.decoded is None:
                        a.decoded = payload
                    a.record_line(lineno, line)

        # -- variation selectors: payload + (guarded) presence
        vs_positions = [i for i, ch in enumerate(line) if _is_vs(ch)]
        if vs_positions:
            for m in VS_RE.finditer(line):
                payload, scheme = _decode_vs_run(m.group())
                if payload:
                    a = agg("variation_selectors_payload")
                    for ch in m.group():
                        a.bump(ch)
                    if a.decoded is None:
                        a.decoded = payload
                        a.scheme = scheme
                    a.record_line(lineno, line)
            # presence: any VS-206, or a >=8 run of VS-16 (emoji use 1-2)
            has_high = any(ord(line[i]) in VS_HIGH_RANGE for i in vs_positions)
            runs = VS_RE.findall(line)
            long_low = any(
                len(r) >= 8 and all(ord(c) in VS_LOW_RANGE for c in r) for r in runs
            )
            if has_high or long_low:
                a = agg("variation_selectors")
                for i in vs_positions:
                    a.bump(line[i])
                a.record_line(lineno, line)

        # -- bidi controls & marks
        for ch in line:
            if ord(ch) in BIDI_CONTROL_CPS:
                a = agg("bidi_control")
                a.bump(ch)
                a.record_line(lineno, line)
            elif ord(ch) in BIDI_MARK_CPS:
                a = agg("bidi_marks")
                a.bump(ch)
                a.record_line(lineno, line)

        # -- homoglyphs (opt-in)
        if detect_homoglyphs:
            minority = _homoglyph_minority(line)
            if minority:
                count, pairs = minority
                a = agg("homoglyph")
                a.count += count
                for ch, _script in pairs:
                    a.bump(ch)
                a.record_line(lineno, line)

    return [aggs[k] for k in sorted(aggs) if aggs[k].count > 0]


def _homoglyph_minority(line: str) -> tuple[int, list[tuple[str, str]]] | None:
    """Return (minority_letter_count, minority_chars) if the line mixes scripts."""
    counts = {"LATIN": 0, "CYRILLIC": 0, "GREEK": 0}
    chars: dict[str, list[str]] = {"LATIN": [], "CYRILLIC": [], "GREEK": []}
    for ch in line:
        if not ch.isalpha():
            continue
        try:
            script = unicodedata.name(ch).split()[0]
        except ValueError:
            continue
        if script in counts:
            counts[script] += 1
            if len(chars[script]) < 8:
                chars[script].append(ch)
    present = [s for s, c in counts.items() if c]
    if len(present) < 2:
        return None
    minority_script = min(present, key=lambda s: counts[s])
    minority = counts[minority_script]
    if 1 <= minority <= 12:
        return minority, [(ch, minority_script) for ch in chars[minority_script]]
    return None


def _finding_from_agg(agg: _Agg, rel: str, max_evidence: int) -> Finding:
    ids, severity, title = _FAMILY_META[agg.family]
    unknown = set(ids) - set(OWASP_IDS)
    if unknown:  # bug guard: keep findings inside the shared taxonomy
        raise ValueError(f"unknown OWASP ids {unknown} for family {agg.family}")

    decoded = agg.decoded
    if decoded and agg.family in ("tags", "zero_width_payload", "variation_selectors_payload"):
        if _PAYLOAD_RISK_RE.search(decoded):
            severity = "critical"

    lines_seen = sorted({ln for ln, _ in agg.lines})
    detail = (
        f"{agg.count} hidden codepoint(s) of the {agg.family.replace('_', ' ')} family "
        f"in file '{rel}' (lines {lines_seen[:10]})."
    )
    if decoded:
        detail += f" Decoded payload: {decoded[:200]!r}."
    detail += (
        " Concealed content is invisible to reviewers and LLM judges alike;"
        " treat any decoded instruction as untrusted input."
    )

    evidence: list[EvidenceSnippet] = []
    for ln, line in agg.lines[:max_evidence]:
        idx = next((i for i, ch in enumerate(line) if _HIDDEN_RE.match(ch)), 0)
        excerpt = f"L{ln} raw={_window(line, idx)!r}"
        if decoded:
            excerpt += f" decoded={decoded[:120]!r}"
        evidence.append(
            EvidenceSnippet(
                source=f"file:{rel}:L{ln}",
                excerpt=excerpt[:480],
                meta={
                    "family": agg.family,
                    "line": ln,
                    "count": agg.count,
                    "decoded_payload": decoded,
                    "codepoints": dict(sorted(agg.cps.items())[:8]),
                },
            )
        )
    if not evidence:  # defensive: families always record lines
        evidence.append(
            EvidenceSnippet(
                source=f"file:{rel}",
                excerpt=f"count={agg.count}",
                meta={"family": agg.family},
            )
        )

    return Finding(
        owasp_ids=list(ids),
        title=f"{title} in {rel}",
        detail=detail,
        severity=severity,  # type: ignore[arg-type]
        confidence="deterministic",
        stage="concealment",
        evidence=evidence,
    )


# --- the stage -------------------------------------------------------------------

class ConcealmentStage:
    """S0 - deterministic Unicode-smuggling detector and payload decoder."""

    name = "concealment"

    def __init__(
        self,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_files: int = DEFAULT_MAX_FILES,
        detect_homoglyphs: bool = False,
        max_evidence_per_finding: int = 5,
    ) -> None:
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.detect_homoglyphs = detect_homoglyphs
        self.max_evidence_per_finding = max_evidence_per_finding

    async def run(self, job: AuditJob, target: Path) -> StageResult:
        t0 = time.perf_counter()
        try:
            files, stats = collect_text_files(target, self.max_file_bytes, self.max_files)
            findings: list[Finding] = []
            for tf in files:
                for agg in scan_file_text(tf.text, detect_homoglyphs=self.detect_homoglyphs):
                    findings.append(_finding_from_agg(agg, tf.rel, self.max_evidence_per_finding))
        except Exception as exc:  # bug or unreadable target: report, don't crash the pipeline
            return StageResult(stage=self.name, ok=False, error=f"{type(exc).__name__}: {exc}")
        stats["findings"] = len(findings)
        stats["duration_s"] = round(time.perf_counter() - t0, 4)
        return StageResult(stage=self.name, ok=True, findings=findings, metrics=stats)


__all__ = [
    "ConcealmentStage",
    "TextFile",
    "collect_text_files",
    "decode_tags_block",
    "decode_tags_run",
    "encode_tags_block",
    "decode_zero_width_binary",
    "encode_zero_width_binary",
    "decode_variation_selectors",
    "encode_variation_selectors",
    "strip_hidden",
    "hidden_codepoint_counts",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_FILES",
]
