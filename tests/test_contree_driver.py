"""ContreeDriver: unit tests (hermetic - no live sandbox calls)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fugu.detonation.contree_driver import (  # noqa: E402
    ContreeDriver,
    _dns_records,
    _proxy_flows,
    _split_sections,
    _wrap_trigger,
)


def test_wrapper_starts_collectors_and_marks_sections():
    w = _wrap_trigger("bash /opt/target/install.sh", {"FUGU_CANARY_TOKEN": "x"})
    for marker in ("__FUGU_TRIGGER_BEGIN__", "__FUGU_TRIGGER_END__",
                   "__FUGU_PROXY_LOG__", "__FUGU_DNS_LOG__", "__FUGU_FS_PROBE__"):
        assert marker in w, marker
    assert "resolv.conf" in w and "8899" in w  # DNS + proxy redirection


def test_split_sections_roundtrip():
    out = _split_sections("__FUGU_PROXY_LOG__\nREQ a\nREQ b\n__FUGU_DNS_LOG__\nx.test\n")
    assert out.get("PROXY_LOG") == "REQ a\nREQ b"
    assert out.get("DNS_LOG") == "x.test"


def test_proxy_flows_parse_host_method_body():
    log = "REQ POST http://185.34.21.9:8080/v2/bootstrap host=185.34.21.9:8080 body=TOK=abc"
    flows = _proxy_flows(log)
    assert len(flows) == 1
    f = flows[0]
    assert f.host == "185.34.21.9:8080" and f.method == "POST"
    assert "TOK=abc" in f.body


def test_proxy_flows_relative_form_uses_host_header():
    log = "REQ POST /v2/bootstrap host=evil.test body=x=1"
    flows = _proxy_flows(log)
    assert flows[0].host == "evil.test" and flows[0].path == "/v2/bootstrap"


def test_dns_records_parse():
    assert [d.query for d in _dns_records("a.test\nb.test\n")] == ["a.test", "b.test"]


def test_driver_needs_creds(monkeypatch):
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("CONTREE_TOKEN", raising=False)
    monkeypatch.delenv("NEBIUS_AI_PROJECT", raising=False)
    monkeypatch.delenv("CONTREE_PROJECT", raising=False)
    drv = ContreeDriver()
    assert not (drv.token and drv.project)


def test_driver_selection_env(monkeypatch):
    import os

    for var in ("NEBIUS_API_KEY", "CONTREE_TOKEN", "NEBIUS_AI_PROJECT", "CONTREE_PROJECT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("FUGU_DRIVER", "contree")
    from fugu.pipeline.assemble import _make_detonation_driver

    # no creds -> must NOT crash; falls back to Docker or None
    drv = _make_detonation_driver()
    assert drv is None or type(drv).__name__ == "DockerDriver"

    monkeypatch.setenv("FUGU_DRIVER", "docker")
    drv2 = _make_detonation_driver()
    assert drv2 is None or type(drv2).__name__ == "DockerDriver"
