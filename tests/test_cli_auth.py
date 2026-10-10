"""BYOK auth contracts: authored secrets, fake storage and blocked transports."""
from __future__ import annotations

import asyncio
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
EU = "https://api.tokenfactory.nebius.com/v1/"
US = "https://api.tokenfactory.us-central1.nebius.com/v1/"


@pytest.fixture(autouse=True)
def isolated_auth(monkeypatch):
    # Never let a test consume the operator's provider configuration or desktop.
    monkeypatch.setenv("FUGU_NO_DOTENV", "1")
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    for name in ("NEBIUS_API_KEY", "TAVILY_API_KEY", "NEBIUS_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FUGU_DISABLE_OSV", "1")
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("network forbidden"))
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("network forbidden"))
    monkeypatch.setitem(sys.modules, "keyring", None)


def credentials():
    assert importlib.util.find_spec("fugu.credentials") is not None, "credential layer is missing"
    return importlib.import_module("fugu.credentials")


class SpyStore:
    def __init__(self, saved=None, error=False):
        self.saved = saved or {}
        self.calls = []
        self.error = error

    def get(self, provider):
        self.calls.append(("get", provider))
        if self.error:
            raise RuntimeError("fake backend private detail")
        return self.saved.get(provider)

    def set(self, provider, value):
        self.calls.append(("set", provider))
        self.saved[provider] = value

    def delete(self, provider):
        self.calls.append(("delete", provider))
        self.saved.pop(provider, None)


@pytest.mark.parametrize("value", ["", " ", "fake-env-nebius"])
def test_environment_presence_never_reads_saved_nebius(value):
    store = SpyStore({"nebius": "fake-saved-nebius", "tavily": "fake-saved-tavily"})
    keys = credentials().resolve_credentials({"NEBIUS_API_KEY": value}, store)
    assert keys.nebius == value.strip()
    assert keys.tavily == ""
    assert store.calls == []


def test_saved_nebius_and_tavily_lookup_are_provider_specific():
    c = credentials()
    store = SpyStore({"nebius": "fake-saved-nebius", "tavily": "fake-saved-tavily"})
    keys = c.resolve_credentials({}, store)
    assert keys.nebius == "fake-saved-nebius" and keys.tavily == ""
    assert store.calls == [("get", "nebius")]
    store.calls.clear()
    keys = c.resolve_credentials({"NEBIUS_API_KEY": "fake-env-nebius"}, store, use_stored_tavily=True)
    assert keys.tavily == "fake-saved-tavily"
    assert store.calls == [("get", "tavily")]


@pytest.mark.parametrize("value", ["", "fake-env-tavily"])
def test_present_tavily_wins_even_with_reputation_opt_in(value):
    store = SpyStore({"tavily": "fake-saved-tavily"})
    keys = credentials().resolve_credentials({"NEBIUS_API_KEY": "fake-env-nebius", "TAVILY_API_KEY": value}, store, use_stored_tavily=True)
    assert keys.tavily == value
    assert store.calls == []


def test_environment_only_headless_setup_never_acquires_backend(monkeypatch):
    c = credentials()
    def forbidden(*a, **k):
        pytest.fail("environment-only command acquired desktop storage")
    monkeypatch.setattr(importlib, "import_module", forbidden)
    keys = c.resolve_credentials({"NEBIUS_API_KEY": "fake-env-nebius"}, c.NativeSecretStore())
    assert keys.nebius == "fake-env-nebius" and keys.tavily == ""


@pytest.mark.parametrize("endpoint", [EU, US, EU.rstrip("/"), US.rstrip("/")])
def test_official_endpoints_are_normalized(endpoint):
    assert credentials().resolve_credentials({"NEBIUS_API_KEY": "", "NEBIUS_BASE_URL": endpoint}, None).base_url == endpoint.rstrip("/") + "/"


@pytest.mark.parametrize("endpoint", ["", "http://api.tokenfactory.nebius.com/v1/", "https://evil.invalid/v1/", "https://user:fake-url-key@api.tokenfactory.nebius.com/v1/", EU + "?token=fake-url-key", EU + "#fake-url-key", EU + "other", "https://api.tokenfactory.nebius.com:443/v1/", "https://api.tokenfactory.nebius.com.evil.invalid/v1/"])
def test_bad_endpoint_fails_before_saved_lookup(endpoint):
    c = credentials()
    store = SpyStore()
    with pytest.raises(c.CredentialError) as error:
        c.resolve_credentials({"NEBIUS_BASE_URL": endpoint}, store)
    assert store.calls == []
    assert "fake-url-key" not in str(error.value)


def test_status_reports_presence_only_and_skips_present_environment():
    c = credentials()
    store = SpyStore({"tavily": "fake-saved-tavily"})
    report = c.credential_status({"NEBIUS_API_KEY": ""}, store)
    assert report["providers"]["nebius"] == {"configured": False, "source": "environment", "disabled": True, "storage": "not_requested"}
    assert report["providers"]["tavily"]["configured"] is True
    assert report["providers"]["tavily"]["source"] == "keyring"
    assert store.calls == [("get", "tavily")]
    assert "fake-saved-tavily" not in json.dumps(report)


def test_unavailable_storage_is_safe_local_status():
    report = credentials().credential_status({}, SpyStore(error=True))
    assert all(p["storage"] == "unavailable" for p in report["providers"].values())
    assert "private detail" not in json.dumps(report)


def native_fake(monkeypatch, module, class_name, *, error=False, subclass=False):
    calls = []
    saved = {}
    class Backend:
        def get_password(self, service, account):
            calls.append(("get", service, account))
            if error:
                raise RuntimeError("fake-secret-backend-detail")
            return saved.get((service, account))
        def set_password(self, service, account, value):
            calls.append(("set", service, account))
            saved[service, account] = value
        def delete_password(self, service, account):
            calls.append(("delete", service, account))
            del saved[service, account]
    Backend.__module__ = module
    Backend.__name__ = class_name
    native = types.ModuleType(module)
    setattr(native, class_name, Backend)
    monkeypatch.setitem(sys.modules, module, native)
    keyring = types.ModuleType("keyring")
    backend = type("Alternate", (Backend,), {})() if subclass else Backend()
    keyring.get_keyring = lambda: backend
    monkeypatch.setitem(sys.modules, "keyring", keyring)
    return calls, saved


@pytest.mark.parametrize("module,class_name", [("keyring.backends.macOS", "Keyring"), ("keyring.backends.Windows", "WinVaultKeyring"), ("keyring.backends.SecretService", "Keyring")])
def test_native_allowlist_and_provider_separated_fugu_entries(monkeypatch, module, class_name):
    c = credentials()
    calls, saved = native_fake(monkeypatch, module, class_name)
    store = c.NativeSecretStore()
    assert calls == []
    store.set("nebius", "fake-stored-nebius")
    store.set("tavily", "fake-stored-tavily")
    assert store.get("nebius") == "fake-stored-nebius"
    assert store.get("tavily") == "fake-stored-tavily"
    store.delete("nebius")
    store.delete("nebius")
    assert store.get("nebius") is None
    assert store.get("tavily") == "fake-stored-tavily"
    assert all("fugu" in call[1].lower() for call in calls)
    assert len(saved) == 1


@pytest.mark.parametrize("module,class_name", [("keyring.backends.null", "Keyring"), ("keyring.backends.fail", "Keyring"), ("keyrings.alt.file", "PlaintextKeyring"), ("keyring.backends.chainer", "ChainerBackend"), ("third_party", "Keyring")])
def test_insecure_and_chained_backends_rejected_before_access(monkeypatch, module, class_name):
    c = credentials()
    calls, _ = native_fake(monkeypatch, module, class_name)
    with pytest.raises(c.CredentialError):
        c.NativeSecretStore().set("nebius", "fake-value")
    assert calls == []


def test_native_subclass_is_not_an_approved_backend(monkeypatch):
    c = credentials()
    calls, _ = native_fake(monkeypatch, "keyring.backends.macOS", "Keyring", subclass=True)
    with pytest.raises(c.CredentialError):
        c.NativeSecretStore().get("nebius")
    assert calls == []


def test_locked_backend_error_is_categorized_without_private_details(monkeypatch):
    c = credentials()
    native_fake(monkeypatch, "keyring.backends.macOS", "Keyring", error=True)
    with pytest.raises(c.CredentialError) as error:
        c.NativeSecretStore().get("nebius")
    assert "NEBIUS_API_KEY" in str(error.value)
    assert "fake-secret" not in str(error.value)


def test_credential_repr_does_not_contain_keys():
    c = credentials()
    assert "fake-repr" not in repr(c.CredentialSet(nebius="fake-repr-nebius", tavily="fake-repr-tavily"))


def test_nested_scopes_restore_settings_and_do_not_mutate_environment(monkeypatch):
    c = credentials()
    from fugu.config import credential_scope, get_settings, get_reputation_api_key
    monkeypatch.setenv("NEBIUS_API_KEY", "fake-environment")
    monkeypatch.setenv("TAVILY_API_KEY", "fake-environment-tavily")
    before = dict(os.environ)
    with credential_scope(c.CredentialSet("fake-outer", "fake-outer-tavily", US)):
        assert get_settings().api_key == "fake-outer" and get_settings().base_url == US
        assert get_reputation_api_key() == "fake-outer-tavily"
        with pytest.raises(ValueError):
            with credential_scope(c.CredentialSet("fake-inner")):
                assert get_settings().api_key == "fake-inner"
                raise ValueError("controlled failure")
        assert get_settings().api_key == "fake-outer"
    assert get_settings().api_key == "fake-environment"
    assert get_reputation_api_key() == "fake-environment-tavily"
    assert dict(os.environ) == before


def test_contexts_are_isolated_across_concurrent_tasks():
    c = credentials()
    from fugu.config import credential_scope, get_settings, get_reputation_api_key
    async def check(key):
        with credential_scope(c.CredentialSet(key, key + "-tavily")):
            await asyncio.sleep(0)
            return get_settings().api_key, get_reputation_api_key()
    async def run():
        return await asyncio.gather(check("fake-first"), check("fake-second"))
    assert asyncio.run(run()) == [("fake-first", "fake-first-tavily"), ("fake-second", "fake-second-tavily")]


def test_scoped_client_uses_credentials_without_prompt_content(monkeypatch):
    c = credentials()
    from fugu.config import credential_scope
    import fugu.client as client
    seen = {}
    monkeypatch.setattr(client, "OpenAI", lambda **kw: seen.update(kw))
    with credential_scope(c.CredentialSet("fake-scoped-header", base_url=US)):
        client.make_client()
    transport = seen.pop("http_client")
    try:
        assert transport.follow_redirects is False
        assert seen == {"base_url": US, "api_key": "fake-scoped-header", "max_retries": 0, "timeout": 90}
        assert "messages" not in seen
    finally:
        transport.close()


def test_reputation_uses_scoped_key_only_in_auth_plane(tmp_path):
    c = credentials()
    from fugu.config import credential_scope
    from fugu.pipeline.stages.reputation import ReputationStage
    from fugu.types import AuditJob
    (tmp_path / "package.json").write_text('{"name":"authored-example-package"}')
    requests = []
    def fake_search(key, query):
        requests.append((key, query))
        return {"results": []}
    with credential_scope(c.CredentialSet(tavily="fake-scoped-tavily")):
        result = asyncio.run(ReputationStage(search_fn=fake_search).run(AuditJob(id="fake-auth", source=str(tmp_path)), tmp_path))
    assert requests and all(key == "fake-scoped-tavily" for key, _ in requests)
    assert all("fake-scoped-tavily" not in query for _, query in requests)
    assert "fake-scoped-tavily" not in repr(result)


# A fresh interpreter loads only authored hooks; every native/network access is fake.
HOOK = r'''
import os, sys, types, socket, json, getpass, dotenv
from pathlib import Path
trace = Path(os.environ["FUGU_TEST_TRACE"])
def note(event):
    with trace.open("a") as f: f.write(event + "\n")
def denied(*a, **k):
    note("forbidden-network")
    raise AssertionError("network forbidden")
socket.create_connection = denied
socket.socket.connect = denied
def dotenv_load(*a, **k):
    note("dotenv-load")
    os.environ["NEBIUS_API_KEY"] = "fake-hostile-dotenv"
    os.environ["NEBIUS_BASE_URL"] = "https://hostile.invalid/v1/"
    return True
dotenv.load_dotenv = dotenv_load
backend_module = "keyring.backends.macOS"
native = types.ModuleType(backend_module)
class Keyring:
    def get_password(self, service, account):
        note("get:" + account)
        if os.environ.get("FUGU_TEST_LOCKED"): raise RuntimeError("fake-private-backend-key")
        return "fake-saved-" + account
    def set_password(self, service, account, value):
        note("set:" + account)
        assert value == "fake-hidden-input"
    def delete_password(self, service, account): note("delete:" + account)
Keyring.__module__ = backend_module
native.Keyring = Keyring
sys.modules[backend_module] = native
keyring = types.ModuleType("keyring")
def backend():
    note("backend")
    return Keyring()
keyring.get_keyring = backend
sys.modules["keyring"] = keyring
def hidden(*a, **k):
    note("getpass")
    if os.environ.get("FUGU_TEST_INTERRUPT"): raise KeyboardInterrupt()
    if os.environ.get("FUGU_TEST_NO_ECHO"): raise getpass.GetPassWarning("fake-terminal-detail")
    return os.environ.get("FUGU_TEST_INPUT", "fake-hidden-input")
getpass.getpass = hidden
if os.environ.get("FUGU_TEST_TTY"):
    class Input:
        def isatty(self): return True
    sys.stdin = Input()
import openai, importlib
OriginalClient = openai.DefaultHttpxClient
httpx = importlib.import_module(OriginalClient.__mro__[1].__module__.split(".")[0])
class FakeClient(OriginalClient):
    def __init__(self, *a, **kw):
        note("http-client:" + str(kw.get("follow_redirects")))
        def respond(req):
            note("request:" + req.method + ":" + req.url.path)
            assert str(req.url).startswith("https://api.tokenfactory.nebius.com/v1/")
            assert req.headers["authorization"] == "Bearer " + os.environ.get("NEBIUS_API_KEY", "fake-saved-nebius")
            assert req.content == b""
            assert all(value == 10.0 for value in req.extensions["timeout"].values())
            status = int(os.environ.get("FUGU_TEST_HTTP_STATUS", "200"))
            if status == 302:
                return httpx.Response(302, headers={"location":"https://evil.invalid/stolen"})
            return httpx.Response(status, json={"object":"list","data":[],"error":{"message":"fake-env-nebius provider detail"}})
        kw["transport"] = httpx.MockTransport(respond)
        super().__init__(*a, **kw)
openai.DefaultHttpxClient = FakeClient
'''


def cli_run(tmp_path, args, extra=None):
    hooks = tmp_path / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "sitecustomize.py").write_text(textwrap.dedent(HOOK))
    trace = tmp_path / "trace.txt"
    # Minimal authored environment: no inherited operator credentials or keyring config.
    env = {"PATH": os.defpath, "PYTHONPATH": str(hooks) + os.pathsep + str(ROOT / "src"), "FUGU_TEST_TRACE": str(trace), "FUGU_DISABLE_OSV": "1"}
    env.update(extra or {})
    (tmp_path / ".env").write_text("NEBIUS_API_KEY=fake-hostile-dotenv\nNEBIUS_BASE_URL=https://hostile.invalid/v1/\n")
    result = subprocess.run([sys.executable, "-m", "fugu", *args], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10)
    events = trace.read_text().splitlines() if trace.exists() else []
    return result, events


@pytest.mark.parametrize("flag", ["--help", "--version"])
def test_actual_module_help_and_version_without_storage_clients_or_dotenv(tmp_path, flag):
    result, events = cli_run(tmp_path, [flag])
    assert result.returncode == 0, result.stderr
    assert events == []
    assert "fugu" in result.stdout.lower()


def test_configure_uses_hidden_input_and_writes_despite_environment(tmp_path):
    result, events = cli_run(tmp_path, ["configure"], {"NEBIUS_API_KEY":"fake-env-nebius", "FUGU_TEST_TTY":"1"})
    assert result.returncode == 0, result.stderr
    assert "getpass" in events and "set:nebius" in events
    assert "dotenv-load" not in events and not any(e.startswith("request:") for e in events)
    assert "Nebius" in result.stderr and "billed" in result.stderr
    assert "fake-hidden-input" not in result.stdout + result.stderr


def test_noninteractive_configure_does_not_prompt_or_acquire_store(tmp_path):
    result, events = cli_run(tmp_path, ["configure"])
    assert result.returncode == 2
    assert events == []
    assert "NEBIUS_API_KEY" in result.stderr


def test_empty_hidden_input_cancels_without_storage(tmp_path):
    result, events = cli_run(tmp_path, ["configure", "--provider", "tavily"], {"FUGU_TEST_TTY":"1", "FUGU_TEST_INPUT":""})
    assert result.returncode == 0
    assert events == ["getpass"]
    assert "cancel" in result.stderr.lower()


def test_logout_deletes_selected_fugu_entry_even_with_environment_override(tmp_path):
    result, events = cli_run(tmp_path, ["auth", "logout", "--provider", "nebius"], {"NEBIUS_API_KEY":"fake-env-nebius"})
    assert result.returncode == 0, result.stderr
    assert "delete:nebius" in events
    assert not any(e.endswith(":tavily") for e in events)
    assert "environment" in result.stdout and "effective" in result.stdout
    assert "fake-env-nebius" not in result.stdout + result.stderr


def test_local_status_reads_only_absent_provider_and_never_network(tmp_path):
    result, events = cli_run(tmp_path, ["auth", "status"], {"NEBIUS_API_KEY":""})
    assert result.returncode == 0, result.stderr
    assert "get:nebius" not in events and "get:tavily" in events
    assert "dotenv-load" not in events and not any(e.startswith("request:") for e in events)
    assert "disabled" in result.stdout and "keyring" in result.stdout
    assert "fake-saved" not in result.stdout + result.stderr


def test_local_status_unavailable_backend_is_safe(tmp_path):
    result, events = cli_run(tmp_path, ["auth", "status"], {"FUGU_TEST_LOCKED":"1"})
    assert result.returncode == 0, result.stderr
    assert "unavailable" in result.stdout
    assert "fake-private" not in result.stdout + result.stderr


@pytest.mark.parametrize("status,expected", [(200,0), (401,2), (403,2), (302,2), (500,2)])
def test_verify_is_one_bounded_no_redirect_request_without_tavily_storage(tmp_path, status, expected):
    result, events = cli_run(tmp_path, ["auth", "status", "--verify"], {"NEBIUS_API_KEY":"fake-env-nebius", "FUGU_TEST_HTTP_STATUS":str(status)})
    assert result.returncode == expected, result.stderr
    assert [e for e in events if e.startswith("request:")] == ["request:GET:/v1/models"]
    assert "http-client:False" in events
    assert "backend" not in events and "dotenv-load" not in events
    assert "fake-env-nebius" not in result.stdout + result.stderr
    if expected == 0:
        assert "not inference" in result.stdout.lower()


def test_verify_empty_environment_never_resurrects_stored_key(tmp_path):
    result, events = cli_run(tmp_path, ["auth", "status", "--verify"], {"NEBIUS_API_KEY":""})
    assert result.returncode == 2
    assert events == []


def test_cli_bad_endpoint_never_reads_storage_or_constructs_client(tmp_path):
    result, events = cli_run(tmp_path, ["auth", "status", "--verify"], {"NEBIUS_BASE_URL":"https://fake-url-key@evil.invalid/v1/"})
    assert result.returncode == 2
    assert events == []
    assert "fake-url-key" not in result.stdout + result.stderr


def test_unknown_cli_argument_does_not_echo_a_secret(tmp_path):
    result, events = cli_run(tmp_path, ["configure", "--key", "fake-argv-key"])
    assert result.returncode == 2
    assert "fake-argv-key" not in result.stdout + result.stderr
    assert events == []


def test_dotenv_guard_preserves_server_behavior_when_absent(tmp_path):
    script = "import dotenv; calls=[]; dotenv.load_dotenv=lambda: calls.append(1); import fugu.config; assert calls == [1]"
    env = {"PATH":os.defpath, "PYTHONPATH":str(ROOT / "src")}
    result = subprocess.run([sys.executable,"-c",script],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
    assert result.returncode == 0, result.stderr


def test_explicit_dotenv_guard_blocks_loader(tmp_path):
    script = "import dotenv; calls=[]; dotenv.load_dotenv=lambda: calls.append(1); import fugu.config; assert calls == []"
    env = {"PATH":os.defpath,"PYTHONPATH":str(ROOT / "src"),"FUGU_NO_DOTENV":"1"}
    result = subprocess.run([sys.executable,"-c",script],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
    assert result.returncode == 0, result.stderr


def test_safe_redaction_preserves_fake_canary():
    assert importlib.util.find_spec("fugu.cli_output") is not None, "safe CLI output layer is missing"
    from fugu.cli_output import redact
    result = redact("fake-provider-secret PRIVATE_DEMO_MARKER fake-provider-secret", ["fake-provider-secret", ""])
    assert result == "[REDACTED] PRIVATE_DEMO_MARKER [REDACTED]"


def test_scoped_client_disables_redirects_without_changing_server_defaults(monkeypatch):
    c = credentials()
    from fugu.config import credential_scope
    import fugu.client as client
    created = []
    monkeypatch.setattr(client, "OpenAI", lambda **kwargs: created.append(kwargs))
    with credential_scope(c.CredentialSet("fake-scoped-nebius")):
        client.make_client()
    assert "http_client" in created[0], "scoped credential requests need redirect protection"
    transport = created[0]["http_client"]
    try:
        assert transport.follow_redirects is False
    finally:
        transport.close()
    client.make_client(types.SimpleNamespace(api_key="fake-server", base_url="https://server.invalid/v1/"))
    assert "http_client" not in created[1]


def test_semantic_prompt_and_results_do_not_receive_runtime_credentials(tmp_path, monkeypatch):
    c = credentials()
    from fugu.config import credential_scope
    import fugu.client as client
    from fugu.pipeline.stages.semantic import SemanticStage
    from fugu.types import AuditJob
    (tmp_path / "SKILL.md").write_text("# Authored sample\nSummarize a selected public document.\n")
    seen = []
    clients = []
    def complete(**kwargs):
        seen.append(kwargs)
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=types.SimpleNamespace(content='{"findings": []}'), finish_reason="stop")],
            model="authored-fake-model", usage=None,
        )
    def fake_client(**kwargs):
        clients.append(kwargs)
        return types.SimpleNamespace(chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=complete)))
    monkeypatch.setattr(client, "OpenAI", fake_client)
    with credential_scope(c.CredentialSet("fake-no-prompt-nebius", "fake-no-prompt-tavily")):
        result = asyncio.run(SemanticStage().run(AuditJob(id="authored-semantic", source=str(tmp_path), depth="full"), tmp_path))
    try:
        assert result.ok and seen and clients[0]["api_key"] == "fake-no-prompt-nebius"
        assert all("fake-no-prompt" not in json.dumps(request) for request in seen)
        assert "fake-no-prompt" not in repr(result)
    finally:
        for kwargs in clients:
            if "http_client" in kwargs:
                kwargs["http_client"].close()


def test_provider_debug_logging_does_not_expose_auth_or_response_secrets(tmp_path):
    result, events = cli_run(tmp_path, ["auth", "status", "--verify"], {"NEBIUS_API_KEY":"fake-env-nebius", "FUGU_TEST_HTTP_STATUS":"401", "OPENAI_LOG":"debug"})
    assert result.returncode == 2
    assert [e for e in events if e.startswith("request:")] == ["request:GET:/v1/models"]
    assert "fake-env-nebius" not in result.stdout + result.stderr
    assert "provider detail" not in result.stdout + result.stderr


def test_configure_tavily_uses_selected_fugu_entry(tmp_path):
    result, events = cli_run(tmp_path, ["configure", "--provider", "tavily"], {"TAVILY_API_KEY":"fake-env-tavily", "FUGU_TEST_TTY":"1"})
    assert result.returncode == 0
    assert "set:tavily" in events and "set:nebius" not in events
    assert "Tavily" in result.stderr
    assert "fake-hidden-input" not in result.stdout + result.stderr


def test_status_both_environment_values_never_acquires_backend(tmp_path):
    result, events = cli_run(tmp_path, ["auth", "status"], {"NEBIUS_API_KEY":"fake-env-nebius", "TAVILY_API_KEY":"fake-env-tavily"})
    assert result.returncode == 0
    assert events == []
    assert result.stdout.count("source=environment") == 2
    assert "fake-env" not in result.stdout + result.stderr


def test_resolving_saved_key_failure_does_not_leak_backend_error():
    c = credentials()
    with pytest.raises(c.CredentialError) as error:
        c.resolve_credentials({}, SpyStore(error=True))
    assert "private detail" not in str(error.value)
    assert "NEBIUS_API_KEY" in str(error.value)


def test_native_store_missing_extra_fails_safely_without_plaintext():
    c = credentials()
    with pytest.raises(c.CredentialError) as error:
        c.NativeSecretStore().set("nebius", "fake-unavailable-key")
    assert "plaintext fallback" in str(error.value)
    assert "fake-unavailable-key" not in str(error.value)


def test_verify_saved_nebius_does_not_request_saved_tavily(tmp_path):
    result, events = cli_run(tmp_path, ["auth", "status", "--verify"])
    assert result.returncode == 0, result.stderr
    assert events.count("backend") == 1 and events.count("get:nebius") == 1
    assert "get:tavily" not in events
    assert [e for e in events if e.startswith("request:")] == ["request:GET:/v1/models"]
    assert "source=keyring" in result.stdout
    assert "fake-saved" not in result.stdout + result.stderr


def test_configure_refuses_echo_fallback(tmp_path):
    result, events = cli_run(tmp_path, ["configure"], {"FUGU_TEST_TTY":"1", "FUGU_TEST_NO_ECHO":"1"})
    assert result.returncode == 2
    assert events == ["getpass"]
    assert "NEBIUS_API_KEY" in result.stderr and "fake-terminal-detail" not in result.stderr


def test_interrupted_hidden_input_returns_130_without_storage(tmp_path):
    result, events = cli_run(tmp_path, ["configure"], {"FUGU_TEST_TTY":"1", "FUGU_TEST_INTERRUPT":"1"})
    assert result.returncode == 130
    assert events == ["getpass"]


def test_logout_all_deletes_only_fugu_provider_entries(tmp_path):
    result, events = cli_run(tmp_path, ["auth", "logout"], {"NEBIUS_API_KEY":"fake-env-nebius", "TAVILY_API_KEY":"fake-env-tavily"})
    assert result.returncode == 0
    assert events.count("backend") == 1
    assert "delete:nebius" in events and "delete:tavily" in events
    assert result.stdout.count("remains effective") == 2
    assert "fake-env" not in result.stdout + result.stderr
