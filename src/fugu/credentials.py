"""Provider-specific credential resolution and lazy approved native storage.

Importing this module never imports keyring or acquires a desktop backend.
Environment presence (including an empty value) suppresses stored lookup.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import importlib
from typing import Any, Mapping, Protocol

from fugu.cli_output import CliError


@dataclass(frozen=True)
class CredentialSet:
    nebius: str = field(default="", repr=False)
    tavily: str = field(default="", repr=False)
    base_url: str = "https://api.tokenfactory.nebius.com/v1/"


class SecretStore(Protocol):
    def get(self, provider: str) -> str | None: ...
    def set(self, provider: str, value: str) -> None: ...
    def delete(self, provider: str) -> None: ...


class CredentialError(CliError):
    def __init__(self, message: str, category: str = "credential") -> None:
        super().__init__(category, message)


_ENV_NAMES = {"nebius": "NEBIUS_API_KEY", "tavily": "TAVILY_API_KEY"}
_NATIVE_BACKENDS = {
    ("keyring.backends.macOS", "Keyring"),
    ("keyring.backends.Windows", "WinVaultKeyring"),
    ("keyring.backends.SecretService", "Keyring"),
}
_SERVICE = "fugu.byok"


def _env_name(provider: str) -> str:
    if provider not in _ENV_NAMES:
        raise CredentialError("Unsupported provider.", "usage")
    return _ENV_NAMES[provider]


def _storage_error(provider: str) -> CredentialError:
    return CredentialError(
        "Approved native credential storage is unavailable, locked or unsupported. "
        f"Use {_env_name(provider)} in your environment; no plaintext fallback is used."
    )


class NativeSecretStore:
    """Acquire once on first operation, then use only exact approved backend types."""

    def __init__(self) -> None:
        self._backend: Any = None

    def _acquire(self, provider: str) -> Any:
        _env_name(provider)
        if self._backend is not None:
            return self._backend
        try:
            keyring = importlib.import_module("keyring")
            backend = keyring.get_keyring()
            identity = (type(backend).__module__, type(backend).__name__)
            if identity not in _NATIVE_BACKENDS:
                raise _storage_error(provider)
            native = importlib.import_module(identity[0])
            if type(backend) is not getattr(native, identity[1]):
                raise _storage_error(provider)
            self._backend = backend
            return backend
        except Exception:
            raise _storage_error(provider) from None

    def get(self, provider: str) -> str | None:
        try:
            return self._acquire(provider).get_password(_SERVICE, provider)
        except Exception:
            raise _storage_error(provider) from None

    def set(self, provider: str, value: str) -> None:
        try:
            self._acquire(provider).set_password(_SERVICE, provider, value)
        except Exception:
            raise _storage_error(provider) from None

    def delete(self, provider: str) -> None:
        try:
            backend = self._acquire(provider)
            # Native backends signal a missing entry differently. Presence check
            # makes repeated logout idempotent without hiding real delete errors.
            if backend.get_password(_SERVICE, provider) is not None:
                backend.delete_password(_SERVICE, provider)
        except Exception:
            raise _storage_error(provider) from None


def validated_base_url(environ: Mapping[str, str]) -> str:
    from fugu.config import BASE_URL_EU, BASE_URL_US

    value = environ.get("NEBIUS_BASE_URL", BASE_URL_EU)
    # Exact spelling excludes userinfo, ports, queries, fragments and other paths.
    allowed = {BASE_URL_EU.rstrip("/"): BASE_URL_EU, BASE_URL_US.rstrip("/"): BASE_URL_US}
    if value.rstrip("/") not in allowed or value.endswith("//"):
        raise CredentialError("CLI requests require the official EU or US HTTPS Token Factory endpoint.", "configuration")
    return allowed[value.rstrip("/")]


def _resolve_provider(environ: Mapping[str, str], store: SecretStore | None, provider: str) -> str:
    env_name = _env_name(provider)
    if env_name in environ:
        return environ[env_name].strip()
    if store is None:
        return ""
    try:
        return (store.get(provider) or "").strip()
    except Exception:
        raise _storage_error(provider) from None


def resolve_credentials(
    environ: Mapping[str, str], store: SecretStore | None,
    *, use_stored_tavily: bool = False,
) -> CredentialSet:
    base_url = validated_base_url(environ)
    return CredentialSet(
        nebius=_resolve_provider(environ, store, "nebius"),
        tavily=_resolve_provider(environ, store if use_stored_tavily else None, "tavily"),
        base_url=base_url,
    )


def credential_status(environ: Mapping[str, str], store: SecretStore | None) -> dict[str, Any]:
    base_url = validated_base_url(environ)
    providers = {}
    for provider, env_name in _ENV_NAMES.items():
        if env_name in environ:
            configured = bool(environ[env_name].strip())
            providers[provider] = {
                "configured": configured, "source": "environment",
                "disabled": not configured, "storage": "not_requested",
            }
            continue
        try:
            configured = bool(_resolve_provider(environ, store, provider))
            providers[provider] = {
                "configured": configured, "source": "keyring" if configured else "none",
                "disabled": False, "storage": "available" if store is not None else "unavailable",
            }
        except CredentialError:
            providers[provider] = {
                "configured": False, "source": "none", "disabled": False, "storage": "unavailable",
            }
    return {"providers": providers, "base_url": base_url}
