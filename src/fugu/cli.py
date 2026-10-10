"""Local CLI entry and BYOK authentication commands.

Help/version parse without importing configuration, providers or native storage.
Audit dispatch is added by the separate canonical-audit phase.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Sequence
import warnings

from fugu import __version__
from fugu.cli_output import CliError, redact


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse diagnostics can otherwise echo an unknown secret argument.
        raise CliError("usage", "Invalid command or option. Run fugu --help for usage.")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="fugu", description="Audit before install; local BYOK CLI.")
    parser.add_argument("--version", action="version", version=f"fugu {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    configure = commands.add_parser("configure", help="Store a provider key in approved native storage")
    configure.add_argument("--provider", choices=("nebius", "tavily"), default="nebius")
    auth = commands.add_parser("auth", help="Inspect or remove Fugu credentials")
    actions = auth.add_subparsers(dest="action", required=True)
    status = actions.add_parser("status", help="Show credential presence, never key values")
    status.add_argument("--verify", action="store_true", help="One bounded Nebius catalog request; no inference")
    logout = actions.add_parser("logout", help="Remove only Fugu's stored provider entries")
    logout.add_argument("--provider", choices=("nebius", "tavily", "all"), default="all")
    return parser


def _configure(provider: str) -> int:
    from fugu.credentials import CredentialError, NativeSecretStore

    env_name = "NEBIUS_API_KEY" if provider == "nebius" else "TAVILY_API_KEY"
    if not sys.stdin.isatty():
        raise CredentialError(f"Configure requires an interactive hidden prompt. Use {env_name} for CI/headless use.")
    if provider == "nebius":
        print("Nebius receives selected extension text/prompts for NVIDIA inference; usage is billed to your provider project.", file=sys.stderr)
    else:
        print("Tavily receives extension identifier/search queries when reputation is enabled.", file=sys.stderr)
    print("The key will be saved only in approved native OS credential storage, under Fugu's entry.", file=sys.stderr)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("Provider API key (empty cancels): ", stream=sys.stderr).strip()
    except (EOFError, getpass.GetPassWarning):
        raise CredentialError(f"Hidden credential input is unavailable. Use {env_name} in your environment.") from None
    if not value:
        print("Configuration cancelled; storage unchanged.", file=sys.stderr)
        return 0
    NativeSecretStore().set(provider, value)
    print(f"Stored {provider} credential in Fugu's approved native entry.")
    return 0


def _verify_nebius(keys) -> None:
    from fugu.credentials import CredentialError
    from openai import DefaultHttpxClient, OpenAI

    if not keys.nebius:
        raise CredentialError("Nebius is not configured or is explicitly disabled. Set NEBIUS_API_KEY or run fugu configure.")
    try:
        # Suppress every redirect, including cross-host redirects, and SDK retries.
        # Read only the first catalog page: pagination would make extra requests.
        with DefaultHttpxClient(timeout=10.0, follow_redirects=False) as transport:
            with OpenAI(api_key=keys.nebius, base_url=keys.base_url,
                        max_retries=0, timeout=10.0, http_client=transport) as client:
                catalog = client.models.list()
                if not isinstance(getattr(catalog, "data", None), list):
                    raise ValueError("catalog data unavailable")
    except Exception:
        raise CredentialError("Nebius authentication/catalog verification failed; check your key and endpoint. No stored-key fallback or inference was attempted.") from None


def _status(verify: bool) -> int:
    from fugu.credentials import NativeSecretStore, credential_status, resolve_credentials

    if verify:
        keys = resolve_credentials(os.environ, NativeSecretStore())
        _verify_nebius(keys)
        # Catalog verification resolves only Nebius. Optional Tavily storage is
        # never queried as a side effect of this command.
        report = credential_status(os.environ, None)
        if "NEBIUS_API_KEY" not in os.environ:
            report["providers"]["nebius"].update(configured=True, source="keyring", storage="available")
        for provider in report["providers"]:
            env_name = "NEBIUS_API_KEY" if provider == "nebius" else "TAVILY_API_KEY"
            if env_name not in os.environ and provider == "tavily":
                report["providers"][provider]["storage"] = "not_requested"
    else:
        report = credential_status(os.environ, NativeSecretStore())
    for provider, status in report["providers"].items():
        state = "disabled" if status["disabled"] else "configured" if status["configured"] else "missing"
        print(f"{provider}: {state}; source={status['source']}; storage={status['storage']}")
    print(f"Nebius endpoint: {report['base_url']}")
    if verify:
        print("Nebius authentication/catalog reachable; not inference, model execution or a credits/billing check.")
    return 0


def _logout(provider: str) -> int:
    from fugu.credentials import NativeSecretStore

    selected = ("nebius", "tavily") if provider == "all" else (provider,)
    store = NativeSecretStore()
    for selected_provider in selected:
        store.delete(selected_provider)
        print(f"Removed Fugu's stored {selected_provider} credential (if present); provider key not revoked.")
        env_name = "NEBIUS_API_KEY" if selected_provider == "nebius" else "TAVILY_API_KEY"
        if os.environ.get(env_name, "").strip():
            print(f"{env_name} remains effective in the environment; logout does not edit it.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        # Must precede the first import of config.py or an engine/provider module.
        os.environ["FUGU_NO_DOTENV"] = "1"
        if args.command == "configure":
            return _configure(args.provider)
        if args.action == "status":
            return _status(args.verify)
        return _logout(args.provider)
    except CliError as error:
        # Error messages are authored categories; never render backend/SDK bodies.
        secrets = (os.environ.get("NEBIUS_API_KEY", ""), os.environ.get("TAVILY_API_KEY", ""))
        print(redact(f"{error.category}: {error}", secrets), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except Exception:
        print("configuration: Command failed; check configuration or native storage. No private error detail is displayed.", file=sys.stderr)
        return 2
