"""Local CLI entry and BYOK authentication commands.

Help/version parse without importing configuration, providers or native storage.
Audits delegate to the canonical engine after profile and consent preflight.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Sequence
import warnings

from fugu import __version__
from fugu.cli_output import CliError, error_report, redact, render_report


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
    audit = commands.add_parser("audit", help="Audit a local directory or public HTTPS Git source")
    audit.add_argument("source")
    audit.add_argument("--mode", choices=("full", "offline"), default="full")
    audit.add_argument("--format", choices=("text", "json"), default="text")
    audit.add_argument("--allow-hosted", action="store_true", help="Consent to provider data transfer and billing")
    audit.add_argument("--reputation", action="store_true", help="Require reputation; allow saved Tavily lookup")
    audit.add_argument("--detonate", action="store_true", help="Request isolated local Docker execution with fake canaries")
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


def _validate_audit_source(source: str, mode: str) -> None:
    from pathlib import Path
    from urllib.parse import urlsplit

    if mode not in {"full", "offline"}:
        raise CliError("usage", "Choose full or offline mode.")
    if not source.strip():
        raise CliError("intake", "Provide a source directory or public HTTPS Git URL.")
    # Existing local directories take precedence even if their name ends .git.
    if Path(source).expanduser().is_dir():
        return
    try:
        parts = urlsplit(source)
        remote = bool(parts.scheme or source.startswith("git@") or source.endswith(".git"))
        if remote and (mode == "offline" or parts.scheme != "https" or not parts.hostname
                       or parts.username is not None or parts.password is not None
                       or parts.query or parts.fragment):
            raise CliError("intake", "Use a local directory in offline mode, or a public HTTPS Git URL without credentials/query/fragment in full mode.")
    except ValueError:
        raise CliError("intake", "Invalid source URL.") from None


def _audit(args) -> int:
    from fugu.credentials import CredentialSet
    from fugu.cli_audit import run_cli_audit

    if args.mode == "offline" and (args.reputation or args.detonate):
        raise CliError("usage", "Offline mode excludes reputation and detonation; remove those flags.")
    _validate_audit_source(args.source, args.mode)
    keys = CredentialSet()
    if args.mode == "full":
        from fugu.credentials import NativeSecretStore, resolve_credentials
        needs_store = ("NEBIUS_API_KEY" not in os.environ or
                       (args.reputation and "TAVILY_API_KEY" not in os.environ))
        keys = resolve_credentials(os.environ, NativeSecretStore() if needs_store else None,
                                   use_stored_tavily=args.reputation)
        if not keys.nebius:
            raise CliError("credential", "Nebius is missing or explicitly disabled. Set NEBIUS_API_KEY or run fugu configure.")
        if args.reputation and not keys.tavily:
            raise CliError("credential", "Requested reputation needs TAVILY_API_KEY or a saved Tavily key; an empty environment override disables it.")
        print("Selected extension text/prompts go to Nebius for NVIDIA inference; usage is billed to your provider project.", file=sys.stderr)
        if keys.tavily:
            print("Reputation sends identifiers/search queries to Tavily and pinned-package lookups to OSV.", file=sys.stderr)
        if args.detonate:
            print("Detonation requests local Docker execution with fake canaries; coverage covers executed triggers only.", file=sys.stderr)
        if not args.allow_hosted:
            if not sys.stdin.isatty():
                raise CliError("consent", "Noninteractive full audits require --allow-hosted after reviewing provider data transfer and billing.")
            print("Allow these hosted data flows and billing? [y/N] ", end="", file=sys.stderr, flush=True)
            try:
                answer = sys.stdin.readline().strip().lower()
            except (EOFError, OSError):
                answer = ""
            if answer not in {"y", "yes"}:
                raise CliError("consent", "Hosted audit declined; no source intake or provider call was attempted.")
    report = run_cli_audit(args.source, args.mode, keys, detonate=args.detonate)
    sys.stdout.write(render_report(report, args.format, (keys.nebius, keys.tavily)))
    return report["exit_code"]


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # Preserve a single JSON envelope for parser errors as well as runtime
    # failures; parser diagnostics never echo unknown arguments.
    json_audit = bool(raw and raw[0] == "audit" and
                      ("--format=json" in raw or any(raw[i:i+2] == ["--format", "json"] for i in range(len(raw)))))
    args = None
    try:
        args = _parser().parse_args(raw)
        os.environ["FUGU_NO_DOTENV"] = "1"
        if args.command == "audit":
            return _audit(args)
        if args.command == "configure":
            return _configure(args.provider)
        if args.action == "status":
            return _status(args.verify)
        return _logout(args.provider)
    except CliError as error:
        return _command_error(error, args, json_audit)
    except KeyboardInterrupt:
        return _command_error(CliError("cancelled", "Cancelled; owned work was stopped."), args, json_audit)
    except Exception:
        return _command_error(CliError("configuration", "Command failed; check configuration or native storage. Private error detail withheld."), args, json_audit)


def _command_error(error: CliError, args, json_audit: bool) -> int:
    secrets = (os.environ.get("NEBIUS_API_KEY", ""), os.environ.get("TAVILY_API_KEY", ""))
    print(redact(f"{error.category}: {error}", secrets), file=sys.stderr)
    if json_audit or (args is not None and args.command == "audit"):
        source = args.source if args is not None else ""
        mode = args.mode if args is not None else "full"
        report = error_report(source, mode, error)
        sys.stdout.write(render_report(report, "json" if json_audit else args.format, secrets))
        return report["exit_code"]
    return 130 if error.category == "cancelled" else 2
