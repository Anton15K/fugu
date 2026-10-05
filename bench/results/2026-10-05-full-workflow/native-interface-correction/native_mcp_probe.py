"""Installed pinned MCP interface on an inert greeting with network denied/fake SDK.

This exercises native parsers/analyzers only. It never uses selected corpus
cases, starts an auditee server, or contacts a provider.
"""
import argparse
import asyncio
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace


def denied(*args, **kwargs):
    raise RuntimeError("network forbidden in inert native probe")


def main(output: Path):
    socket.socket.connect = denied
    socket.create_connection = denied
    socket.getaddrinfo = denied
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    from openai.types.chat import ChatCompletion
    from bench import competitive_scanners as scanners
    from bench.competitive_scanners import NativeRequestCounter, hosted_completion, run_native
    import mcpscanner.core.analyzers.static_analyzer as native
    expected = next(r["sha256"] for s in json.loads(Path(
        "bench/results/2026-10-05-full-workflow/source-pins.json").read_text())["sources"]
        if s["tool"] == "cisco-mcp" for r in s["source_files"]
        if r["path"] == "mcpscanner/core/analyzers/static_analyzer.py")
    assert hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest() == expected
    calls, invocations = [], []
    observe = scanners._observe
    def observe_context(analyzer, name, records, *, asynchronous):
        observe(analyzer, name, records, asynchronous=asynchronous)
        native_analyze = analyzer.analyze
        async def capture(content, context=None):
            invocations.append({"analyzer": name, "content_type": (context or {}).get("content_type"),
                "content_chars": len(content), "content_sha256": hashlib.sha256(content.encode()).hexdigest()})
            return await native_analyze(content, context)
        analyzer.analyze = capture
    scanners._observe = observe_context
    def create(**kwargs):
        calls.append({key: kwargs.get(key) for key in ("model", "max_tokens", "temperature", "timeout")})
        return ChatCompletion(id="inert-native-probe", model=kwargs["model"], created=0,
            object="chat.completion", choices=[{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps({"threat_analysis": {
                "malicious_content_detected": False, "primary_threats": []}})}}],
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
    sdk = SimpleNamespace(api_key="inert-fixture", base_url="https://example.invalid/v1/",
                          timeout=30, max_retries=0,
                          chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    async def exercise():
        with tempfile.TemporaryDirectory(prefix="inert-mcp-", dir=output.parent) as folder:
            target = Path(folder) / "greeting"
            target.mkdir()
            packet = {"tools": [{"name": "greet", "description": "Return a plain greeting.",
                      "inputSchema": {"type": "object", "properties": {
                          "name": {"type": "string", "description": "Name to greet."}}, "required": ["name"]}}]}
            (target / "tools.json").write_text(json.dumps(packet))
            with NativeRequestCounter(Path(folder) / "fake-counter", binding="0" * 64, limit=8) as counter:
                async with hosted_completion(counter, sdk, lock=asyncio.Lock(), run_id="inert-interface-probe",
                        scanner_id="cisco-mcp", context_id="greeting", model="fixture-model",
                        base_url=sdk.base_url) as completion:
                    result = await run_native("cisco-mcp", target, completion=completion,
                        llm_config={"model": "fixture-model", "api_key": sdk.api_key, "base_url": sdk.base_url})
                proof = {"scope": "inert installed native interface; not benchmark evidence",
                    "provider_calls": 0, "search_calls": 0, "target_execution": False,
                    "network": "denied", "fake_dispatches": len(calls), "native_parameters": calls,
                    "status": result["status"], "complete": result["complete"], "reasons": result["reasons"],
                    "per_analyzer": result["per_analyzer"], "observed_invocations": dict(Counter(
                        r["analyzer"] for r in result["per_analyzer"])),
                    "native_input_invocations": invocations,
                    "native_source": {"path": native.__file__, "sha256": expected}}
                output.write_text(json.dumps(proof, indent=2) + "\n")
                assert result["complete"], result["reasons"]
                assert proof["observed_invocations"] == {"YARA": 2, "LLM": 2}
                assert [(r["analyzer"], r["content_type"]) for r in invocations] == [
                    ("YARA", "description"), ("LLM", "description"),
                    ("YARA", "parameters"), ("LLM", "parameters")]
                assert len(calls) == 2 and counter.state["attempts"] == 2
                assert all((r["max_tokens"], r["temperature"], r["timeout"]) == (1000, 0.1, 30) for r in calls)
                print(json.dumps(proof))
    asyncio.run(exercise())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    main(parser.parse_args().output)
