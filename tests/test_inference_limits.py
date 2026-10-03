"""Regression tests for the bounded production inference profile."""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest

from fugu.config import DEFAULT_PRODUCTION_LIMITS, get_production_limits
from fugu.pipeline.stages.harness import CANARY_ENV_TOKEN, HarnessStage
from fugu.pipeline.stages.semantic import JudgeCall, SemanticStage, _chunks, _default_make_call
from fugu.types import AuditJob, JobStatus


def _target(tmp_path: Path, content: str = "ordinary skill") -> Path:
    target = tmp_path / "skill"
    target.mkdir()
    (target / "SKILL.md").write_text(content)
    return target


def _record(system: str, user: str, text: str) -> JudgeCall:
    return JudgeCall("fake/model", 0.01, len(system) + len(user), len(text), {})


def test_default_profile_is_immutable_and_serializable() -> None:
    profile = DEFAULT_PRODUCTION_LIMITS
    serialized = profile.to_dict()

    assert get_production_limits() is profile
    assert serialized["llm_max_output_tokens"] == 4096
    assert serialized["request_timeout_seconds"] == 90
    assert serialized["sdk_max_retries"] == 0
    assert serialized["semantic_max_units"] == 24
    assert serialized["semantic_max_chars_per_unit"] == 6000
    assert serialized["harness_mount_char_budget"] == 32000
    assert serialized["red_probe_count"] == 3
    assert serialized["red_probe_max_chars"] == 200
    assert serialized["source_max_entries"] == 20000
    assert serialized["source_max_bytes"] == 512 * 1024 * 1024
    assert serialized["git_clone_timeout_seconds"] == 120
    assert serialized["fanout_max_units"] == 24
    with pytest.raises(FrozenInstanceError):
        profile.semantic_max_units = 1  # type: ignore[misc]


def test_semantic_chunks_have_a_hard_limit_and_preserve_every_character() -> None:
    text = "x" * 12001 + "\r\nline one\n\nlast line"

    chunks = _chunks(text)

    assert chunks
    assert all(len(chunk) <= DEFAULT_PRODUCTION_LIMITS.semantic_max_chars_per_unit for chunk in chunks)
    assert "".join(chunks) == text
    assert chunks[0] == "x" * 6000


def test_semantic_default_limit_completes_24_units_and_reports_the_25th(tmp_path: Path) -> None:
    target = _target(tmp_path)
    for index in range(23):
        (target / f"{index:02}.md").write_text(f"unit {index}")
    (target / "24.md").write_text("unit 24")

    def judge(system: str, user: str):
        text = '{"findings": []}'
        return text, _record(system, user, text)

    result = asyncio.run(
        SemanticStage(make_call=judge).run(
            AuditJob(id="unit-cap", source=str(target), status=JobStatus.running), target
        )
    )

    assert result.metrics["units_total"] == 25
    assert result.metrics["units"] == 24
    assert result.metrics["units_completed"] == 24
    assert result.metrics["units_omitted"] == 1
    assert result.metrics["effective_limits"] == DEFAULT_PRODUCTION_LIMITS.to_dict()
    assert result.metrics["coverage_incomplete"]


def test_harness_caps_whole_packet_and_red_exposure_and_limits_generated_probes(tmp_path: Path) -> None:
    late_marker = "LATE_EVIDENCE_AFTER_4000_CHARS"
    content = "a" * 5000 + late_marker + "z" * 40000
    target = _target(tmp_path, content)
    seen: list[tuple[str, str]] = []

    def call(system: str, user: str):
        seen.append((system, user))
        if '"probes"' in system:
            text = json.dumps({"probes": [f"Generated probe {i}" for i in range(10)]})
        else:
            text = "A direct answer."
        return text, _record(system, user, text)

    job = AuditJob(id="red-cap", source=str(target), depth="full", status=JobStatus.running)
    result = asyncio.run(HarnessStage(make_call=call).run(job, target))

    assert result.metrics["mounted_chars"] <= DEFAULT_PRODUCTION_LIMITS.harness_mount_char_budget
    assert result.metrics["red_mounted_chars"] == result.metrics["mounted_chars"]
    assert result.metrics["red_mounted_chars"] > 4000
    assert late_marker in next(user for system, user in seen if '"probes"' in system)
    assert any(
        late_marker in system
        for system, _user in seen
        if "skill-instructions authoritative=true" in system
    )
    assert result.metrics["probes"] == 9
    assert result.metrics["red_probes_generated"] == 3
    assert result.metrics["red_probes_omitted"] == 7
    assert result.metrics["runs"] == 9
    assert len(seen) == 28  # one RED request plus three primary calls per probe
    assert result.metrics["coverage_incomplete"]
    assert result.metrics["effective_limits"] == DEFAULT_PRODUCTION_LIMITS.to_dict()


def test_skipped_oversized_file_is_explicit_partial_coverage_for_both_live_stages(tmp_path: Path) -> None:
    target = _target(tmp_path, "ordinary skill")
    (target / "oversized.txt").write_text("x" * (2_000_001))

    def judge(system: str, user: str):
        text = '{"findings": []}'
        return text, _record(system, user, text)

    semantic = asyncio.run(
        SemanticStage(make_call=judge).run(
            AuditJob(id="sem-omission", source=str(target), status=JobStatus.running), target
        )
    )
    harness = asyncio.run(
        HarnessStage(make_call=judge).run(
            AuditJob(id="harness-omission", source=str(target), status=JobStatus.running), target
        )
    )

    assert semantic.metrics["skipped_large"] == 1
    assert semantic.metrics["coverage_incomplete"]
    assert harness.metrics["file_collection"]["skipped_large"] == 1
    assert harness.metrics["coverage_incomplete"]
    assert CANARY_ENV_TOKEN not in harness.metrics.get("skipped", "")


def test_no_eligible_units_after_source_omission_cannot_look_like_a_clean_pass(tmp_path: Path) -> None:
    from fugu.verdict import aggregate_verdict

    target = tmp_path / "only-oversized"
    target.mkdir()
    (target / "large.txt").write_text("x" * 2_000_001)

    def fake(system: str, user: str):
        text = '{"findings": []}'
        return text, _record(system, user, text)

    semantic = asyncio.run(
        SemanticStage(make_call=fake).run(
            AuditJob(id="no-sem-units", source=str(target), status=JobStatus.running), target
        )
    )
    harness = asyncio.run(
        HarnessStage(make_call=fake).run(
            AuditJob(id="no-harness-packet", source=str(target), status=JobStatus.running), target
        )
    )

    assert not semantic.ok and semantic.metrics["coverage_incomplete"]
    assert not harness.ok and harness.metrics["coverage_incomplete"]
    assert aggregate_verdict([], [semantic, harness])["status"] == "warn"


def test_default_semantic_request_uses_profile_and_records_served_response_identity(monkeypatch) -> None:
    import fugu.config as config
    import fugu.client as client_module
    import fugu.model_router as router

    calls = []

    class Client:
        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(
                model="fake/served",
                choices=[SimpleNamespace(
                    message=SimpleNamespace(content='{"findings": []}'),
                    finish_reason="stop",
                )],
                usage=None,
            )

    client = Client()
    client.chat = SimpleNamespace(completions=SimpleNamespace(create=client.create))
    monkeypatch.setattr(config, "get_settings", lambda: SimpleNamespace(has_api_key=True))
    monkeypatch.setattr(client_module, "make_client", lambda settings, **kwargs: client)
    monkeypatch.setattr(router, "pick_model", lambda task="", tier="": "fake/requested")

    result_text, record = _default_make_call()("system", "user")  # type: ignore[misc]

    assert calls[0]["max_tokens"] == DEFAULT_PRODUCTION_LIMITS.llm_max_output_tokens == 4096
    assert calls[0]["temperature"] == 0.1
    assert record.requested_model == "fake/requested"
    assert record.served_model == "fake/served"
    assert record.max_tokens == 4096
    assert record.finish_reason == "stop"
    assert record.response_sha256 == hashlib.sha256(result_text.encode()).hexdigest()
    assert record.usage == {"prompt_tokens": None, "completion_tokens": None}


def test_failed_sdk_attempt_retains_safe_cap_latency_and_unknown_usage(monkeypatch) -> None:
    import fugu.config as config
    import fugu.client as client_module
    import fugu.model_router as router
    from fugu.pipeline.stages.semantic import InferenceCallError

    class Client:
        class Chat:
            class Completions:
                @staticmethod
                def create(**kwargs):
                    raise RuntimeError("provider diagnostic text")

            completions = Completions()

        chat = Chat()

    monkeypatch.setattr(config, "get_settings", lambda: SimpleNamespace(has_api_key=True))
    monkeypatch.setattr(client_module, "make_client", lambda settings, **kwargs: Client())
    monkeypatch.setattr(router, "pick_model", lambda task="", tier="": "fake/requested")

    call = _default_make_call()
    with pytest.raises(InferenceCallError) as error:
        call("system", "user")  # type: ignore[misc]

    assert error.value.attempt["requested_model"] == "fake/requested"
    assert error.value.attempt["served_model"] is None
    assert error.value.attempt["max_tokens"] == 4096
    assert error.value.attempt["latency_s"] is not None
    assert error.value.attempt["usage"] == {"prompt_tokens": None, "completion_tokens": None}
    assert "provider diagnostic text" not in str(error.value)


def test_default_semantic_red_ultra_and_super_sdk_requests_all_use_4096(tmp_path, monkeypatch) -> None:
    import fugu.config as config
    import fugu.client as client_module
    import fugu.model_router as router

    target = _target(tmp_path)
    requests = []

    class Client:
        def __init__(self):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **kwargs):
            requests.append(kwargs)
            system = kwargs["messages"][0]["content"]
            if '"probes"' in system:
                content = '{"probes": []}'
            elif "security reviewer" in system:
                content = '{"findings": []}'
            else:
                content = "A direct answer."
            model = "fake/super-served" if kwargs["model"] == "fake/super" else "fake/ultra-served"
            return SimpleNamespace(
                model=model,
                choices=[SimpleNamespace(
                    message=SimpleNamespace(content=content),
                    finish_reason="stop",
                )],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
            )

    client = Client()
    monkeypatch.setattr(config, "get_settings", lambda: SimpleNamespace(has_api_key=True))
    monkeypatch.setattr(client_module, "make_client", lambda settings, **kwargs: client)
    monkeypatch.setattr(
        router,
        "pick_model",
        lambda task="", tier="": "fake/super" if tier == "super" else "fake/ultra",
    )

    semantic = asyncio.run(
        SemanticStage().run(
            AuditJob(id="default-semantic", source=str(target), status=JobStatus.running),
            target,
        )
    )
    harness = asyncio.run(
        HarnessStage().run(
            AuditJob(id="default-harness", source=str(target), status=JobStatus.running),
            target,
        )
    )

    assert semantic.ok and harness.ok
    assert requests
    assert all(request["max_tokens"] == 4096 for request in requests)
    assert {request["model"] for request in requests} == {"fake/ultra", "fake/super"}
    assert any(request["messages"][0]["content"].startswith("You write benign user tasks") for request in requests)
    assert any("security reviewer" in request["messages"][0]["content"] for request in requests)
    assert any(request["model"] == "fake/super" for request in requests)


def test_assembly_does_not_construct_excluded_providers_or_forward_wrong_reputation_flag(
    tmp_path: Path, monkeypatch
) -> None:
    import builtins

    import fugu.pipeline.assemble as assemble

    original_import = builtins.__import__
    forbidden = {
        "fugu.pipeline.stages.reputation",
        "fugu.pipeline.stages.detonation_stage",
    }

    def guarded_import(name, *args, **kwargs):
        if name in forbidden:
            raise AssertionError(f"excluded provider was imported: {name}")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(
        assemble,
        "_make_detonation_driver",
        lambda: (_ for _ in ()).throw(AssertionError("excluded driver was constructed")),
    )
    stages = assemble.build_stages(
        include_detonation=False,
        include_semantic=False,
        include_harness=False,
        include_reputation=False,
    )
    assert [stage.name for stage in stages] == ["concealment", "static"]

    target = tmp_path / "local"
    target.mkdir()
    captured = {}
    monkeypatch.setattr(
        assemble,
        "build_stages",
        lambda **kwargs: captured.update(kwargs) or [],
    )

    assert assemble.run_audit(target, include_reputation=False) == []
    assert captured["include_reputation"] is False
