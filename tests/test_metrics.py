"""Tests for the Fugu eval harness: loader validation, metrics edge cases,
renderers, and the CLI selfcheck. Stdlib + pytest only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from eval.loader import ManifestError, Sample, fixtures_dir, load_corpus
from eval.metrics import category_metrics, to_console, to_markdown
from eval.run_eval import _selfcheck, load_results_file, main as run_main

# --- helpers -------------------------------------------------------------------


def make_sample(name: str, kind: str = "malicious", ids: list[str] | None = None) -> Sample:
    return Sample(
        path=Path(f"/corpus/{name}"),
        manifest={"name": name, "kind": kind, "expected_owasp_ids": ids or []},
    )


MAL_A = make_sample("mal-a", "malicious", ["LLM01", "MCP06"])
MAL_B = make_sample("mal-b", "malicious", ["MCP01", "LLM02"])
BEN_1 = make_sample("ben-1", "benign", [])
BEN_2 = make_sample("ben-2", "benign", [])
CORPUS = [MAL_A, MAL_B, BEN_1, BEN_2]


def perfect_predictions() -> dict[str, list[str]]:
    return {
        "mal-a": ["LLM01", "MCP06"],
        "mal-b": ["MCP01", "LLM02"],
        "ben-1": [],
        "ben-2": [],
    }


# --- loader ----------------------------------------------------------------------


def test_load_fixtures_corpus() -> None:
    samples, warnings = load_corpus(fixtures_dir())
    assert len(samples) == 4
    assert warnings == []  # fixtures are clean by construction
    kinds = {s.kind for s in samples}
    assert kinds == {"malicious", "benign"}
    labeled = [s for s in samples if s.expected_ids]
    assert len(labeled) == 2  # both malicious samples carry expected ids
    assert all(s.kind == "malicious" for s in labeled)
    # samples sorted deterministically
    assert [s.name for s in samples] == sorted(s.name for s in samples)


def test_loader_roundtrip_in_tmp(tmp_path: Path) -> None:
    (tmp_path / "s1").mkdir()
    (tmp_path / "s1" / "manifest.json").write_text(
        json.dumps({"name": "s1", "kind": "malicious", "expected_owasp_ids": ["MCP05"]})
    )
    (tmp_path / "s1" / "payload.txt").write_text("x")
    (tmp_path / "not_a_sample.txt").write_text("ignored: files are not samples")
    samples, warnings = load_corpus(tmp_path)
    assert len(samples) == 1
    assert samples[0].name == "s1"
    assert samples[0].expected_ids == ["MCP05"]
    assert samples[0].path == (tmp_path / "s1").resolve()
    assert warnings == []


def test_loader_unknown_id_warns_not_raises(tmp_path: Path) -> None:
    (tmp_path / "weird").mkdir()
    (tmp_path / "weird" / "manifest.json").write_text(
        json.dumps({"name": "weird", "kind": "malicious", "expected_owasp_ids": ["CVE-1234"]})
    )
    samples, warnings = load_corpus(tmp_path)
    assert len(samples) == 1
    assert samples[0].expected_ids == ["CVE-1234"]  # kept, not dropped
    assert any("CVE-1234" in w for w in warnings)
    assert any("OWASP_IDS" in w for w in warnings)


def test_loader_structural_errors(tmp_path: Path) -> None:
    def load_isolated(manifest: object, expected_match: str) -> None:
        # fresh dir per case so earlier bad manifests don't leak in
        import shutil

        solo = tmp_path / "solo"
        if solo.exists():
            shutil.rmtree(solo)
        solo.mkdir()
        (solo / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(ManifestError, match=expected_match):
            load_corpus(tmp_path)

    load_isolated({"kind": "malicious", "expected_owasp_ids": []}, "name")
    load_isolated({"name": "", "kind": "benign", "expected_owasp_ids": []}, "name")
    load_isolated({"name": "x", "expected_owasp_ids": []}, "kind")
    load_isolated({"name": "x", "kind": "benign", "expected_owasp_ids": "MCP01"}, "list of strings")
    load_isolated({"name": "x", "kind": "benign", "expected_owasp_ids": [1, 2]}, "list of strings")
    load_isolated(["not", "an", "object"], "JSON object")

    # duplicate names raise (prediction keys are names)
    (tmp_path / "dup1").mkdir()
    (tmp_path / "dup1" / "manifest.json").write_text(
        json.dumps({"name": "dup", "kind": "benign", "expected_owasp_ids": []})
    )
    (tmp_path / "dup2").mkdir()
    (tmp_path / "dup2" / "manifest.json").write_text(
        json.dumps({"name": "dup", "kind": "benign", "expected_owasp_ids": []})
    )
    with pytest.raises(ManifestError, match="duplicate"):
        load_corpus(tmp_path)


def test_loader_bad_json_and_missing_manifest(tmp_path: Path) -> None:
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "manifest.json").write_text("{not json")
    with pytest.raises(ManifestError, match="cannot parse"):
        load_corpus(tmp_path)

    fresh = tmp_path / "phase2"
    fresh.mkdir()
    (fresh / "empty-dir").mkdir()
    samples, warnings = load_corpus(fresh)
    assert samples == []
    assert any("no manifest.json" in w for w in warnings)


def test_loader_semantic_warnings(tmp_path: Path) -> None:
    (tmp_path / "w1").mkdir()
    (tmp_path / "w1" / "manifest.json").write_text(
        json.dumps({"name": "w1", "kind": "malicious", "expected_owasp_ids": []})
    )
    (tmp_path / "w2").mkdir()
    (tmp_path / "w2" / "manifest.json").write_text(
        json.dumps({"name": "w2", "kind": "benign", "expected_owasp_ids": ["MCP08"]})
    )
    (tmp_path / "w3").mkdir()
    (tmp_path / "w3" / "manifest.json").write_text(
        json.dumps({"name": "w3", "kind": "malicious", "expected_owasp_ids": ["LLM01", "LLM01"]})
    )
    samples, warnings = load_corpus(tmp_path)
    assert len(samples) == 3
    assert any("kind=malicious but expected_owasp_ids is empty" in w for w in warnings)
    assert any("kind=benign but expected" in w for w in warnings)
    assert any("duplicate ids" in w for w in warnings)
    # duplicate ids are de-duplicated in expected_ids
    assert next(s for s in samples if s.name == "w3").expected_ids == ["LLM01"]


def test_loader_missing_dir_raises() -> None:
    with pytest.raises(ManifestError, match="not found"):
        load_corpus("/nonexistent/fugu-corpus")


# --- metrics: perfect ------------------------------------------------------------


def test_perfect_predictions() -> None:
    report = category_metrics(CORPUS, perfect_predictions())
    assert report["micro"] == {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    assert report["macro"] == {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    assert report["benign_fp"]["rate"] == 0.0
    assert report["benign_fp"]["flagged"] == 0
    assert report["confusion_pairs"] == []
    assert report["unmatched_prediction_keys"] == []
    assert report["unknown_predicted_ids"] == {}
    assert report["n_samples"] == 4 and report["n_malicious"] == 2 and report["n_benign"] == 2
    for m in report["per_id"]:
        assert m["tp"] == 1 and m["fp"] == 0 and m["fn"] == 0 and m["support"] == 1


# --- metrics: partial ------------------------------------------------------------


def test_partial_prediction() -> None:
    preds = {
        "mal-a": ["LLM01", "MCP05"],   # missed MCP06, extra MCP05 on same sample
        "mal-b": ["MCP01", "LLM02"],
        "ben-1": [],
        "ben-2": [],
    }
    report = category_metrics(CORPUS, preds)
    # micro: tp=3, fp=1, fn=1 -> P=0.75 R=0.75 F1=0.75
    assert report["micro"]["precision"] == pytest.approx(0.75)
    assert report["micro"]["recall"] == pytest.approx(0.75)
    assert report["micro"]["f1"] == pytest.approx(0.75)
    # confusion: predicted MCP05 where MCP06 was expected, on mal-a
    assert report["confusion_pairs"] == [{"predicted": "MCP05", "expected": "MCP06", "count": 1}]
    mcp06 = next(m for m in report["per_id"] if m["owasp_id"] == "MCP06")
    assert (mcp06["tp"], mcp06["fp"], mcp06["fn"]) == (0, 0, 1)
    mcp05 = next(m for m in report["per_id"] if m["owasp_id"] == "MCP05")
    assert (mcp05["tp"], mcp05["fp"], mcp05["fn"], mcp05["support"]) == (0, 1, 0, 0)


def test_missing_sample_in_predictions_counts_as_no_findings() -> None:
    report = category_metrics(CORPUS, {"mal-a": ["LLM01", "MCP06"]})
    # mal-b entirely un-predicted: recall damage only
    assert report["micro"]["precision"] == 1.0
    assert report["micro"]["recall"] == 0.5
    assert report["n_samples_with_predictions"] == 1


# --- metrics: benign FP ----------------------------------------------------------


def test_benign_false_positive() -> None:
    preds = dict(perfect_predictions())
    preds["ben-1"] = ["MCP03"]
    report = category_metrics(CORPUS, preds)
    assert report["benign_fp"]["rate"] == 0.5
    assert report["benign_fp"]["flagged"] == 1
    assert report["benign_fp"]["total_benign"] == 2
    assert report["benign_fp"]["offending"] == [{"sample": "ben-1", "ids": ["MCP03"]}]
    # the FP also hits precision of MCP03
    mcp03 = next(m for m in report["per_id"] if m["owasp_id"] == "MCP03")
    assert (mcp03["tp"], mcp03["fp"], mcp03["support"]) == (0, 1, 0)
    assert mcp03["precision"] == 0.0
    # benign FP is NOT a confusion pair
    assert report["confusion_pairs"] == []


def test_benign_fp_rate_zero_when_no_benign_samples() -> None:
    report = category_metrics([MAL_A], {"mal-a": ["LLM01"]})
    assert report["benign_fp"] == {
        "total_benign": 0,
        "flagged": 0,
        "rate": 0.0,
        "offending": [],
    }


# --- metrics: empty / degenerate ---------------------------------------------------


def test_empty_predictions_everywhere() -> None:
    report = category_metrics(CORPUS, {})
    assert report["micro"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    assert report["macro"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    assert report["per_id"] != []  # expected ids still listed with fn counts
    assert all(m["tp"] == 0 and m["fn"] == m["support"] for m in report["per_id"])
    assert report["n_samples_with_predictions"] == 0
    assert report["confusion_pairs"] == []


def test_all_empty_lists_predictions() -> None:
    report = category_metrics(CORPUS, {s.name: [] for s in CORPUS})
    assert report["micro"]["f1"] == 0.0
    assert report["benign_fp"]["rate"] == 0.0  # empty list = no findings, not an FP


def test_empty_corpus_and_predictions() -> None:
    report = category_metrics([], {})
    assert report["n_samples"] == 0
    assert report["micro"]["f1"] == 0.0
    assert report["macro"]["f1"] == 0.0
    assert report["per_id"] == []
    assert report["benign_fp"]["rate"] == 0.0
    # renderers must still work on the degenerate report
    assert "none" in to_markdown(report).lower()
    assert "FUGU EVAL REPORT" in to_console(report)


def test_unknown_predicted_ids() -> None:
    report = category_metrics(CORPUS, {"mal-a": ["MCP99", "LLM01", "MCP06"],
                                        "ben-1": ["TOTALLY-MADE-UP"]})
    assert report["unknown_predicted_ids"] == {"MCP99": 1, "TOTALLY-MADE-UP": 1}
    # unknown ids are still scored (FP against expected LLM01/MCP06)
    mcp99 = next(m for m in report["per_id"] if m["owasp_id"] == "MCP99")
    assert mcp99["fp"] == 1
    # ben-1 flagged by an unknown id still counts as benign-FP
    assert report["benign_fp"]["flagged"] == 1


def test_unmatched_prediction_keys_reported() -> None:
    report = category_metrics(CORPUS, {"no-such-sample": ["MCP01"]})
    assert report["unmatched_prediction_keys"] == ["no-such-sample"]
    # and it did not pollute scoring of real samples
    assert report["micro"]["precision"] == 0.0
    assert all(m["owasp_id"] != "MCP01" or m["fp"] == 0 for m in report["per_id"])


# --- metrics: multi-label overlap -------------------------------------------------


def test_multilabel_overlap_partial_credit() -> None:
    # mal-a expects {LLM01, MCP06}; we predict overlapping {LLM01, MCP03}
    report = category_metrics([MAL_A], {"mal-a": ["LLM01", "MCP03"]})
    llm01 = next(m for m in report["per_id"] if m["owasp_id"] == "LLM01")
    assert (llm01["tp"], llm01["fp"], llm01["fn"]) == (1, 0, 0)
    mcp03 = next(m for m in report["per_id"] if m["owasp_id"] == "MCP03")
    assert (mcp03["tp"], mcp03["fp"], mcp03["fn"]) == (0, 1, 0)
    mcp06 = next(m for m in report["per_id"] if m["owasp_id"] == "MCP06")
    assert (mcp06["tp"], mcp06["fp"], mcp06["fn"]) == (0, 0, 1)
    # overlap cross-product: MCP03->MCP06
    assert report["confusion_pairs"] == [{"predicted": "MCP03", "expected": "MCP06", "count": 1}]
    # tp=1 fp=1 fn=1 -> micro P=R=F1=0.5
    assert report["micro"]["f1"] == pytest.approx(0.5)


def test_duplicate_predicted_ids_dont_double_count() -> None:
    report = category_metrics([MAL_A], {"mal-a": ["LLM01", "LLM01", "MCP06", "MCP06"]})
    assert report["micro"] == {"precision": 1.0, "recall": 1.0, "f1": 1.0}


def test_swapped_labels_generate_symmetric_confusions() -> None:
    two = [make_sample("a", "malicious", ["MCP03"]), make_sample("b", "malicious", ["MCP06"])]
    report = category_metrics(two, {"a": ["MCP06"], "b": ["MCP03"]})
    pairs = {(p["predicted"], p["expected"]): p["count"] for p in report["confusion_pairs"]}
    assert pairs == {("MCP06", "MCP03"): 1, ("MCP03", "MCP06"): 1}
    assert report["micro"]["f1"] == 0.0
    assert report["micro"]["precision"] == 0.0  # wrong on every count


def test_macro_vs_micro_diverge_on_rare_category() -> None:
    # 10 samples of LLM01 all caught + 1 rare MCP07 missed
    many = [make_sample(f"m{i}", "malicious", ["LLM01"]) for i in range(10)]
    many.append(make_sample("rare", "malicious", ["MCP07"]))
    preds = {f"m{i}": ["LLM01"] for i in range(10)}
    report = category_metrics(many, preds)
    assert report["micro"]["f1"] == pytest.approx(2 * 10 / (2 * 10 + 1), abs=1e-3)
    assert report["macro"]["f1"] == pytest.approx(0.5, abs=1e-3)  # 1.0 + 0.0 over 2 ids


# --- renderers --------------------------------------------------------------------


def test_markdown_rendering_smoke() -> None:
    md = to_markdown(category_metrics(CORPUS, perfect_predictions()))
    assert md.startswith("## Fugu eval report")
    assert "| OWASP id | precision | recall | F1 | tp | fp | fn | support |" in md
    assert "| LLM01 | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | 1 |" in md
    assert "### Confusion pairs (predicted → expected)" in md
    assert "_none_" in md  # no confusion pairs section placeholder
    assert "0.000" in md  # benign-FP rate
    assert "## Fugu eval report" in to_markdown(category_metrics([], {}))  # degenerate ok


def test_markdown_rendering_with_everything_populated() -> None:
    preds = {
        "mal-a": ["MCP99", "LLM01"],
        "mal-b": ["MCP05"],
        "ben-1": ["MCP03"],
        "ghost": ["MCP01"],
    }
    md = to_markdown(category_metrics(CORPUS, preds))
    assert "unmatched prediction keys" in md
    assert "MCP99×1" in md            # unknown id with multiplicity
    assert "| MCP05 |" in md          # wrong-only id row present
    assert "`ben-1`" in md            # benign offender listed
    assert md.count("|---|") >= 2     # tables well-formed


def test_console_rendering_smoke() -> None:
    text = to_console(category_metrics(CORPUS, perfect_predictions()))
    assert "FUGU EVAL REPORT" in text
    assert "micro: P=1.000 R=1.000 F1=1.000" in text
    assert "benign-FP rate: 0.000 (0/2)" in text
    assert "confusion pairs: none" in text
    assert "LLM01" in text


def test_report_json_serializable() -> None:
    report = category_metrics(CORPUS, {"mal-a": ["MCP99"], "ghost": ["MCP01"]})
    dumped = json.dumps(report)  # must not raise
    reloaded = json.loads(dumped)
    assert reloaded["micro"]["f1"] == report["micro"]["f1"]


# --- results file loading -----------------------------------------------------------


def test_load_results_file_wrapped_and_bare(tmp_path: Path) -> None:
    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"provenance": "smoke", "predictions": {"mal-a": ["LLM01"]}}))
    assert load_results_file(wrapped) == {"mal-a": ["LLM01"]}

    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps({"mal-a": ["LLM01"], "ben-1": []}))
    assert load_results_file(bare) == {"mal-a": ["LLM01"], "ben-1": []}


def test_load_results_file_rejects_bad_shapes(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"mal-a": "LLM01"}))  # str not list
    with pytest.raises(SystemExit, match="list of owasp id"):
        load_results_file(bad)

    not_json = tmp_path / "nj.json"
    not_json.write_text("nope{")
    with pytest.raises(SystemExit, match="not valid JSON"):
        load_results_file(not_json)

    with pytest.raises(SystemExit, match="not found"):
        load_results_file(tmp_path / "missing.json")


# --- CLI end-to-end -----------------------------------------------------------------


def test_selfcheck_function_passes() -> None:
    # _selfcheck prints tables and returns 0 on success (used by --selfcheck)
    assert _selfcheck() == 0


def test_cli_selfcheck_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_main(["--selfcheck"]) == 0
    out = capsys.readouterr().out
    assert "selfcheck OK: perfect -> F1 1.0, garbage -> F1 0.0" in out


def test_cli_end_to_end_with_results_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"predictions": {
        "hidden-unicode-instructions": ["LLM01", "MCP06"],
        "env-harvest-install": ["MCP01", "LLM02"],
        "clean-pdf-skill": [],
        "clean-table-formatter": [],
    }}))
    md_out = tmp_path / "report.md"
    rc = run_main(["--fixtures", "--results", str(results), "--markdown", str(md_out)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "FUGU EVAL REPORT" in out
    assert "F1=1.000" in out
    assert md_out.is_file()
    assert "## Fugu eval report" in md_out.read_text()


def test_cli_missing_corpus_falls_back_to_fixtures(capsys: pytest.CaptureFixture[str]) -> None:
    # With the landed pipeline, no --results means a LIVE static run over the
    # fallback fixtures: must print a real report and exit 0 (no detonation
    # by default — Docker stays out of unit tests).
    rc = run_main(["--corpus", "/nonexistent/corpus"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "using built-in fixtures" in captured.err
    assert "FUGU EVAL REPORT" in captured.out


def test_cli_corrupt_manifest_exits_2(tmp_path: Path) -> None:
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "manifest.json").write_text("{oops")
    assert run_main(["--corpus", str(tmp_path)]) == 2
