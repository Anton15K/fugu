"""CLI for the Fugu eval harness.

Score a predictions file against a labeled corpus:

    uv run --no-sync python -m eval.run_eval --corpus corpus/ --results results.json

If ``--corpus`` is omitted or the directory does not exist, the built-in
fixtures corpus (``eval/fixtures/``) is used so the harness always runs.
If ``--results`` is omitted, predictions are produced by the real fugu
pipeline if its stages are importable (they may not exist yet — the
import is behind try/except and failure falls back to a clear error).

``--selfcheck`` ignores corpus/results entirely: it builds synthetic
predictions against the fixtures corpus and asserts the metrics contract
(perfect predictions → micro/macro F1 = 1.0, garbage → 0.0, benign-FP
behaves), printing the tables as an executable sanity proof. Exits 1 if
any expectation fails.

results.json schema (documented in eval/README.md):

    {
      "provenance": "optional string — how predictions were produced",
      "predictions": {
        "<sample_name>": ["MCP01", "LLM01", ...],
        ...
      }
    }

A bare ``{"name": [...]}`` mapping (no ``predictions`` wrapper, no
provenance) is accepted too, for hand-written smoke files.

``--sets DIR`` switches to composition-set mode (S6, contracts §5): DIR
is a root of ``<set-name>/set.json`` specs loaded via
``eval.loader.load_set_specs``; ``--results`` must point at a sets
predictions JSON of shape ``{"sets": [{"set": name, "trifecta": bool,
"shadowing": bool}, ...]}``. The mode prints a markdown table of per-set
verdicts plus set_detection_rate / set_fp_rate and the advisory-tier
caveat. Composition metrics are reported SEPARATELY from per-extension
metrics and never merged into them (strategy-arxiv-drift D2). ``--sets``
cannot be combined with ``--corpus``/``--fixtures``/``--selfcheck``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from eval.loader import (
    ManifestError,
    Sample,
    SetSpecError,
    fixtures_dir,
    load_corpus,
    load_set_specs,
)
from eval.metrics import (
    MetricsReport,
    category_metrics,
    set_metrics,
    sets_to_markdown,
    to_console,
    to_markdown,
)

DEFAULT_CORPUS = _PROJECT_ROOT / "corpus"

# Any id we allow the selfcheck garbage run to use (deliberately outside
# the taxonomy to also exercise the unknown-id path).
_GARBAGE_ID = "MCP99"


# --- predictions sources --------------------------------------------------------

def load_results_file(path: str | Path) -> dict[str, list[str]]:
    """Parse results.json into a name -> ids mapping.

    Accepts both the wrapped form ({"provenance": ..., "predictions":
    {...}}) and a bare mapping. Non-string values raise SystemExit with
    a pointed message rather than a stack trace.
    """
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f"error: results file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {p} is not valid JSON: {exc}") from exc

    if isinstance(data, dict) and isinstance(data.get("predictions"), dict):
        raw = data["predictions"]
    elif isinstance(data, dict):
        raw = data
    else:
        raise SystemExit(f"error: {p} must be a JSON object mapping sample name -> [owasp_ids]")

    predictions: dict[str, list[str]] = {}
    for name, ids in raw.items():
        if isinstance(ids, str) or not isinstance(ids, (list, tuple)):
            raise SystemExit(
                f"error: {p}: predictions[{name!r}] must be a list of owasp id strings, "
                f"got {type(ids).__name__}"
            )
        predictions[str(name)] = [str(i) for i in ids]
    return predictions


def collect_pipeline_predictions(
    samples: list[Sample], detonate: bool = False
) -> dict[str, list[str]]:
    """Run the real fugu pipeline over each sample via the pinned entrypoint.

    Stable contract (lead-blessed): ``fugu.pipeline.run_audit(target, include_detonation)``.
    Detonation is opt-in (--detonate) because it needs Docker and minutes,
    not milliseconds; the default is the fast static pass (S0+S1).
    """
    try:
        from fugu.pipeline import run_audit
    except ImportError as exc:  # pragma: no cover - would be a broken install
        raise SystemExit(
            f"error: fugu.pipeline.run_audit is not importable ({exc}). "
            "Fix the install, or hand-write a results.json (schema in eval/README.md)."
        ) from exc

    predictions: dict[str, list[str]] = {}
    for sample in samples:
        try:
            findings = run_audit(
                sample.path,
                include_detonation=detonate,
                include_semantic=detonate,  # all live stages (LLM + sandbox) are opt-in
                include_harness=detonate,
            )
        except Exception as exc:  # stages must not kill the harness
            print(f"warning: run_audit failed on {sample.name}: {exc}", file=sys.stderr)
            predictions[sample.name] = []
            continue
        ids: list[str] = []
        for finding in findings or []:
            ids.extend(getattr(finding, "owasp_ids", []) or [])
        predictions[sample.name] = list(dict.fromkeys(ids))
    return predictions


# --- selfcheck --------------------------------------------------------------------

def _fixtures_samples() -> list[Sample]:
    samples, warnings = load_corpus(fixtures_dir())
    for warning in warnings:
        print(f"fixtures warning: {warning}", file=sys.stderr)
    if len(samples) < 4:
        raise SystemExit(f"selfcheck: expected >=4 fixtures, found {len(samples)}")
    return samples


def _selfcheck() -> int:
    samples = _fixtures_samples()
    failures: list[str] = []

    print("=== selfcheck: fixtures corpus ===")
    print(to_console(category_metrics(samples, {})))

    # 1. Perfect predictions: exact expected ids on malicious, none on benign.
    perfect = {s.name: list(s.expected_ids) for s in samples}
    perfect_report = category_metrics(samples, perfect)
    _expect(failures, "perfect micro F1 == 1.0", perfect_report["micro"]["f1"] == 1.0)
    _expect(failures, "perfect macro F1 == 1.0", perfect_report["macro"]["f1"] == 1.0)
    _expect(failures, "perfect precision == 1.0", perfect_report["micro"]["precision"] == 1.0)
    _expect(failures, "perfect benign-FP rate == 0.0", perfect_report["benign_fp"]["rate"] == 0.0)
    _expect(failures, "perfect has no confusion pairs", not perfect_report["confusion_pairs"])
    print("=== selfcheck: perfect predictions (expect F1 1.0) ===")
    print(to_console(perfect_report))

    # 2. Garbage predictions: unknown id on every malicious sample, none on
    #    benign (so the 0.0 comes from wrong labels, not from benign noise).
    garbage = {
        s.name: ([_GARBAGE_ID] if s.kind == "malicious" else [])
        for s in samples
    }
    garbage_report = category_metrics(samples, garbage)
    _expect(failures, "garbage micro F1 == 0.0", garbage_report["micro"]["f1"] == 0.0)
    _expect(failures, "garbage macro F1 == 0.0", garbage_report["macro"]["f1"] == 0.0)
    _expect(failures, "garbage recall == 0.0", garbage_report["micro"]["recall"] == 0.0)
    _expect(
        failures,
        "garbage records the unknown id",
        garbage_report["unknown_predicted_ids"].get(_GARBAGE_ID, 0)
        == garbage_report["n_malicious"],
    )
    print("=== selfcheck: garbage predictions (expect F1 0.0) ===")
    print(to_console(garbage_report))

    # 3. Benign-FP path: flag a benign sample, rate must move.
    benign_names = [s.name for s in samples if s.kind == "benign"]
    if benign_names:
        fp_report = category_metrics(samples, {benign_names[0]: ["MCP03"]})
        _expect(failures, "benign-FP rate == 0.5 with one of two flagged", fp_report["benign_fp"]["rate"] == 0.5)
        _expect(failures, "benign-FP offending lists the sample", [o["sample"] for o in fp_report["benign_fp"]["offending"]] == [benign_names[0]])
    else:
        failures.append("fixtures contain no benign sample to exercise benign-FP")

    if failures:
        print("\nSELFCHECK FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("\nselfcheck OK: perfect -> F1 1.0, garbage -> F1 0.0, benign-FP path exercised.")
    return 0


def _expect(failures: list[str], label: str, condition: bool) -> None:
    status = "ok  " if condition else "FAIL"
    print(f"[selfcheck] {status} {label}")


def _print_report(report: MetricsReport, markdown_out: str | None) -> None:
    if markdown_out:
        Path(markdown_out).write_text(to_markdown(report) + "\n", encoding="utf-8")
        print(f"markdown report written to {markdown_out}")
    print(to_console(report))


# --- sets-mode helpers --------------------------------------------------------------


def load_sets_results_file(path: str | Path) -> list[dict[str, object]]:
    """Parse a sets predictions JSON (``{"sets": [{...}]}``) into rows.

    Shape per contracts §5: ``{"sets": [{"set": name, "trifecta": bool,
    "shadowing": bool}, ...]}``. Raises SystemExit with a pointed message
    on structural violations rather than a stack trace.
    """
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f"error: sets results file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {p} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("sets"), list):
        raise SystemExit(
            f"error: {p} must be a JSON object of shape "
            f'{{"sets": [{{"set": name, "trifecta": bool, "shadowing": bool}}, ...]}}'
        )
    return data["sets"]


def _run_sets_mode(sets_dir: str, results_path: str | None, markdown_out: str | None) -> int:
    """Score composition-set predictions; return a process exit code."""
    try:
        specs = load_set_specs(sets_dir)
    except SetSpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not specs:
        print(f"error: no sets found under {sets_dir} (expected <set>/set.json)", file=sys.stderr)
        return 2

    if results_path:
        try:
            results = load_sets_results_file(results_path)
        except SystemExit:
            raise
        provenance = str(results_path)
    else:
        print(
            "error: --sets requires --results with a sets predictions JSON "
            '(shape {"sets": [...]}; schema in eval/README.md)',
            file=sys.stderr,
        )
        return 2

    try:
        report = set_metrics(results, specs)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"# provenance: {provenance}")
    print(sets_to_markdown(report))
    print()
    if markdown_out:
        Path(markdown_out).write_text(sets_to_markdown(report) + "\n", encoding="utf-8")
        print(f"markdown report written to {markdown_out}")

    if report["unmatched_prediction_keys"]:
        print(
            "warning: sets results contain keys with no set spec: "
            + ", ".join(report["unmatched_prediction_keys"]),
            file=sys.stderr,
        )
    return 0


# --- entrypoint --------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m eval.run_eval",
        description="Score Fugu predictions against the labeled eval corpus.",
    )
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS),
                        help=f"corpus directory (default: {DEFAULT_CORPUS}; "
                             f"falls back to built-in fixtures if missing)")
    parser.add_argument("--fixtures", action="store_true",
                        help="force the built-in fixtures corpus (eval/fixtures/)")
    parser.add_argument("--results", default=None,
                        help="results.json with predictions (see eval/README.md); "
                             "omit to attempt a real pipeline run")
    parser.add_argument("--markdown", default=None,
                        help="also write a markdown report to this path")
    parser.add_argument("--detonate", action="store_true",
                        help="include the Docker detonation stage in live runs (slow)")
    parser.add_argument("--sets", default=None,
                        help="composition-sets root (dirs of <set>/set.json); "
                             "scores a sets predictions JSON via --results")
    parser.add_argument("--selfcheck", action="store_true",
                        help="run on synthetic perfect/garbage predictions and "
                             "verify expected metrics; ignores --corpus/--results")
    args = parser.parse_args(argv)

    if args.selfcheck and args.sets:
        parser.error("--selfcheck cannot be combined with --sets")
    if args.sets and (args.corpus != str(DEFAULT_CORPUS) or args.fixtures):
        parser.error(
            "--sets cannot be combined with --corpus/--fixtures "
            "(it scores composition sets, not per-extension corpora)"
        )
    if args.selfcheck:
        return _selfcheck()

    if args.sets:
        return _run_sets_mode(args.sets, args.results, args.markdown)

    corpus_dir = fixtures_dir() if args.fixtures else Path(args.corpus)
    using_fixtures = False
    if not args.fixtures and not corpus_dir.is_dir():
        print(f"note: corpus dir {corpus_dir} not found — using built-in fixtures "
              f"({fixtures_dir()})", file=sys.stderr)
        corpus_dir = fixtures_dir()
        using_fixtures = True

    try:
        samples, warnings = load_corpus(corpus_dir)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if not samples:
        print("error: corpus is empty (no sample directories with manifest.json)", file=sys.stderr)
        return 2

    if args.results:
        predictions = load_results_file(args.results)
        provenance = str(args.results)
    else:
        predictions = collect_pipeline_predictions(samples, detonate=args.detonate)
        provenance = "live fugu pipeline"

    report = category_metrics(samples, predictions)
    print(f"# provenance: {provenance}"
          + (" (fixtures)" if using_fixtures else ""))
    _print_report(report, args.markdown)

    if report["unmatched_prediction_keys"]:
        print("warning: results contain keys with no corpus sample: "
              + ", ".join(report["unmatched_prediction_keys"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
