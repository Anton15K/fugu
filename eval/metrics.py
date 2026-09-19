"""Pure metrics for the Fugu eval harness.

Multi-label, set-based scoring: for each OWASP id X over the corpus,

* tp(X) = #samples where X expected AND predicted
* fp(X) = #samples where X predicted and NOT expected
* fn(X) = #samples where X expected and NOT predicted

precision = tp/(tp+fp), recall = tp/(tp+fn), F1 with the zero-division
convention of returning 0.0 (matching sklearn's ``zero_division=0``).

* **micro** averages pool tp/fp/fn across all ids first — dominated by
  frequent categories, answers "how good is the scanner overall".
* **macro** averages the per-id F1s unweighted over every id that appears
  in the gold labels OR the predictions — answers "does it catch rare
  categories too".

Confusion pairs generalize to multi-label as a cross-product: for a
sample, every wrongly-predicted id X paired with every missed expected
id Y increments ``confusion[X -> Y]`` — read it as "cried X where Y was
the truth". Benign samples never contribute confusion pairs (there is no
true Y to confuse with); their wrong findings surface in benign-FP.

All functions are pure (no I/O, no globals); the report is a plain typed
dict that JSON-serializes as-is.
"""
from __future__ import annotations

from typing import Iterable, Mapping, TypedDict

from fugu.types import OWASP_IDS

from eval.loader import Sample


class IdMetrics(TypedDict):
    owasp_id: str
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    support: int  # samples where the id is expected


class AverageMetrics(TypedDict):
    precision: float
    recall: float
    f1: float


class ConfusionPair(TypedDict):
    predicted: str
    expected: str
    count: int


class BenignFp(TypedDict):
    total_benign: int
    flagged: int  # benign samples with >= 1 predicted id
    rate: float  # flagged / total_benign (0.0 when no benign samples)
    offending: list[dict[str, object]]  # [{sample, ids}, ...] sorted by name


class MetricsReport(TypedDict):
    n_samples: int
    n_malicious: int
    n_benign: int
    n_samples_with_predictions: int
    unmatched_prediction_keys: list[str]  # prediction keys with no corpus sample
    per_id: list[IdMetrics]  # sorted by owasp_id
    micro: AverageMetrics
    macro: AverageMetrics
    confusion_pairs: list[ConfusionPair]  # sorted by count desc, then names
    benign_fp: BenignFp
    unknown_predicted_ids: dict[str, int]  # id -> times predicted (not in OWASP_IDS)


# --- core helpers -------------------------------------------------------------

def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def _dedup(seq: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(seq))


def category_metrics(
    samples: Iterable[Sample],
    predictions: Mapping[str, Iterable[str]],
) -> MetricsReport:
    """Score ``predictions`` against the corpus ground truth.

    ``predictions`` maps sample name -> predicted OWASP ids. Missing
    entries count as "no findings" (recall damage, no precision damage);
    extra keys are reported in ``unmatched_prediction_keys``. Predicted
    ids outside ``fugu.types.OWASP_IDS`` are kept and scored (so nothing
    silently vanishes) and additionally counted in
    ``unknown_predicted_ids``.
    """
    sample_list = list(samples)

    # Normalize predictions to name -> de-duplicated list, dropping dups.
    norm_pred: dict[str, list[str]] = {
        name: _dedup(str(i) for i in ids) for name, ids in predictions.items()
    }

    known = set(OWASP_IDS)  # taxonomy contract from fugu.types (read-only)

    per_id_tp: dict[str, int] = {}
    per_id_fp: dict[str, int] = {}
    per_id_fn: dict[str, int] = {}
    support: dict[str, int] = {}
    confusion: dict[tuple[str, str], int] = {}

    benign_total = 0
    benign_flagged = 0
    benign_offending: list[dict[str, object]] = []
    unknown_ids: dict[str, int] = {}
    samples_with_predictions = 0
    corpus_names = set()

    for sample in sample_list:
        expected = _dedup(sample.expected_ids)
        predicted = norm_pred.get(sample.name, [])
        corpus_names.add(sample.name)
        if predicted:
            samples_with_predictions += 1
        for pid in predicted:
            if pid not in known:
                unknown_ids[pid] = unknown_ids.get(pid, 0) + 1

        for owasp_id in set(expected) | set(predicted):
            per_id_tp.setdefault(owasp_id, 0)
            per_id_fp.setdefault(owasp_id, 0)
            per_id_fn.setdefault(owasp_id, 0)

        for owasp_id in expected:
            support[owasp_id] = support.get(owasp_id, 0) + 1
            if owasp_id in predicted:
                per_id_tp[owasp_id] += 1
            else:
                per_id_fn[owasp_id] += 1

        wrong_predicted = [p for p in predicted if p not in expected]
        missed_expected = [e for e in expected if e not in predicted]

        if sample.kind == "benign":
            benign_total += 1
            if predicted:
                benign_flagged += 1
                benign_offending.append({"sample": sample.name, "ids": predicted})
        else:
            # confusion cross-product: predicted X where Y was the truth
            for p in wrong_predicted:
                for e in missed_expected:
                    confusion[(p, e)] = confusion.get((p, e), 0) + 1

        for p in wrong_predicted:
            per_id_fp[p] += 1

    # Unknown prediction keys (typo / stale results file).
    unmatched = sorted(k for k in norm_pred if k not in corpus_names)

    # Per-id table over every id that appeared anywhere.
    per_id: list[IdMetrics] = []
    for owasp_id in sorted(set(per_id_tp) | set(support)):
        tp, fp, fn = per_id_tp[owasp_id], per_id_fp[owasp_id], per_id_fn[owasp_id]
        precision, recall, f1 = _prf(tp, fp, fn)
        per_id.append(
            IdMetrics(
                owasp_id=owasp_id,
                tp=tp, fp=fp, fn=fn,
                precision=round(precision, 4),
                recall=round(recall, 4),
                f1=round(f1, 4),
                support=support.get(owasp_id, 0),
            )
        )

    # Micro: pool counts. Macro: mean of per-id metrics over all seen ids.
    sum_tp = sum(per_id_tp.values())
    sum_fp = sum(per_id_fp.values())
    sum_fn = sum(per_id_fn.values())
    micro_p, micro_r, micro_f = _prf(sum_tp, sum_fp, sum_fn)

    if per_id:
        macro_p = sum(m["precision"] for m in per_id) / len(per_id)
        macro_r = sum(m["recall"] for m in per_id) / len(per_id)
        macro_f = sum(m["f1"] for m in per_id) / len(per_id)
    else:
        macro_p = macro_r = macro_f = 0.0

    confusion_pairs = [
        ConfusionPair(predicted=p, expected=e, count=c)
        for (p, e), c in sorted(confusion.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    return MetricsReport(
        n_samples=len(sample_list),
        n_malicious=sum(1 for s in sample_list if s.kind == "malicious"),
        n_benign=benign_total,
        n_samples_with_predictions=samples_with_predictions,
        unmatched_prediction_keys=unmatched,
        per_id=per_id,
        micro=AverageMetrics(
            precision=round(micro_p, 4), recall=round(micro_r, 4), f1=round(micro_f, 4)
        ),
        macro=AverageMetrics(
            precision=round(macro_p, 4), recall=round(macro_r, 4), f1=round(macro_f, 4)
        ),
        confusion_pairs=confusion_pairs,
        benign_fp=BenignFp(
            total_benign=benign_total,
            flagged=benign_flagged,
            rate=round(benign_flagged / benign_total, 4) if benign_total else 0.0,
            offending=sorted(benign_offending, key=lambda d: str(d["sample"])),
        ),
        unknown_predicted_ids=dict(sorted(unknown_ids.items())),
    )


# --- renderers ------------------------------------------------------------------

def _fmt(value: float) -> str:
    return f"{value:.3f}"


def to_markdown(report: MetricsReport) -> str:
    """Render a report as a GitHub-flavored markdown document."""
    lines: list[str] = []
    lines.append("## Fugu eval report")
    lines.append("")
    lines.append(
        f"- Samples: **{report['n_samples']}** "
        f"({report['n_malicious']} malicious, {report['n_benign']} benign); "
        f"{report['n_samples_with_predictions']} received predictions"
    )
    lines.append(
        f"- Micro: P={_fmt(report['micro']['precision'])} "
        f"R={_fmt(report['micro']['recall'])} "
        f"F1=**{_fmt(report['micro']['f1'])}**"
    )
    lines.append(
        f"- Macro: P={_fmt(report['macro']['precision'])} "
        f"R={_fmt(report['macro']['recall'])} "
        f"F1=**{_fmt(report['macro']['f1'])}**"
    )
    bfp = report["benign_fp"]
    lines.append(
        f"- Benign-FP: **{_fmt(bfp['rate'])}** "
        f"({bfp['flagged']}/{bfp['total_benign']} benign samples flagged)"
    )
    if report["unmatched_prediction_keys"]:
        lines.append(
            f"- ⚠️ unmatched prediction keys (no such corpus sample): "
            f"{', '.join(report['unmatched_prediction_keys'])}"
        )
    if report["unknown_predicted_ids"]:
        unknown = ", ".join(
            f"{k}×{v}" for k, v in report["unknown_predicted_ids"].items()
        )
        lines.append(f"- ⚠️ predicted ids outside OWASP_IDS: {unknown}")
    lines.append("")

    lines.append("### Per-OWASP-id metrics")
    lines.append("")
    lines.append("| OWASP id | precision | recall | F1 | tp | fp | fn | support |")
    lines.append("|---|---|---|---|---|---|---|---|")
    if report["per_id"]:
        for m in report["per_id"]:
            lines.append(
                f"| {m['owasp_id']} | {_fmt(m['precision'])} | {_fmt(m['recall'])} "
                f"| {_fmt(m['f1'])} | {m['tp']} | {m['fp']} | {m['fn']} | {m['support']} |"
            )
    else:
        lines.append("| _none_ | — | — | — | — | — | — | — |")
    lines.append("")

    lines.append("### Confusion pairs (predicted → expected)")
    lines.append("")
    if report["confusion_pairs"]:
        lines.append("| predicted | expected | count |")
        lines.append("|---|---|---|")
        for pair in report["confusion_pairs"]:
            lines.append(f"| {pair['predicted']} | {pair['expected']} | {pair['count']} |")
    else:
        lines.append("_none_")
    lines.append("")

    if bfp["offending"]:
        lines.append("### Benign samples flagged (false positives)")
        lines.append("")
        for entry in bfp["offending"]:
            ids = ", ".join(str(i) for i in entry["ids"])  # type: ignore[attr-defined]
            lines.append(f"- `{entry['sample']}`: {ids}")
        lines.append("")
    return "\n".join(lines)


def to_console(report: MetricsReport) -> str:
    """Render a report as fixed-width plain text for terminals/CI logs."""
    w = max([len(m["owasp_id"]) for m in report["per_id"]] + [10])
    header = f"{'id'.ljust(w)}  {'prec':>5} {'rec':>5} {'f1':>5}  {'tp':>3} {'fp':>3} {'fn':>3} {'sup':>3}"
    lines: list[str] = []
    lines.append("=" * len(header))
    lines.append("FUGU EVAL REPORT")
    lines.append("=" * len(header))
    lines.append(
        f"samples: {report['n_samples']} "
        f"(malicious {report['n_malicious']}, benign {report['n_benign']}); "
        f"with predictions: {report['n_samples_with_predictions']}"
    )
    m, a = report["micro"], report["macro"]
    lines.append(f"micro: P={_fmt(m['precision'])} R={_fmt(m['recall'])} F1={_fmt(m['f1'])}")
    lines.append(f"macro: P={_fmt(a['precision'])} R={_fmt(a['recall'])} F1={_fmt(a['f1'])}")
    bfp = report["benign_fp"]
    lines.append(f"benign-FP rate: {_fmt(bfp['rate'])} ({bfp['flagged']}/{bfp['total_benign']})")
    if report["unmatched_prediction_keys"]:
        lines.append(f"WARNING unmatched prediction keys: {', '.join(report['unmatched_prediction_keys'])}")
    if report["unknown_predicted_ids"]:
        lines.append(
            "WARNING unknown predicted ids: "
            + ", ".join(f"{k}x{v}" for k, v in report["unknown_predicted_ids"].items())
        )
    lines.append("-" * len(header))
    lines.append(header)
    lines.append("-" * len(header))
    if report["per_id"]:
        for metrics in report["per_id"]:
            lines.append(
                f"{metrics['owasp_id'].ljust(w)}  "
                f"{_fmt(metrics['precision']):>5} {_fmt(metrics['recall']):>5} "
                f"{_fmt(metrics['f1']):>5}  "
                f"{metrics['tp']:>3} {metrics['fp']:>3} {metrics['fn']:>3} {metrics['support']:>3}"
            )
    else:
        lines.append("(no ids predicted or expected)")
    lines.append("-" * len(header))
    if report["confusion_pairs"]:
        lines.append("confusion pairs (predicted -> expected):")
        for pair in report["confusion_pairs"]:
            bar = "#" * min(pair["count"], 40)
            lines.append(f"  {pair['predicted']} -> {pair['expected']}: {pair['count']} {bar}")
    else:
        lines.append("confusion pairs: none")
    if bfp["offending"]:
        lines.append("benign samples flagged:")
        for entry in bfp["offending"]:
            ids = ", ".join(str(i) for i in entry["ids"])  # type: ignore[attr-defined]
            lines.append(f"  {entry['sample']}: {ids}")
    lines.append("=" * len(header))
    return "\n".join(lines)
