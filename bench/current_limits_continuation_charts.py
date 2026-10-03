"""Render dated charts for the bounded current-profile continuation packet."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import re
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench.current_limits import (FROZEN, case_target, hash_json, input_hashes, read_json, sha,
                                  write_json)
from bench.current_limits_charts import comparison_data, load_competitors


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = FROZEN / "cases.json"
DEFAULT_COMPARATORS = FROZEN / "competitors"
PROTOCOL = "current-production-source-inference-continuation-v1"
ENGINE_COMMIT = "cc58a58d6cea861510980814ae2e70b7bdf24e63"
PARENT_RESULT_SHA256 = "708623e0fac256a4cb2810bdddc2875ba22a1ad3b16bbdb7ed39324821d3b987"
PARENT_PLAN_SHA256 = "8f304c3da81e0db091da6e2c324c064d013129d63644b278079c4cf8ad9ef725"
PARENT_INVENTORY_SHA256 = "63240327fc6adf050b6cefbd0340f1fb6c16700c48551bc12548b071a057783e"
CASE_MANIFEST_SHA256 = "f9b31035908d217a822079dd190c4d5797f86646c65f01c2e06b1f57ae3e91b1"
REUSED_RUNNER_SHA256 = "2e69cd6654ec8158d3de968ad026c56d2e04179574c0667133cac8edadea002d"
PARENT_ROWS = 13
PLANNED_ROWS = 40


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _is_sha256(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("interval timestamps must be ISO-8601") from exc
    _require(parsed.tzinfo is not None, "interval timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _row_ids(rows: list[dict]) -> list[str]:
    try:
        return [row["id"] for row in rows]
    except (KeyError, TypeError) as exc:
        raise ValueError("combined rows must contain case IDs") from exc


def _validate_usage(combined: dict, intervals: list[dict]) -> None:
    usage = combined.get("usage")
    _require(isinstance(usage, dict), "combined usage is missing")
    interval_usage = [record.get("usage") for record in intervals]
    _require(all(isinstance(item, dict) for item in interval_usage), "interval usage is missing")

    attempts = [item.get("attempts") for item in interval_usage]
    _require(all(isinstance(value, int) and value >= 0 for value in attempts),
             "interval attempts must be nonnegative SDK-row counts")
    _require(usage.get("attempts") == sum(attempts), "combined SDK attempt count does not match intervals")

    unknown = [item.get("unknown_usage_calls") for item in interval_usage]
    unknown_count = None
    if all(isinstance(value, int) and value >= 0 for value in unknown):
        unknown_count = sum(unknown)
        _require(usage.get("unknown_usage_calls") == sum(unknown),
                 "combined unknown-usage count does not match intervals")

    for field in ("prompt_tokens", "completion_tokens"):
        total_key = field + "_total"
        values = [item.get(total_key) for item in interval_usage]
        if any(value is None for value in values) or (unknown_count is not None and unknown_count > 0):
            _require(usage.get(total_key) is None, f"unknown interval {field} must keep combined total null")
        elif all(isinstance(value, int) and value >= 0 for value in values):
            _require(usage.get(total_key) == sum(values), f"combined {field} total does not match intervals")

        subtotal_key = field + "_known_subtotal"
        subtotals = [item.get(subtotal_key) for item in interval_usage]
        if all(isinstance(value, int) and value >= 0 for value in subtotals):
            _require(usage.get(subtotal_key) == sum(subtotals),
                     f"combined {field} known subtotal does not match intervals")


def validate_combined(combined: dict, manifest: dict) -> tuple[dict, dict]:
    """Fail closed on schema, lineage, interval, row-order, and usage mismatches."""
    _require(isinstance(combined, dict), "combined result must be an object")
    _require(combined.get("schema") == 2, "unsupported combined result schema")
    _require(combined.get("protocol") == PROTOCOL, "combined result protocol mismatch")
    _require(combined.get("planned") == PLANNED_ROWS, "combined planned denominator must be 40")
    engine, limits = combined.get("engine"), combined.get("limits")
    _require(isinstance(engine, dict) and engine.get("commit") == ENGINE_COMMIT,
             "combined engine commit differs from the checked production engine")
    _require(isinstance(limits, dict) and limits.get("llm_max_output_tokens") == 4096,
             "combined production output profile must remain 4096 tokens")

    cases = manifest.get("cases") if isinstance(manifest, dict) else None
    rows = combined.get("rows")
    _require(isinstance(cases, list) and len(cases) == PLANNED_ROWS,
             "original case manifest must contain 40 cases")
    _require(isinstance(rows, list) and len(rows) == PLANNED_ROWS,
             "combined result must contain 40 rows")
    case_ids, ids = _row_ids(cases), _row_ids(rows)
    _require(len(set(case_ids)) == PLANNED_ROWS, "original manifest contains duplicate case IDs")
    _require(len(set(ids)) == PLANNED_ROWS and ids == case_ids,
             "combined rows must preserve the original 40 case IDs and order")

    for case, row in zip(cases, rows):
        _require(row.get("input_sha256") == case.get("input_sha256"),
                 f"combined row input hash differs from original manifest: {case['id']}")

    parent_hash = combined.get("parent_result_sha256")
    child_hash = combined.get("child_result_sha256")
    _require(parent_hash == PARENT_RESULT_SHA256, "combined parent result hash is not the accepted frozen result")
    _require(_is_sha256(child_hash), "combined child result hash is malformed")
    _require(child_hash != parent_hash, "parent and continuation result hashes must differ")

    intervals = combined.get("intervals")
    _require(isinstance(intervals, list) and len(intervals) == 2,
             "combined result must describe exactly two intervals")
    interval_ids = [record.get("id") if isinstance(record, dict) else None for record in intervals]
    _require(all(isinstance(value, str) and value for value in interval_ids)
             and len(set(interval_ids)) == 2, "interval IDs must be unique nonempty strings")
    for record in intervals:
        for field in ("started_utc", "measured_utc", "result_sha256", "usage"):
            _require(field in record, f"interval is missing {field}")
        _require(_is_sha256(record.get("result_sha256")), "interval result hash is malformed")
        _require(_utc(record["started_utc"]) <= _utc(record["measured_utc"]),
                 "interval measurement ends before it starts")

    parent_intervals = [r for r in intervals if r["result_sha256"] == parent_hash]
    child_intervals = [r for r in intervals if r["result_sha256"] == child_hash]
    _require(len(parent_intervals) == len(child_intervals) == 1,
             "interval result hashes must identify one parent and one continuation")
    parent_interval, child_interval = parent_intervals[0], child_intervals[0]
    _require(_utc(parent_interval["measured_utc"]) < _utc(child_interval["started_utc"]),
             "continuation interval must follow the stopped parent interval")

    lineage = combined.get("lineage")
    _require(isinstance(lineage, dict), "combined lineage is missing")
    parent_lineage, child_lineage = lineage.get("parent"), lineage.get("child")
    _require(isinstance(parent_lineage, dict) and isinstance(child_lineage, dict),
             "combined parent/child lineage is incomplete")
    _require(parent_lineage.get("plan_sha256") == PARENT_PLAN_SHA256,
             "parent accepted plan hash mismatch")
    _require(parent_lineage.get("inventory_sha256") == PARENT_INVENTORY_SHA256,
             "parent accepted inventory hash mismatch")
    _require(parent_lineage.get("result_sha256") == parent_hash,
             "parent lineage result hash mismatch")
    _require(_is_sha256(child_lineage.get("plan_sha256")), "child plan hash is malformed")
    _require(child_lineage.get("result_sha256") == child_hash,
             "child lineage result hash mismatch")
    _require(lineage.get("original_case_manifest_sha256") == CASE_MANIFEST_SHA256,
             "original 40-case manifest hash mismatch")
    _require(lineage.get("reused_runner_sha256") == REUSED_RUNNER_SHA256,
             "reused runner hash mismatch")

    row_interval = combined.get("row_interval")
    _require(isinstance(row_interval, dict) and set(row_interval) == set(ids),
             "every case row must have exactly one interval mapping")
    _require(all(isinstance(value, str) and value for value in row_interval.values()),
             "row interval IDs must be nonempty strings")
    _require(set(row_interval.values()) == set(interval_ids), "row interval mapping references an unknown interval")
    parent_ids = [case_id for case_id in case_ids if row_interval[case_id] == parent_interval["id"]]
    child_ids = [case_id for case_id in case_ids if row_interval[case_id] == child_interval["id"]]
    _require(parent_ids == case_ids[:PARENT_ROWS] and len(child_ids) == PLANNED_ROWS - PARENT_ROWS,
             "parent rows must remain first and the 27 untouched rows must map to the continuation")
    parent_rows = rows[:PARENT_ROWS]
    _require(sum(row.get("status") == "completed" for row in parent_rows) == 12
             and sum(row.get("status") == "partial" for row in parent_rows) == 1,
             "the 12 complete and one partial parent rows must be preserved")

    _validate_usage(combined, intervals)
    return parent_interval, child_interval


def verify_manifest_packets(manifest: dict) -> None:
    """Verify all 40 original input trees against the immutable case manifest."""
    for case in manifest.get("cases", []):
        try:
            actual = input_hashes(case_target(case))
        except Exception as exc:
            raise ValueError(f"cannot verify input packet for {case.get('id', 'unknown')}") from exc
        if actual != case.get("input_sha256"):
            raise ValueError(f"input packet hash mismatch: {case.get('id', 'unknown')}")


def _interval_label(record: dict) -> str:
    start = _utc(record["started_utc"]).strftime("%Y-%m-%d %H:%M UTC")
    end = _utc(record["measured_utc"]).strftime("%Y-%m-%d %H:%M UTC")
    return f"{record['id']}: {start}–{end}"


def chart_data(combined: dict, manifest: dict, competitors: dict, *,
               comparator_snapshot: str = "unspecified") -> dict:
    parent_interval, child_interval = validate_combined(combined, manifest)
    comparison = comparison_data(combined, manifest, competitors)
    rows = {row["id"]: row for row in combined["rows"]}
    benign_ids = [case["id"] for case in manifest["cases"] if case.get("kind") == "benign"]
    observed_benign = [case_id for case_id in benign_ids if rows[case_id].get("complete")]
    pending_flags = [case_id for case_id in benign_ids if rows[case_id].get("detected") is True
                     and rows[case_id].get("adjudicated_false_positive") is None]
    confirmed = [case_id for case_id in benign_ids
                 if rows[case_id].get("adjudicated_false_positive") is True]
    raw_flags = [case_id for case_id in benign_ids if rows[case_id].get("detected") is True]
    false_positive_rate = (len(confirmed) / len(benign_ids)
                           if benign_ids and len(observed_benign) == len(benign_ids) and not pending_flags
                           else None)

    partial_rows = [row for row in combined["rows"] if not row.get("complete")]
    partial_ids = [row["id"] for row in partial_rows]
    evidence_rows = [row for row in partial_rows if row.get("findings")]
    evidence_ids = [row["id"] for row in evidence_rows]
    high_critical = sum(
        str(finding.get("severity", "")).lower() in {"high", "critical"}
        for row in evidence_rows for finding in row.get("findings", [])
    )
    interval_caption = "; ".join((_interval_label(parent_interval), _interval_label(child_interval)))
    comparator_versions = ", ".join(
        f"{name} {document.get('version', 'version unavailable')}"
        for name, document in competitors.items()
    ) or "no historical comparators"
    pending_total = len(pending_flags)
    caption = (
        f"Intervals (UTC): {interval_caption}.\n"
        f"Current engine {combined['engine']['commit'][:12]}; unchanged production output profile: 4096 tokens.\n"
        f"Historical comparator snapshot {comparator_snapshot}: {comparator_versions}.\n"
        f"{len(partial_ids)} partial/incomplete rows; {high_critical} high/critical partial findings retained. "
        f"{pending_total} benign flags pending adjudication; FPR is unavailable when benign coverage or adjudication is incomplete."
    )
    return {
        "schema": 1,
        "synthetic": bool(combined.get("synthetic")),
        "planned": combined["planned"],
        "scope": combined.get("scope"),
        "engine": combined["engine"],
        "limits": combined["limits"],
        "summary": combined.get("summary", {}),
        "usage": combined["usage"],
        "coverage": combined.get("coverage", {}),
        "intervals": combined["intervals"],
        "row_interval": combined["row_interval"],
        "lineage": combined["lineage"],
        "comparison": comparison,
        "cohorts": _cohort_coverage(combined["rows"]),
        "partial_evidence": {"case_ids": evidence_ids,
                             "incomplete_case_ids": partial_ids,
                             "high_or_critical_findings": high_critical,
                             "findings_retained": True},
        "benign_adjudication": {
            "planned": len(benign_ids), "observed_denominator": len(observed_benign),
            "raw_flags": len(raw_flags), "confirmed_false_positives": len(confirmed),
            "pending_adjudication": pending_total,
            "incomplete": len(benign_ids) - len(observed_benign),
            "false_positive_rate": false_positive_rate,
        },
        "provenance": {
            "parent_result_sha256": combined["parent_result_sha256"],
            "child_result_sha256": combined["child_result_sha256"],
            "parent_plan_sha256": combined["lineage"]["parent"]["plan_sha256"],
            "parent_inventory_sha256": combined["lineage"]["parent"]["inventory_sha256"],
            "child_plan_sha256": combined["lineage"]["child"]["plan_sha256"],
            "original_case_manifest_sha256": combined["lineage"]["original_case_manifest_sha256"],
            "reused_runner_sha256": combined["lineage"]["reused_runner_sha256"],
            "comparator_result_sha256": {name: hash_json(document)
                                         for name, document in competitors.items()},
            "profile_output_tokens": combined["limits"]["llm_max_output_tokens"],
            "comparator_snapshot": comparator_snapshot,
            "comparator_versions": comparator_versions,
            "caption": caption,
        },
        "caveats": [
            "This report combines a stopped parent interval and its single bounded continuation.",
            "Historical comparator outputs are versioned records, not executions in either interval.",
            "The same complete attack-ID intersection is used for every paired tool count.",
            "Partial findings remain visible but do not count as complete detections.",
            "Unknown parent SDK usage keeps combined token totals null; known subtotals remain available.",
            "No population false-positive rate, cost saving, or universal superiority claim is made.",
        ],
    }


def _cohort_coverage(rows: list[dict]) -> list[dict]:
    counts = Counter()
    for row in rows:
        state = "completed" if row.get("complete") else "unattempted" if row.get("status") == "unattempted" else "incomplete"
        counts[(row.get("cohort", "unknown"), row.get("kind", "unknown"), state)] += 1
    return [
        {"cohort": cohort, "kind": kind,
         "completed": counts[(cohort, kind, "completed")],
         "incomplete": counts[(cohort, kind, "incomplete")],
         "unattempted": counts[(cohort, kind, "unattempted")],
         "planned": sum(counts[(cohort, kind, state)] for state in ("completed", "incomplete", "unattempted"))}
        for cohort, kind in sorted({(row.get("cohort", "unknown"), row.get("kind", "unknown")) for row in rows})
    ]


def render(data: dict, output: Path) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "svg.fonttype": "none", "savefig.facecolor": "white"})
    prefix = "SYNTHETIC OFFLINE FIXTURE\n" if data["synthetic"] else ""
    primary = data["comparison"]["primary"]
    names = []

    def save(fig, name: str) -> None:
        fig.savefig(output / f"{name}.png", dpi=180, bbox_inches="tight")
        svg = output / f"{name}.svg"
        fig.savefig(svg, bbox_inches="tight")
        svg.write_text("".join(line.rstrip() + "\n" for line in svg.read_text(encoding="utf-8").splitlines()),
                       encoding="utf-8")
        plt.close(fig)
        names.extend([f"{name}.png", f"{name}.svg"])

    labels, attack_counts = [], []
    for name, row in primary.items():
        if name == "fugu":
            labels.append("Fugu current production profile")
            attack_counts.append([row["attack_detected"], row["attack_missed"],
                                  row["attack_incomplete"], row["attack_unattempted"]])
        else:
            labels.append(f"{name} {row.get('version') or ''}\nHistorical")
            positive = row["attack_medium_positive"]
            attack_counts.append([positive, row["completed_attacks"] - positive, 0,
                                  len(row["unavailable_attack_ids"])])

    fig, axes = plt.subplots(1, 2, figsize=(14, 8), gridspec_kw={"width_ratios": [1.45, 1]})
    fig.suptitle(prefix + "Fixed description cohort: planned results and clean-description flags", fontsize=14, y=.98)
    colors = ["#267d72", "#c5ced4", "#d49a3f", "#855d95"]
    left = [0] * len(labels)
    for index, (title, color) in enumerate(zip(
            ("Detected medium+", "Missed", "Incomplete", "Unattempted / unavailable"), colors)):
        values = [row[index] for row in attack_counts]
        axes[0].barh(labels, values, left=left, color=color, label=title)
        for position, (start, value) in enumerate(zip(left, values)):
            if value:
                axes[0].text(start + value / 2, position, str(value), va="center", ha="center",
                             color="white" if index in (0, 3) else "#26333e", fontsize=9)
        left = [start + value for start, value in zip(left, values)]
    for position, (parts, total) in enumerate(zip(attack_counts, left)):
        axes[0].text(total + .15, position, f"{parts[0]}/{total} planned", va="center", fontsize=9)
    axes[0].invert_yaxis()
    axes[0].set_xlim(0, max(left, default=1) * 1.32 + 1)
    axes[0].set_xlabel("15 planned malicious descriptions")
    axes[0].legend(loc="upper left", bbox_to_anchor=(0, -.18), ncol=2, fontsize=8)

    control_values = []
    control_annotations = []
    planned_controls = primary["fugu"]["planned_controls"]
    for name, row in primary.items():
        control_values.append(row["raw_benign_flags"])
        available = (planned_controls - row["control_incomplete"] if name == "fugu"
                     else planned_controls - len(row["control_unavailable_ids"]))
        control_annotations.append(f"{row['raw_benign_flags']} flags; {available}/{planned_controls} observed")
    axes[1].barh(labels, control_values, color="#547b9d")
    axes[1].invert_yaxis()
    axes[1].set_xlim(0, max(5, max(control_values, default=0) + 2.5))
    axes[1].set_xlabel("Raw medium+ flags; 5 clean descriptions planned")
    for position, (value, annotation) in enumerate(zip(control_values, control_annotations)):
        axes[1].text(value + .08, position, annotation, va="center", fontsize=8)
    paired = data["comparison"]["paired"]
    paired_count = len(data["comparison"]["paired_attack_ids"])
    paired_summary = "; ".join(
        f"{name}: {counts['attack_medium_positive']}/{counts['attack_denominator']}"
        for name, counts in paired.items()
    )
    fig.text(.025, .025, data["provenance"]["caption"] +
             f"\nSecondary complete paired attacks (same {paired_count} IDs): {paired_summary}. "
             "Clean-description flags are not an FPR.\n"
             "Partial findings are retained when present and do not count as completed detections.",
             fontsize=8, va="bottom")
    fig.subplots_adjust(left=.19, right=.98, top=.9, bottom=.36, wspace=.55)
    save(fig, "common-results")

    cohorts = data["cohorts"]
    labels = [f"{row['cohort']} / {row['kind']}" for row in cohorts]
    fig, ax = plt.subplots(figsize=(12, 8))
    left = [0] * len(cohorts)
    for key, color, title in (("completed", "#267d72", "Completed"),
                              ("incomplete", "#d49a3f", "Partial / incomplete"),
                              ("unattempted", "#855d95", "Unattempted")):
        values = [row[key] for row in cohorts]
        ax.barh(labels, values, left=left, color=color, label=title)
        left = [start + value for start, value in zip(left, values)]
    for index, row in enumerate(cohorts):
        ax.text(row["planned"] + .1, index, f"{row['planned']} planned", va="center", fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, max(left, default=1) * 1.25 + 1)
    ax.set_xlabel("All 40 original case rows; dependency controls are separate from clean descriptions")
    fig.suptitle(prefix + "Coverage across the fixed 40-case manifest", fontsize=14, y=.98)
    ax.legend(loc="upper center", bbox_to_anchor=(.5, -.12), ncol=3, fontsize=9)
    fig.text(.03, .025, data["provenance"]["caption"] +
             "\nA partial/incomplete row can retain severe findings; it is not a completed detection. "
             "Pending benign adjudication remains separate.", fontsize=8, va="bottom")
    fig.subplots_adjust(left=.32, right=.96, top=.9, bottom=.27)
    save(fig, "cohort-coverage")

    intervals = data["intervals"]
    interval_labels = [record["id"] for record in intervals]
    fig, axes = plt.subplots(1, 2, figsize=(12, 6.8))
    fig.suptitle(prefix + "SDK ledger by measured interval", fontsize=14, y=.98)
    attempts = [record["usage"]["attempts"] for record in intervals]
    axes[0].bar(interval_labels, attempts, color=["#547b9d", "#267d72"])
    for index, value in enumerate(attempts):
        axes[0].text(index, value, f"{value:,}", ha="center", va="bottom", fontsize=9)
    axes[0].set_ylabel("Numbered SDK journal rows")
    axes[0].set_title("Actual attempts by interval")
    width = .36
    prompt_values = [record["usage"].get("prompt_tokens_known_subtotal") for record in intervals]
    completion_values = [record["usage"].get("completion_tokens_known_subtotal") for record in intervals]
    positions = list(range(len(intervals)))
    prompt_heights = [value if isinstance(value, int) and value >= 0 else 0 for value in prompt_values]
    completion_heights = [value if isinstance(value, int) and value >= 0 else 0 for value in completion_values]
    axes[1].bar([position - width / 2 for position in positions], prompt_heights, width,
                color="#547b9d", label="Known prompt-token subtotal")
    axes[1].bar([position + width / 2 for position in positions], completion_heights, width,
                color="#d49a3f", label="Known completion-token subtotal")
    for index, (prompt, completion) in enumerate(zip(prompt_values, completion_values)):
        prompt_label = f"{prompt:,}" if isinstance(prompt, int) else "Unavailable"
        completion_label = f"{completion:,}" if isinstance(completion, int) else "Unavailable"
        axes[1].text(index - width / 2, prompt_heights[index], prompt_label,
                     ha="center", va="bottom", fontsize=8)
        axes[1].text(index + width / 2, completion_heights[index], completion_label,
                     ha="center", va="bottom", fontsize=8)
    axes[1].set_xticks(positions, interval_labels)
    axes[1].set_ylabel("Tokens with reported usage")
    axes[1].set_title("Known subtotals only")
    axes[1].legend(fontsize=8)
    unknown = [record["usage"].get("unknown_usage_calls", "unknown") for record in intervals]
    fig.text(.03, .025, data["provenance"]["caption"] +
             "\nUnknown token-usage calls: " + "; ".join(f"{label} {count}" for label, count in zip(interval_labels, unknown)) +
             ". Combined token totals stay unavailable when any call is unknown.\n"
             "SDK journal rows only; native logical calls, cache hits, and replay references are not attempts.",
             fontsize=8, va="bottom")
    fig.subplots_adjust(left=.1, right=.97, top=.86, bottom=.34, wspace=.45)
    save(fig, "call-telemetry")

    write_json(output / "chart-data.json", data)
    return names


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--combined", type=Path, required=True,
                        help="combined two-interval JSON emitted by the continuation aggregate")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST,
                        help="immutable original 40-case manifest")
    parser.add_argument("--historical-competitors", type=Path, default=DEFAULT_COMPARATORS,
                        help="immutable dated comparator artifacts")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if sha(args.manifest.read_bytes()) != CASE_MANIFEST_SHA256:
        raise ValueError("original 40-case manifest hash mismatch")
    runner_path = Path(__file__).with_name("current_limits.py")
    if sha(runner_path.read_bytes()) != REUSED_RUNNER_SHA256:
        raise ValueError("reused benchmark runner hash mismatch")
    manifest = read_json(args.manifest)
    verify_manifest_packets(manifest)
    competitors = load_competitors(manifest, args.historical_competitors)
    combined = read_json(args.combined)
    data = chart_data(combined, manifest, competitors,
                      comparator_snapshot=args.historical_competitors.parent.name)
    render(data, args.output)
    return 0


if __name__ == "__main__":
    main()
