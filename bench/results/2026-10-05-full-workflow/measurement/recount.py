"""Offline safe export/recount. Never imports detectors or loads credentials."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def wilson(successes, total):
    if not total:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [0.0 if successes == 0 else max(0, center - margin),
            1.0 if successes == total else min(1, center + margin)]


def rate(flags):
    positives = sum(value is True for value in flags)
    return {"n": len(flags), "flagged": positives,
            "unflagged": sum(value is False for value in flags),
            "rate": positives / len(flags) if flags else None,
            "wilson95": wilson(positives, len(flags))}


def stage_metadata(stage):
    metrics = stage.get("metrics") or {}
    counts = {"finding_count" if key == "findings" else key: value for key, value in metrics.items()
              if type(value) in (int, float, bool) and math.isfinite(value)}
    for key in ("effective_limits", "file_collection"):
        if isinstance(metrics.get(key), dict):
            counts[key] = {k: v for k, v in metrics[key].items()
                           if type(v) in (int, float, bool) and math.isfinite(v)}
    return {"stage": stage["stage"], "state": stage["state"],
            "member": stage.get("member"), "ok": stage.get("ok"),
            "error_present": bool(stage.get("error")),
            "error_sha256": hashlib.sha256(str(stage["error"]).encode()).hexdigest()
                if stage.get("error") else None,
            "metrics": counts,
            "parse_error_count": len(metrics.get("parse_errors") or []),
            "call_error_count": len(metrics.get("call_errors") or []),
            "native_request_attempt_count": len(metrics.get("request_attempts") or []),
            "finding_severities": dict(Counter(f.get("severity") for f in stage.get("findings", []))),
            "journal_alignment": stage.get("journal_alignment"),
            "scanner_prerequisite_alignment": stage.get("scanner_prerequisite_alignment")}


def fugu_row(row):
    keys = ("id", "cohort", "kind", "input_sha256", "plan_sha256", "status", "complete",
            "detected", "raw_medium_flag", "composition_score", "matches_frozen_expectations",
            "adjudicated_false_positive", "provenance", "overlap")
    return {**{k: row.get(k) for k in keys},
            "stages": [stage_metadata(s) for s in row.get("stages", [])],
            "members": row.get("members"),
            "member_coverage": [{"label": m.get("label"), "member": m.get("member"),
                "fingerprint": m.get("fingerprint"),
                "complete": bool(m.get("stages")) and all(s.get("state") in {"completed", "not_applicable"}
                    for s in m.get("stages", [])),
                "cached_identical_input": m.get("cached_identical_input"),
                "stage_states": [{"stage": s.get("stage"), "state": s.get("state")}
                    for s in m.get("stages", [])]} for m in row.get("members_results", [])],
            "finding_severities": dict(Counter(f.get("severity") for f in row.get("findings", [])))}


def native_row(row, native_root):
    copied = dict(row)
    if copied.get("native_artifact"):
        copied["native_artifact"] = "competitor/" + Path(copied["native_artifact"]).resolve().relative_to(native_root.resolve()).as_posix()
    return copied


def sdk_rows(fugu_root, native_root):
    rows = []
    for journal in sorted((fugu_root / "journals").glob("fugu-*")):
        for path in sorted((journal / "calls").glob("*.json")):
            raw = read(path)
            response = raw.get("raw_response")
            rows.append({"lane": "fugu", "journal": journal.name,
                **{k: raw.get(k) for k in ("number", "context", "stage", "phase", "ordinal", "state",
                    "reserved_utc", "request_sha256", "messages_sha256", "requested_model", "max_tokens",
                    "temperature", "served_model", "finish_reason", "usage", "response_sha256",
                    "duration_s", "error", "output_error")},
                "response_chars": len(response) if isinstance(response, str) else None,
                "raw_artifact": f"fugu/{path.relative_to(fugu_root).as_posix()}",
                "raw_artifact_sha256": sha(path)})
    ledger = read(native_root / "hosted-counter/ledger.json")
    for raw in ledger["requests"]:
        options = raw["native_options"]
        rows.append({"lane": "competitor", "journal": "shared-cisco",
            **{k: raw.get(k) for k in ("number", "run_id", "context_id", "stage", "phase", "ordinal",
                "state", "started_utc", "request_sha256", "native_options_sha256", "usage", "served_model",
                "finish_reason", "response_chars", "response_sha256", "latency_s", "error",
                "request_artifact_sha256", "response_artifact_sha256")},
            "requested_model": options["sdk_model"], "native_model": options["native_model"],
            "max_tokens": options["max_tokens"], "temperature": options["temperature"],
            "timeout_seconds": options["timeout"], "sdk_max_retries": options["sdk_max_retries"],
            "native_max_retries": options["native_max_retries"]})
    return rows


def usage(rows):
    tokens = {}
    for key in ("prompt_tokens", "completion_tokens"):
        values = [(row.get("usage") or {}).get(key) for row in rows]
        known = [v for v in values if type(v) is int and v >= 0]
        tokens[key] = {"known_subtotal": sum(known), "unknown_calls": len(values) - len(known),
                       "total": sum(known) if len(known) == len(values) else None}
    return {"attempts": len(rows), "states": dict(Counter(row["state"] for row in rows)),
            "provider_errors": sum(bool(r.get("error")) for r in rows), "tokens": tokens,
            "requested_completion_token_envelope": sum(r["max_tokens"] for r in rows),
            "known_cost": None, "remaining_quota": None}


def paired(fugu, native):
    by_id = {row["id"]: row for row in fugu}
    summaries = []
    for scanner in ("sentinel", "mcp-sec-audit", "cisco-skill", "cisco-mcp"):
        for kind in ("malicious", "benign"):
            selected = [row for row in native if row["scanner"] == scanner and row["kind"] == kind]
            pairs = [(by_id[row["id"]], row) for row in selected]
            assert all(a["input_sha256"] == b["input_sha256"] and a["kind"] == b["kind"]
                       and a["cohort"] == b["cohort"] for a, b in pairs)
            valid = [(a, b) for a, b in pairs if a["complete"] and b["complete"]]
            assert all(type(a["detected"]) is bool and type(b["flagged"]) is bool
                       and type(b["any_alert"]) is bool for a, b in valid)
            summaries.append({"scanner": scanner, "cohort": "skills" if scanner == "cisco-skill" else "mcp_metadata",
                "kind": kind, "planned": len(pairs), "matched_complete": len(valid),
                "matched_ids": [a["id"] for a, b in valid],
                "excluded": [{"id": a["id"], "fugu_status": a["status"], "native_status": b["status"],
                              "fugu_complete": a["complete"], "native_complete": b["complete"]}
                             for a, b in pairs if not (a["complete"] and b["complete"])],
                "fugu_primary": rate([a["detected"] for a, b in valid]),
                "native_primary": rate([b["flagged"] for a, b in valid]),
                "disagreements": {
                    "fugu_only": [a["id"] for a, b in valid if a["detected"] and not b["flagged"]],
                    "native_only": [a["id"] for a, b in valid if b["flagged"] and not a["detected"]],
                    "both_flagged": [a["id"] for a, b in valid if a["detected"] and b["flagged"]],
                    "both_unflagged": [a["id"] for a, b in valid if not a["detected"] and not b["flagged"]]},
                "native_any_alert_secondary": rate([b["any_alert"] for a, b in valid])})
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fugu-root", type=Path, required=True)
    parser.add_argument("--native-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    fugu = read(args.fugu_root / "fugu.json")
    native = read(args.native_root / "competitors.json")
    assert fugu["planned"] == len(fugu["rows"]) == 140
    assert native["planned"] == len(native["rows"]) == 320
    assert fugu["plan_sha256"] == native["plan_sha256"]
    assert fugu["cases_sha256"] == native["cases_sha256"]
    assert fugu["data_release_ref"] == native["data_release_ref"] == "qitem-20261005103009-2753fe32"
    calls = sdk_rows(args.fugu_root, args.native_root)
    fugu_calls = [r for r in calls if r["lane"] == "fugu"]
    native_calls = [r for r in calls if r["lane"] == "competitor"]
    budgets = [read(path) for path in sorted((args.fugu_root / "journals").glob("*/budget.json"))]
    assert len(budgets) == 3 and all(b["attempts"] <= 1800 for b in budgets)
    assert len(fugu_calls) == sum(b["attempts"] for b in budgets) <= 5400
    assert len(native_calls) == read(args.native_root / "hosted-counter/ledger.json")["attempts"] <= 1800
    assert len(calls) <= 7200
    assert all(r["max_tokens"] == 4096 for r in fugu_calls)
    assert all(r["max_tokens"] == (8192 if r["stage"] == "competitor:cisco-skill" else 1000) for r in native_calls)
    assert sum(r["max_tokens"] for r in calls) <= 36864000
    result = {"schema": 1, "protocol": "fugu-full-workflow-safe-measurement-v1",
        "data_release_ref": fugu["data_release_ref"], "plan_sha256": fugu["plan_sha256"],
        "cases_sha256": fugu["cases_sha256"],
        "raw_provenance": {"fugu.json": sha(args.fugu_root / "fugu.json"),
            "competitors.json": sha(args.native_root / "competitors.json"),
            "competitor-ledger.json": sha(args.native_root / "hosted-counter/ledger.json")},
        "intervals": {"fugu": {k: fugu.get(k) for k in ("started_utc", "measured_utc")},
                      "competitors": {"initialized_utc": native.get("started_utc"),
                          "started_utc": min((r["started_utc"] for r in native["rows"] if r.get("started_utc")), default=None),
                          "measured_utc": max((r["measured_utc"] for r in native["rows"] if r.get("measured_utc")), default=None)}},
        "fugu_planned": 140, "competitor_planned": 320,
        "profile": fugu["profile"],
        "usage": {"all": usage(calls), "fugu": usage(fugu_calls), "competitors": usage(native_calls),
            "search": fugu["usage"]["search"], "native_stops": [b["stop_reason"] for b in budgets],
            "competitor_stop": read(args.native_root / "hosted-counter/ledger.json")["stop_reason"]},
        "fugu_rows": [fugu_row(row) for row in fugu["rows"]],
        "competitor_rows": [native_row(row, args.native_root) for row in native["rows"]],
        "paired": paired(fugu["rows"], native["rows"]),
        "conventions": {"fugu_primary": "medium-or-higher; composition uses frozen cross-member scope",
            "cisco-skill_primary": "HIGH/CRITICAL", "cisco-mcp_primary": "retained native non-infrastructure security finding",
            "sentinel_primary": "HIGH/CRITICAL", "mcp-sec-audit_primary": "native total risk score >=25",
            "secondary": "native any_alert; advisory native thresholds are uncalibrated",
            "controls": "raw control flag rate; no new false-positive adjudication",
            "wilson95": "descriptive binomial interval; convenience/clustered samples limit population inference",
            "incomplete": "excluded from paired intersections; retained in all planned denominators",
            "unsupported": "no native source/composition pairing; no claim of runtime safety from no-trigger N/A"}}
    print(json.dumps({"fugu_attempts": len(fugu_calls), "competitor_attempts": len(native_calls),
                     "fugu_statuses": dict(Counter(r["status"] for r in fugu["rows"])),
                     "competitor_statuses": dict(Counter(r["status"] for r in native["rows"]))}))
    if args.output:
        assert all(r["status"] != "in_progress" for r in native["rows"])
        assert all(r["reasons"] for r in native["rows"] if r["status"] == "unattempted")
        args.output.mkdir(parents=True, exist_ok=True)
        write(args.output / "results.json", result)
        with (args.output / "sdk-calls.jsonl").open("w") as handle:
            for row in calls:
                handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
