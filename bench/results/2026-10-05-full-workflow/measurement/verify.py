"""Verify the portable measurement without raw payloads, credentials or network."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_keys(value):
    forbidden = {"api_key", "authorization", "password", "messages", "raw_response",
                 "tool_content", "content", "findings", "evidence", "source_text", "prompt", "reply"}
    if isinstance(value, dict):
        assert not forbidden.intersection(k.lower() for k in value), "payload or credential field in export"
        for child in value.values():
            safe_keys(child)
    elif isinstance(value, list):
        for child in value:
            safe_keys(child)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measurement", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--envelope", type=Path)
    args = parser.parse_args()
    root = args.measurement
    cases_path = args.cases or root.parent / "cases-v2.json"
    envelope_path = args.envelope or root.parent / "plan.json"
    cases = read(cases_path)["cases"]
    envelope = read(envelope_path)
    result = read(root / "results.json")
    calls = [json.loads(line) for line in (root / "sdk-calls.jsonl").read_text().splitlines()]
    assert fingerprint(envelope_path) == "568166b50a97997ba12667635ac2eef4ca99dc2ddb1caca1306f3eb83aef4b40"
    assert fingerprint(cases_path) == "250aeeeaef812c39e5a10a7caec55bc36d79c1babb0066ce47dd80ede4c21143"
    assert result["protocol"] == "fugu-full-workflow-safe-measurement-v1" and result["schema"] == 1
    assert result["plan_sha256"] == envelope["fugu"]["plan_json_sha256"]
    assert result["data_release_ref"] == "qitem-20261005103009-2753fe32"
    assert result["profile"] == envelope["fugu"]["profile"]
    assert result["usage"]["all"]["known_cost"] is None
    assert result["usage"]["all"]["remaining_quota"] is None
    safe_keys(result)
    safe_keys(calls)
    fugu, native = result["fugu_rows"], result["competitor_rows"]
    assert result["fugu_planned"] == len(fugu) == len(cases) == 140
    assert result["competitor_planned"] == len(native) == 320
    assert len({r["id"] for r in fugu}) == 140
    for original, row in zip(cases, fugu):
        assert all(original[k] == row[k] for k in ("id", "cohort", "kind", "input_sha256", "provenance", "overlap"))
        assert type(row["complete"]) is bool and row["adjudicated_false_positive"] is None
        if row["complete"]:
            assert row["status"] == "completed" and type(row["detected"]) is bool
            assert all(s["state"] in {"completed", "not_applicable"} for s in row["stages"])
    expected = [(scanner, c["id"]) for scanner, cohort in
                (("sentinel", "mcp_metadata"), ("mcp-sec-audit", "mcp_metadata"),
                 ("cisco-skill", "skills"), ("cisco-mcp", "mcp_metadata"))
                for c in cases if c["cohort"] == cohort]
    assert [(r["scanner"], r["id"]) for r in native] == expected
    by_id = {r["id"]: r for r in fugu}
    for row in native:
        assert row["input_sha256"] == by_id[row["id"]]["input_sha256"]
        assert row["status"] != "in_progress"
        assert row["reasons"] if row["status"] == "unattempted" else True
        if row["complete"]:
            assert row["status"] == "completed" and type(row["flagged"]) is bool and type(row["any_alert"]) is bool
    for journal in ("fugu-1", "fugu-2", "fugu-3", "shared-cisco"):
        records = [c for c in calls if c["journal"] == journal]
        assert [r["number"] for r in records] == list(range(1, len(records) + 1))
        assert len(records) <= 1800
    for call in calls:
        assert call["requested_model"] in envelope["fugu"]["models"]
        if call["lane"] == "fugu":
            assert call["max_tokens"] == 4096 and call["journal"] in {"fugu-1", "fugu-2", "fugu-3"}
        else:
            scanner = call["stage"].removeprefix("competitor:")
            contract = envelope["competitors"]["native_llm"][scanner]
            assert call["max_tokens"] == contract["output_cap"] and call["sdk_max_retries"] == 0
            assert call["temperature"] == contract["temperature"]
            assert call["timeout_seconds"] == contract["timeout_s"]
            assert call["native_max_retries"] == contract["native_max_retries"]
    assert len(calls) <= envelope["bounds"]["all_sdk"]
    assert sum(c["max_tokens"] for c in calls) <= envelope["bounds"]["requested_output_tokens_max"]
    for lane, selected in (("all", calls), ("fugu", [c for c in calls if c["lane"] == "fugu"]),
                           ("competitors", [c for c in calls if c["lane"] == "competitor"])):
        usage = result["usage"][lane]
        assert usage["attempts"] == len(selected)
        assert usage["states"] == dict(Counter(c["state"] for c in selected))
        assert usage["requested_completion_token_envelope"] == sum(c["max_tokens"] for c in selected)
        for field in ("prompt_tokens", "completion_tokens"):
            known = [(c.get("usage") or {}).get(field) for c in selected]
            values = [v for v in known if type(v) is int and v >= 0]
            assert usage["tokens"][field]["known_subtotal"] == sum(values)
            assert usage["tokens"][field]["unknown_calls"] == len(selected) - len(values)
            assert usage["tokens"][field]["total"] == (sum(values) if len(values) == len(selected) else None)
    search = result["usage"]["search"]
    assert search["attempts"] <= envelope["bounds"]["tavily"]
    for pair in result["paired"]:
        planned = [r for r in native if r["scanner"] == pair["scanner"] and r["kind"] == pair["kind"]]
        matched = [r for r in planned if r["complete"] and by_id[r["id"]]["complete"]]
        assert pair["planned"] == len(planned) and pair["matched_ids"] == [r["id"] for r in matched]
        assert pair["matched_complete"] == len(matched)
        assert {r["id"] for r in pair["excluded"]} == {r["id"] for r in planned if r not in matched}
        for field, flags in (("fugu_primary", [by_id[r["id"]]["detected"] for r in matched]),
                             ("native_primary", [r["flagged"] for r in matched]),
                             ("native_any_alert_secondary", [r["any_alert"] for r in matched])):
            count, n = sum(flags), len(flags)
            stat = pair[field]
            assert (stat["flagged"], stat["n"], stat["unflagged"]) == (count, n, n - count)
            assert stat["rate"] == (count / n if n else None)
            if n:
                lower, upper = stat["wilson95"]
                assert 0 <= lower <= count / n <= upper <= 1
                z = 1.959963984540054
                radicand = z * z + 4 * count * (1 - count / n)
                expected_bounds = [(2 * count + z * z + sign * z * math.sqrt(radicand)) /
                                   (2 * (n + z * z)) for sign in (-1, 1)]
                assert all(abs(a - b) < 1e-12 for a, b in zip((lower, upper), expected_bounds))
            else:
                assert stat["wilson95"] is None
        groups = pair["disagreements"]
        assert sorted(x for group in groups.values() for x in group) == sorted(r["id"] for r in matched)
        for name, values in (("fugu_only", (True, False)), ("native_only", (False, True)),
                             ("both_flagged", (True, True)), ("both_unflagged", (False, False))):
            assert groups[name] == [r["id"] for r in matched if (by_id[r["id"]]["detected"], r["flagged"]) == values]
    inventory = root / "inventory.json"
    if inventory.exists():
        manifest = read(inventory)
        assert manifest["schema"] == 2
        for record in manifest["files"]:
            path = Path(record["path"])
            assert not path.is_absolute() and ".." not in path.parts
            assert fingerprint(root / path) == record["sha256"]
    print(json.dumps({"verified": True, "fugu_planned": len(fugu), "competitor_planned": len(native),
                      "sdk_attempts": len(calls), "search_attempts": search["attempts"],
                      "paired_n": {p["scanner"] + ":" + p["kind"]: p["matched_complete"] for p in result["paired"]}}))


if __name__ == "__main__":
    main()
