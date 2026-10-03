"""Dated source/inference charts, with historical same-input comparators."""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench.current_limits import (FROZEN, case_target, fingerprint, hash_json, read_json,
                                 sha, summarize_rows, write_json)


def comparison_data(fresh: dict, manifest: dict, competitors: dict) -> dict:
    common = [c for c in manifest["cases"] if c["cohort"] in {"mcptox", "clean_descriptions"}]
    attacks = [c["id"] for c in common if c["kind"] == "malicious"]
    controls = [c["id"] for c in common if c["kind"] == "benign"]
    rows = {r["id"]: r for r in fresh["rows"]}
    completed = {key for key, row in rows.items() if row.get("complete")}
    primary = {"fugu": {
        "execution": "fresh" if not fresh.get("synthetic") else "synthetic offline fixture",
        "planned_attacks": len(attacks), "planned_controls": len(controls),
        "attack_detected": sum(key in completed and rows[key].get("detected") is True for key in attacks),
        "attack_missed": sum(key in completed and rows[key].get("detected") is False for key in attacks),
        "attack_incomplete": sum(key not in completed and rows.get(key, {}).get("status") != "unattempted"
                                 and key in rows for key in attacks),
        "attack_unattempted": sum(key not in rows or rows[key].get("status") == "unattempted" for key in attacks),
        "raw_benign_flags": sum(rows.get(key, {}).get("detected") is True for key in controls),
        "control_incomplete": sum(key not in completed for key in controls),
        "confirmed_false_positives": sum(rows.get(key, {}).get("adjudicated_false_positive") is True for key in controls),
        "pending_adjudication": sum(rows.get(key, {}).get("detected") is True and
                                     rows[key].get("adjudicated_false_positive") is None for key in controls),
    }}
    primary["fugu"]["attack_planned_rate"] = primary["fugu"]["attack_detected"] / len(attacks) if attacks else None
    maps = {}
    paired = set(completed)
    for name, document in competitors.items():
        tool_rows = {r["id"]: r for r in document["results"]}
        maps[name] = tool_rows
        available = {key for key, row in tool_rows.items() if row["status"] == "completed"}
        paired &= available
        good_attacks = [key for key in attacks if key in available]
        positive = sum(tool_rows[key].get("flagged_medium") is True for key in good_attacks)
        primary[name] = {"execution": "historical", "version": document.get("version"),
                         "source_commit": document.get("source_commit"),
                         "pinned_context": document.get("pinned_context"),
                         "planned_attacks": len(attacks), "completed_attacks": len(good_attacks),
                         "attack_medium_positive": positive,
                         "attack_medium_rate": positive / len(good_attacks) if good_attacks else None,
                         "attack_native_positive": sum(tool_rows[key].get("flagged_native") is True for key in good_attacks),
                         "unavailable_attack_ids": [key for key in attacks if key not in available],
                         "raw_benign_flags": sum(key in available and tool_rows[key].get("flagged_medium") is True for key in controls),
                         "control_unavailable_ids": [key for key in controls if key not in available]}
    paired_attacks = [key for key in attacks if key in paired]
    paired_controls = [key for key in controls if key in paired]
    pair_counts = {"fugu": {"attack_medium_positive": sum(rows[key].get("detected") is True for key in paired_attacks)}}
    for name, tool_rows in maps.items():
        pair_counts[name] = {"attack_medium_positive": sum(tool_rows[key].get("flagged_medium") is True
                                                          for key in paired_attacks)}
    for group in pair_counts.values():
        group["attack_denominator"] = len(paired_attacks)
        group["attack_medium_rate"] = group["attack_medium_positive"] / len(paired_attacks) if paired_attacks else None
    return {"primary": primary, "paired": pair_counts, "paired_attack_ids": paired_attacks,
            "paired_control_ids": paired_controls, "excluded_ids": [c["id"] for c in common if c["id"] not in paired],
            "thresholds": {"fugu": "any finding medium+", "fuzzd": "any unsuppressed finding medium+",
                           "mcp-sec-audit": "aggregate risk medium+ (25+); native capability separate"}}


def chart_data(fresh: dict, manifest: dict, competitors: dict, *, historical_telemetry=None) -> dict:
    return {"schema": 1, "scope": fresh.get("scope", "S0/S1/S2/S4 and source composition only"),
            "measured_utc": fresh.get("measured_utc"), "synthetic": bool(fresh.get("synthetic")),
            "cost": None, "cost_status": "not measured", "usage": fresh.get("usage", {}),
            "limits": fresh.get("limits"), "engine": fresh.get("engine"),
            "comparison": comparison_data(fresh, manifest, competitors),
            "cohorts": summarize_rows(fresh["rows"]), "coverage": fresh.get("coverage", {}),
            "historical_telemetry": historical_telemetry or {"execution": "historical", "status": "not supplied"},
            "fresh_result_sha256": hash_json(fresh),
            "case_manifest_sha256": hash_json(manifest),
            "comparator_result_sha256": {name: hash_json(doc) for name, doc in competitors.items()},
            "caveats": ["Historical/versioned comparator executions, identical inputs only",
                        "Native capability presence does not establish maliciousness",
                        "Raw benign flags and adjudicated false positives are separate",
                        "Harness stated replies do not execute tools",
                        "Detonation/reputation unavailable in this fresh protocol",
                        "Selected small corpus; no population FPR or universal superiority claim"]}


def historical_telemetry(directory: Path = FROZEN) -> dict:
    """Retained SDK ledger context; never a fresh execution or cost estimate."""
    initial = read_json(directory / "fugu.json")
    recovered = read_json(directory / "fugu-recovered.json")
    paths = sorted((directory / "calls").glob("*.json")) + sorted((directory / "recovery/calls").glob("*.json"))
    records = [read_json(path) for path in paths]
    usage = {"attempts": len(records), "provider_errors": None, "orphan_attempts": None,
             "sum_request_duration_s": sum(r.get("duration_s", 0) for r in records),
             "unknown_duration_calls": sum(r.get("duration_s") is None for r in records),
             "unknown_usage_calls": sum(any(r.get("usage", {}).get(k) is None for k in
                 ("prompt_tokens", "completion_tokens")) for r in records),
             "finish_reasons": dict(Counter(r.get("finish_reason") or "unknown" for r in records))}
    for field in ("prompt_tokens", "completion_tokens"):
        values = [r.get("usage", {}).get(field) for r in records]
        unknown = sum(v is None for v in values)
        subtotal = sum(v for v in values if v is not None)
        usage[field + "_known_subtotal"] = subtotal
        usage[field + "_unknown_calls"] = unknown
        usage[field + "_total"] = subtotal if not unknown else None
    hashes = {p.relative_to(directory).as_posix(): sha(p.read_bytes()) for p in paths}
    hashes.update({name: sha((directory / name).read_bytes()) for name in ("fugu.json", "fugu-recovered.json")})
    exposure = {"status": "not supplied"}
    bounds_path, cases_path = directory / "harness-mount-bounds.json", directory / "cases.json"
    if bounds_path.exists() and cases_path.exists():
        bounds = read_json(bounds_path)["rows"]
        contexts = {}
        for case in read_json(cases_path)["cases"]:
            for member in case.get("members") or [{"dir": None}]:
                prefix = member["dir"] + "/" if member["dir"] else ""
                input_hashes = {n[len(prefix):]: h for n, h in case["input_sha256"].items() if n.startswith(prefix)}
                name = case["id"] + ("/" + member["dir"] if member["dir"] else "")
                contexts[name] = fingerprint(input_hashes)
        omitted = {contexts[r["context"]] for r in bounds if r["content_omitted_by_mount_budget"] > 0}
        red = {contexts[r["context"]] for r in bounds if r["mounted_packet_chars"] > r["targeted_probe_packet_char_limit"]}
        exposure = {"status": "offline derived historical bounds", "contexts": len(bounds),
                    "unique_inputs": len(set(contexts.values())), "mount_omitted_unique_inputs": len(omitted),
                    "red_truncated_unique_inputs": len(red), "mount_content_cap": 4000, "red_packet_cap": 2500}
        hashes.update({p.name: sha(p.read_bytes()) for p in (bounds_path, cases_path)})
    return {"execution": "historical", "scope": "Retained S2/S4 SDK requests including recovery; other stages excluded",
            "source_directory": "bench/results/2026-10-02-full", "usage": usage,
            "source_sha256": hashes, "ledger_manifest_sha256": hash_json(hashes),
            "initial_full_capability_completed": sum(r["complete"] for r in initial["rows"]),
            "recovered_full_capability_completed": sum(r["complete"] for r in recovered["rows"]),
            "output_caps": dict(Counter(str(r["max_tokens"]) for r in records)),
            "structured_retry_requests": sum(bool(r.get("structured_retry_index")) for r in records),
            "super_empty_length_requests": sum(r.get("finish_reason") == "length" and
                not (r.get("raw_response") or "").strip() and "super" in r["requested_model"].lower() for r in records),
            "later_saved_response_recoveries": len(list((directory / "recovery/calls").glob("*.json"))),
            "exposure": exposure,
            "cost": None, "caveat": "Historical full-capability completion and current source/inference completion differ"}


def load_competitors(manifest: dict, directory: Path) -> dict:
    import json
    setup = read_json(directory / "setup.json")
    result = {name: read_json(directory / file) for name, file in (
        ("fuzzd", "fuzzd.json"), ("mcp-sec-audit", "mcp-sec-audit.json"))}
    for name, key in (("fuzzd", "fuzzd"), ("mcp-sec-audit", "mcp_sec_audit")):
        pinned = setup[key]
        if result[name]["source_commit"] != pinned["source_commit"] or result[name]["version"] != pinned["version"]:
            raise ValueError("comparator version mismatch")
        result[name]["pinned_context"] = {k: v for k, v in pinned.items()
                                          if k in {"source_commit", "version", "binary_sha256", "cargo_lock_sha256", "rules_sha256"}}
    maps = {name: {row["id"]: row for row in doc["results"]} for name, doc in result.items()}
    for case in manifest["cases"]:
        if case["cohort"] not in {"mcptox", "clean_descriptions"}:
            continue
        packet = case_target(case) / "tools.json"
        if sha(packet.read_bytes()) != case["input_sha256"]["tools.json"]:
            raise ValueError("current comparator input hash mismatch")
        tools = read_json(packet)["tools"]
        if len(tools) != 1 or set(tools[0]) != {"name", "description", "inputSchema"} or tools[0]["inputSchema"] != {}:
            raise ValueError("description adapter contract changed")
        wrapper = {"tool_name": tools[0]["name"], "tool_content": tools[0]["description"]}
        if maps["fuzzd"][case["id"]]["packet_sha256"] != sha(packet.read_bytes()):
            raise ValueError("historical fuzzd input mismatch")
        if maps["mcp-sec-audit"][case["id"]]["wrapper_sha256"] != sha(json.dumps(wrapper, ensure_ascii=False).encode()):
            raise ValueError("historical mcp-sec adapter mismatch")
    return result


def render(data: dict, output: Path) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    output.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "svg.fonttype": "none", "savefig.facecolor": "white"})
    prefix = "SYNTHETIC OFFLINE FIXTURE\n" if data["synthetic"] else ""
    names = []

    def save(fig, name):
        if not data["synthetic"]:
            engine = data.get("engine") or {}
            limits = data.get("limits") or {}
            fig.text(.05, .92, f"Measured UTC: {data.get('measured_utc') or 'unavailable'}; "
                     f"engine: {engine.get('commit', 'unavailable')[:12]}; "
                     f"output cap: {limits.get('llm_max_output_tokens', 'unavailable')}", fontsize=9)
        fig.savefig(output / (name + ".png"), dpi=180)
        fig.savefig(output / (name + ".svg"))
        plt.close(fig)
        names.extend([name + ".png", name + ".svg"])

    primary = data["comparison"]["primary"]
    fig, axes = plt.subplots(1, 2, figsize=(13.5, 7.2), gridspec_kw={"width_ratios": [1.4, 1]})
    fig.suptitle(prefix + "Fixed descriptions: current source/inference and historical tools", fontsize=13, y=.97)
    labels, counts = [], []
    for name, row in primary.items():
        if name == "fugu":
            labels.append("Fugu current profile")
            counts.append([row["attack_detected"], row["attack_missed"], row["attack_incomplete"], row["attack_unattempted"]])
        else:
            labels.append(f"{name} {row.get('version') or ''}\nHistorical")
            good = row["attack_medium_positive"]
            counts.append([good, row["completed_attacks"] - good, 0, len(row["unavailable_attack_ids"])])
    colors = ["#267d72", "#c5ced4", "#d49a3f", "#855d95"]
    left = [0] * len(labels)
    for column, title in enumerate(["Detected medium+", "Missed", "Incomplete", "Unattempted / unavailable"]):
        values = [row[column] for row in counts]
        axes[0].barh(labels, values, left=left, color=colors[column], label=title)
        for index, (start, value) in enumerate(zip(left, values)):
            if value:
                axes[0].text(start + value / 2, index, str(value), va="center", ha="center",
                             color="white" if column in (0, 3) else "#26333e", fontsize=9)
        left = [a + b for a, b in zip(left, values)]
    for index, (row, total) in enumerate(zip(counts, left)):
        axes[0].text(total + .15, index, f"{row[0]}/{total} planned", va="center", fontsize=9)
    maximum = max(left, default=0)
    axes[0].set_xlim(0, maximum + max(3, maximum * .28))
    axes[0].invert_yaxis()
    axes[0].set_xlabel("Planned poisoned-description cases")
    axes[0].legend(loc="upper left", bbox_to_anchor=(0, -.22), fontsize=8, ncol=2)
    control_flags = [row["raw_benign_flags"] for row in primary.values()]
    axes[1].barh(labels, control_flags, color="#547b9d")
    axes[1].invert_yaxis()
    denominator = primary["fugu"]["planned_controls"]
    axes[1].set_xlim(0, max(denominator, 1))
    axes[1].set_xlabel(f"Raw flags on {denominator} constructed clean descriptions")
    fugu = primary["fugu"]
    axes[1].set_title(f"Confirmed false positives: {fugu['confirmed_false_positives']}\n"
                      f"Pending adjudication: {fugu['pending_adjudication']}\n"
                      f"Incomplete clean cases: {fugu['control_incomplete']}", fontsize=10)
    paired = data["comparison"]["paired"]
    pair_text = "; ".join(f"{name}: {r['attack_medium_positive']}/{r['attack_denominator']}"
                          for name, r in paired.items())
    native_text = "; ".join(f"{name}: {r['attack_native_positive']}/{r['completed_attacks']}"
                            for name, r in primary.items() if name != "fugu")
    fig.text(.04, .04, "Secondary complete paired subset (same excluded IDs): " + pair_text + "\n"
             "Historical native any-finding/capability flags: " + (native_text or "unavailable") + "\n"
             "Medium+ thresholds are tool-specific; capability presence does not establish maliciousness.\n"
             "Detonation/reputation excluded. Harness replies describe behavior; tools are not executed.", fontsize=9)
    fig.subplots_adjust(left=.15, right=.97, top=.76, bottom=.36, wspace=.6)
    save(fig, "common-results")

    cohorts = data["cohorts"]
    fig, ax = plt.subplots(figsize=(11, 6.6))
    labels = [f"{row['cohort']} / {row['kind']}" for row in cohorts]
    left = [0] * len(cohorts)
    for key, color, title in (("completed", "#267d72", "Source/inference complete"),
                              ("incomplete", "#d49a3f", "Incomplete"),
                              ("unattempted", "#855d95", "Unattempted")):
        values = [row[key] for row in cohorts]
        ax.barh(labels, values, left=left, color=color, label=title)
        left = [a + b for a, b in zip(left, values)]
    ax.invert_yaxis()
    ax.set_xlabel("All planned case rows; dependency reputation expectations unavailable")
    fig.suptitle(prefix + "Case completion in the declared source/inference protocol", fontsize=13, y=.97)
    ax.legend(loc="upper center", bbox_to_anchor=(.5, -.15), ncol=3, fontsize=9)
    fig.subplots_adjust(left=.34, right=.96, top=.86, bottom=.22)
    save(fig, "cohort-coverage")

    usage = data["usage"]
    old = data["historical_telemetry"].get("usage", {})
    fig, axes = plt.subplots(1, 3, figsize=(13, 6.2))
    fig.suptitle(prefix + "SDK ledger context: attempts, known tokens and time", fontsize=13)
    metrics = [("Reserved attempts", "attempts"),
               ("Known completion tokens", "completion_tokens_known_subtotal"),
               ("Summed known SDK seconds", "sum_request_duration_s")]
    for ax, (title, key) in zip(axes, metrics):
        for index, (label, series, color) in enumerate((("Current", usage, "#267d72"),
                                                       ("Historical + recovery", old, "#547b9d"))):
            value = series.get(key)
            if value is not None:
                ax.bar(index, value, color=color)
                ax.text(index, value, f"{value:,.1f}" if isinstance(value, float) else f"{value:,}",
                        ha="center", va="bottom", fontsize=9)
            else:
                ax.text(index, 0, "Unavailable", ha="center", fontsize=9)
        ax.set_xticks([0, 1], ["Current", "Historical + recovery"])
        ax.set_title(title, fontsize=11)
        ax.tick_params(axis="x", labelrotation=15)
        ax.margins(y=.2)
    fig.text(.04, .04, f"Current provider errors: {usage.get('provider_errors', 'unknown')}; orphans: {usage.get('orphan_attempts', 'unknown')}; "
             f"unknown usage: {usage.get('unknown_usage_calls', 'unknown')}; unknown duration: {usage.get('unknown_duration_calls', 'unknown')}.\n"
             f"Known prompt tokens — current: {usage.get('prompt_tokens_known_subtotal', 'unknown')}; "
             f"historical: {old.get('prompt_tokens_known_subtotal', 'unknown')}.\n"
             "Historical S2/S4 records include later recovery; profiles and other audit capabilities differ.\n"
             "Token/latency savings are unmeasured. Unknown totals stay null; cost and remaining quota unknown.", fontsize=9)
    fig.subplots_adjust(left=.08, right=.98, top=.8, bottom=.31, wspace=.5)
    save(fig, "call-telemetry")

    coverage = data["coverage"]
    fig, axes = plt.subplots(1, 2, figsize=(13, 6.4))
    fig.suptitle(prefix + "Distinct-input omissions and native response recovery", fontsize=13)
    entries = [("S2 submitted", "semantic", "submitted_chars"),
               ("S2 omitted", "semantic", "omitted_chars"),
               ("S4 mounted content", "harness", "mounted_content_chars"),
               ("S4 omitted", "harness", "omitted_chars"),
               ("RED mounted packet", "harness", "red_mounted_chars")]
    for index, (label, stage, key) in enumerate(entries):
        measure = coverage.get(stage, {}).get(key, {})
        value = measure.get("total")
        if value is None:
            axes[0].text(0, index, f"Unreported; unknown audits: {measure.get('unknown_audits', '?')}", va="center", fontsize=9)
        else:
            axes[0].barh(index, value, color="#547b9d")
            axes[0].text(value, index, f" {value:,}", va="center", fontsize=9)
    axes[0].set_yticks(range(len(entries)), [e[0] for e in entries])
    axes[0].set_ylim(len(entries) - .5, -.5)
    axes[0].set_xlabel("Total characters over distinct input audits")
    axes[0].margins(x=.3)
    parsing = coverage.get("parsing", {})
    keys = [("Parse errors", "parse_error_records"), ("Call/validation errors", "call_error_records"),
            ("Retry recoveries", "retry_recoveries"), ("Reparse recoveries", "reparse_recoveries"),
            ("Unresolved recoveries", "unresolved_recoveries"), ("Super retry records", "super_retry_records")]
    for index, (label, key) in enumerate(keys):
        value = parsing.get(key)
        if value is None:
            axes[1].text(0, index, "Unreported", va="center", fontsize=9)
        else:
            axes[1].barh(index, value, color="#d49a3f")
            axes[1].text(value, index, f" {value}", va="center", fontsize=9)
    axes[1].set_yticks(range(len(keys)), [e[0] for e in keys])
    axes[1].set_ylim(len(keys) - .5, -.5)
    axes[1].set_xlabel("Native metadata records; SDK attempts counted in journal")
    axes[1].margins(x=.3)
    historical = data["historical_telemetry"]
    exposure = historical.get("exposure", {})
    fig.text(.04, .04, f"Observed distinct audits: {coverage.get('unique_audits', 'unknown')}; "
             f"planned: {coverage.get('planned_unique_audits', 'unknown')}. Cached contexts count once.\n"
             "Native recovery/lineage references are not extra calls. Missing telemetry does not establish zero omission.\n"
             f"Historical retained ledger: {historical.get('structured_retry_requests', 'unknown')} structured retries; "
             f"{historical.get('later_saved_response_recoveries', 'unknown')} later Super recoveries.\n"
             f"Historical derived mount omission: {exposure.get('mount_omitted_unique_inputs', 'unknown')} unique inputs; "
             f"RED truncation: {exposure.get('red_truncated_unique_inputs', 'unknown')}. Source exposure profile differs.", fontsize=9)
    fig.subplots_adjust(left=.17, right=.94, top=.82, bottom=.26, wspace=1.05)
    save(fig, "input-coverage")
    write_json(output / "chart-data.json", data)
    return names


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--historical-competitors", type=Path, default=FROZEN / "competitors")
    args = parser.parse_args(argv)
    fresh = read_json(args.source / "fugu.json")
    manifest = read_json(args.source / "cases.json")
    competitors = load_competitors(manifest, args.historical_competitors)
    render(chart_data(fresh, manifest, competitors, historical_telemetry=historical_telemetry()), args.output)


if __name__ == "__main__":
    main()
