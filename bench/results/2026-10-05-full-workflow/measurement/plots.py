"""Replot safe measured results only; no inference or private input required."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

plt.rcParams["svg.hashsalt"] = "fugu-full-workflow-20261005"

NAMES = {"sentinel": "Sentinel", "mcp-sec-audit": "MCP-Sec", "cisco-skill": "Cisco Skill", "cisco-mcp": "Cisco MCP"}
BLUE, ORANGE, GRAY = "#1761A0", "#C66D21", "#A7B2BC"


def paired_panel(result, scanners, title, output):
    fig, axes = plt.subplots(1, 2, figsize=(11, 3 + 0.55 * len(scanners)), sharey=True)
    for ax, kind, label in zip(axes, ("malicious", "benign"), ("Attack detection", "Raw control flag rate")):
        rows = [next(p for p in result["paired"] if p["scanner"] == scanner and p["kind"] == kind)
                for scanner in scanners]
        for index, row in enumerate(rows):
            for key, color, offset in (("fugu_primary", BLUE, 0.1), ("native_primary", ORANGE, -0.1)):
                statistic = row[key]
                if statistic["n"]:
                    value, bounds = statistic["rate"], statistic["wilson95"]
                    ax.errorbar(value, index + offset, xerr=[[value - bounds[0]], [bounds[1] - value]],
                                color=color, fmt="o", markersize=6, capsize=3, linewidth=1.7)
            annotation = f"matched n={row['matched_complete']}/{row['planned']}  ·  excluded {len(row['excluded'])}"
            ax.text(0.02, index + 0.30, annotation, fontsize=8.5, color="#485765")
        ax.set_xlim(-0.025, 1.025)
        ax.set_ylim(len(rows) - 0.45, -0.55)
        ax.set_yticks(range(len(scanners)), [NAMES[s] for s in scanners])
        ax.xaxis.set_major_formatter(PercentFormatter(1))
        ax.set_title(label, loc="left", fontsize=11, fontweight="bold")
        ax.grid(axis="x", color="#E1E5EA", linewidth=0.8)
        ax.set_axisbelow(True)
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.tick_params(axis="both", length=0)
    fig.suptitle(title, x=0.08, ha="left", fontsize=15, fontweight="bold")
    fig.legend([plt.Line2D([], [], color=BLUE, marker="o", linestyle=""),
                plt.Line2D([], [], color=ORANGE, marker="o", linestyle="")],
               ["Fugu full workflow", "Native comparator"], loc="lower center", ncol=2,
               bbox_to_anchor=(0.5, 0.06), frameon=False)
    fig.text(0.08, 0.025, "Complete matched cases only. Wilson 95% intervals; clustered convenience inputs and different native thresholds limit inference.",
             fontsize=8, color="#485765")
    fig.subplots_adjust(left=0.15, right=0.97, top=0.79, bottom=0.22, wspace=0.18)
    fig.savefig(output.with_suffix(".png"), dpi=180, facecolor="white")
    fig.savefig(output.with_suffix(".svg"), facecolor="white", metadata={"Date": None})
    plt.close(fig)


def coverage_panel(result, output):
    fig, axes = plt.subplots(1, 2, figsize=(12, 6.8), gridspec_kw={"width_ratios": [1.5, 1]})
    labels, counts = [], []
    for cohort in ("mcp_metadata", "skills", "composition", "source"):
        for kind in ("malicious", "benign"):
            rows = [r for r in result["fugu_rows"] if r["cohort"] == cohort and r["kind"] == kind]
            labels.append(f"{cohort.replace('_', ' ')} · {'attack' if kind == 'malicious' else 'control'}")
            counts.append((sum(r["complete"] and r["detected"] is True for r in rows),
                           sum(r["complete"] and r["detected"] is False for r in rows),
                           sum(not r["complete"] for r in rows)))
    left = [0] * len(counts)
    for index, color, label in ((0, BLUE, "Complete, flagged"), (1, "#6F9EA9", "Complete, unflagged"),
                              (2, GRAY, "Incomplete / unattempted")):
        values = [c[index] for c in counts]
        axes[0].barh(range(len(counts)), values, left=left, color=color, label=label, height=0.65)
        left = [a + b for a, b in zip(left, values)]
    axes[0].set_yticks(range(len(labels)), labels)
    axes[0].invert_yaxis()
    axes[0].set_title("Fugu full workflow · all 140 planned cases", loc="left", fontsize=11, fontweight="bold")
    for i, row in enumerate(counts):
        axes[0].text(sum(row) + 0.8, i, "/".join(map(str, row)), va="center", fontsize=8.5)
    axes[0].set_xlim(0, max(sum(c) for c in counts) + 19)
    axes[0].set_xlabel("Cases · labels at right: flagged / unflagged / incomplete")
    scanners = list(NAMES)
    left = [0] * len(scanners)
    for complete, color, label in ((True, BLUE, "Native complete"), (False, GRAY, "Native incomplete / unattempted")):
        values = [sum(r["complete"] is complete for r in result["competitor_rows"] if r["scanner"] == s) for s in scanners]
        axes[1].barh(range(len(scanners)), values, left=left, color=color, label=label, height=0.6)
        left = [a + b for a, b in zip(left, values)]
    axes[1].set_yticks(range(len(scanners)), [NAMES[s] for s in scanners])
    axes[1].invert_yaxis()
    axes[1].set_xlim(0, 125)
    for i, scanner in enumerate(scanners):
        rows = [r for r in result["competitor_rows"] if r["scanner"] == scanner]
        completed = sum(r["complete"] for r in rows)
        axes[1].text(len(rows) + 1, i, f"{completed}/{len(rows)}", va="center", fontsize=8.5)
    axes[1].set_title("Native coverage · 320 supported pairs", loc="left", fontsize=11, fontweight="bold")
    axes[1].set_xlabel("Cases · labels at right: complete / planned")
    for ax in axes:
        ax.grid(axis="x", color="#E1E5EA", linewidth=0.8)
        ax.set_axisbelow(True)
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.tick_params(length=0)
        ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), fontsize=8, frameon=False)
    date = result.get("intervals", {}).get("fugu", {}).get("started_utc", "")[:10]
    fig.suptitle("Measured completion coverage" + (f" · {date}" if date else ""), x=0.08, ha="left", fontsize=15, fontweight="bold")
    fig.text(0.08, 0.025, "No source/composition pairing in these measured modes. Composition controls test cross-member scope. No-trigger N/A gives no runtime-safety proof.",
             fontsize=8, color="#485765")
    fig.subplots_adjust(left=0.19, right=0.97, top=0.87, bottom=0.24, wspace=0.42)
    fig.savefig(output.with_suffix(".png"), dpi=180, facecolor="white")
    fig.savefig(output.with_suffix(".svg"), facecolor="white", metadata={"Date": None})
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = json.loads(args.results.read_text())
    assert result["protocol"] == "fugu-full-workflow-safe-measurement-v1"
    args.output.mkdir(parents=True, exist_ok=True)
    date = result.get("intervals", {}).get("fugu", {}).get("started_utc", "")[:10]
    suffix = f" · {date}" if date else ""
    paired_panel(result, ("sentinel", "mcp-sec-audit", "cisco-mcp"), "MCP metadata · native primary flags" + suffix, args.output / "metadata-paired")
    paired_panel(result, ("cisco-skill",), "Skills · supported complete intersections" + suffix, args.output / "skills-paired")
    coverage_panel(result, args.output / "completion-coverage")


if __name__ == "__main__":
    main()
