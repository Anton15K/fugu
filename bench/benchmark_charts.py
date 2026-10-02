"""Render benchmark SVG/PNG and CSV from retained results (offline, no API calls).

MPLCONFIGDIR=/tmp/fugu-mpl /tmp/fugu-charts-venv/bin/python -m bench.benchmark_charts
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = ROOT / 'bench/results/2026-10-02'
DEFAULT_OUTPUT = ROOT / 'docs/benchmark-charts'


def percentage(numerator, denominator):
    if numerator is None or denominator in (None, 0):
        return None
    if denominator < 0 or not 0 <= numerator <= denominator:
        raise ValueError('Invalid numerator/denominator')
    return 100 * numerator / denominator


def export_table(rows: list[dict], path: Path):
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def dataset(results: Path) -> list[dict]:
    rows = []
    for name in ('static', 'semantic'):
        doc = json.loads((results / f'{name}.json').read_text())
        for item in doc['summary']:
            planned = sum(s.startswith(item['set'] + '/') for s in doc['selected_ids']) if item['set'] != 'crafted' else item['attempted']
            rows.append({
                'tool': 'Fugu', 'provenance': 'fresh label-free',
                'cohort': item['set'], 'mode': item['mode'],
                'metric': 'attack detection' if item['kind'] == 'malicious' else 'benign flag rate',
                'numerator': item['flagged'], 'denominator': planned,
                'completed': item['completed'],
                'incomplete': item['incomplete'],
                'planned': planned,
                'percent': percentage(item['flagged'], planned),
                'completed_case_percent': percentage(item['flagged'], item['completed']),
                'source': str((results / f'{name}.json').relative_to(ROOT)),
                'note': '>=medium observed flags per planned case; incomplete cases unknown; no S3/S4; benign labels provisional',
            })
    index = json.loads((results / 'sources/index.json').read_text())

    def url(repo, path):
        return next(r['url'] for r in index if r['repo'] == repo and r['path'] == path)

    for tool, numerator, denominator, percent, source, note in [
        ('fuzzd v0.13', 440, 485, percentage(440, 485),
         url('ksek87/fuzzd', 'bench/README.md'), 'Published tool-name-in-output rule; not rerun'),
        ('mcp-sec-audit detection README', 367, 491, percentage(367, 491),
         url('nyit-vancouver/mcp-sec-audit', 'detection/README.md'), 'Conflicts with root README at same revision; not rerun'),
        ('mcp-sec-audit root README', None, 491, 94.7,
         url('nyit-vancouver/mcp-sec-audit', 'README.md'), 'Reported percentage; numerator unpublished; conflict unresolved'),
        ('Snyk Agent Scan', None, None, None,
         url('snyk/agent-scan', 'docs/cli-reference.md'), 'Not rerun; authenticated hosted analysis; no comparable measurement'),
    ]:
        rows.append({'tool': tool, 'provenance': 'published only', 'cohort': 'MCPTox (publisher protocol)',
                     'mode': 'publisher-specific', 'metric': 'published coverage', 'numerator': numerator,
                     'denominator': denominator, 'completed': None, 'incomplete': None, 'planned': None,
                     'percent': percent, 'completed_case_percent': None, 'source': source, 'note': note})
    return rows


def charts(rows: list[dict], output: Path):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter

    navy, teal, amber, gray = '#183548', '#137F82', '#BD7626', '#637381'
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 11,
                         'axes.spines.top': False, 'axes.spines.right': False,
                         'axes.spines.left': False, 'axes.edgecolor': '#D4DBE0',
                         'svg.fonttype': 'none', 'svg.hashsalt': 'fugu-20261002'})

    def setup(ax):
        ax.set_xlim(0, 100)
        ax.xaxis.set_major_formatter(PercentFormatter(100))
        ax.set_xticks([0, 25, 50, 75, 100])
        ax.grid(axis='x', color='#E5EAEE', zorder=0)
        ax.tick_params(axis='y', length=0, pad=10)
        ax.set_axisbelow(True)

    def save(fig, stem):
        for ext in ('svg', 'png'):
            fig.savefig(output / f'{stem}.{ext}', dpi=180, facecolor='white',
                        metadata={'Date': None} if ext == 'svg' else {})
            if ext == 'svg':
                path = output / f'{stem}.{ext}'
                path.write_text('\n'.join(line.rstrip() for line in path.read_text().splitlines()) + '\n')
        plt.close(fig)

    fresh = [r for r in rows if r['provenance'] == 'fresh label-free']
    live_attack = next(r for r in fresh if r['cohort'] == 'mcptox_pure' and r['mode'] == 'S0+S1+S2')
    live_misses = live_attack['completed'] - live_attack['numerator']
    conditional = (f"{live_attack['numerator']}/{live_attack['completed']} = "
                   f"{live_attack['completed_case_percent']:.1f}%") if live_attack['completed'] else 'unavailable'
    labels = {'crafted': 'Crafted corpus', 'mcptox_pure': 'MCPTox pure_tool',
              'mcptox_full': 'MCPTox full corpus', 'fuzzd_clean': 'Constructed clean tools',
              'public_skills': 'Public skills (provisional benign)'}
    fig, axes = plt.subplots(1, 2, figsize=(15, 7.8), gridspec_kw={'wspace': .8})
    fig.subplots_adjust(left=.20, right=.97, bottom=.24, top=.82)
    fig.suptitle('Fugu: fresh detection and benign flags', x=.05, ha='left', y=.97,
                 fontsize=22, weight='bold', color=navy)
    fig.text(.05, .915, '2026-10-02  |  Frozen engine  |  Any finding ≥ medium  |  No detector tuning', color=gray)
    for ax, metric, title in zip(axes, ('attack detection', 'benign flag rate'),
                               ('Attack detection ↑', 'Benign flag rate ↓')):
        selected = [r for r in fresh if r['metric'] == metric]
        setup(ax)
        ax.set_title(title, loc='left', color=navy, pad=18, weight='bold')
        ax.set_yticks(range(len(selected)), [labels[r['cohort']] + '\n' + r['mode'] for r in selected])
        ax.invert_yaxis()
        for y, r in enumerate(selected):
            value = r['percent']
            color = teal if r['mode'].endswith('+S2') else navy
            if value is None:
                ax.text(2, y, 'No completed measurement', va='center', color=gray)
                continue
            ax.barh(y, 100, height=.48, color='#EFF2F4', zorder=1)
            ax.barh(y, value, height=.48, color=color, zorder=2)
            if r['incomplete']:
                failed_percent = percentage(r['incomplete'], r['planned'])
                ax.barh(y, failed_percent, left=100-failed_percent, height=.48, color=amber, hatch='//', zorder=2)
            text = f"{r['numerator']}/{r['denominator']}  ({value:.1f}%)"
            ax.text(value - 2 if value > 70 else value + 2, y, text, va='center',
                    ha='right' if value > 70 else 'left',
                    color='white' if value > 70 else navy, fontsize=10)
            if r['incomplete']:
                ax.text(0, y + .35,
                        f"{r['incomplete']} incomplete; {r['numerator']}/{r['completed']} completed", fontsize=8, color=amber)
    fig.text(.05, .17, 'Colored = observed detections/flags   ·   Light gray = completed without a flag   ·   Amber hatching = incomplete', fontsize=10, color=navy)
    fig.text(.05, .13, f"Primary rates use planned cases. Live attacks: {live_attack['numerator']} detections + {live_misses} completed misses + {live_attack['incomplete']} incomplete; conditional {conditional}.", fontsize=10, color=navy)
    fig.text(.05, .095, 'Live sample: 10 attacks per paradigm; 20 constructed clean tool descriptions; 5 public skills per repository. Cohorts stay separate.', fontsize=10, color=gray)
    fig.text(.05, .06, 'Tool inputs contain names and descriptions only. Benign flags require adjudication. These charts do not measure S3 detonation or S4 behavior.', fontsize=10, color=gray)
    save(fig, 'fresh-results')

    fig, ax = plt.subplots(figsize=(13, 7.6))
    fig.subplots_adjust(left=.29, right=.97, bottom=.27, top=.78)
    fig.suptitle('Published comparator claims and fresh Fugu results', x=.05, ha='left',
                 y=.96, fontsize=20, weight='bold', color=navy)
    fig.text(.05, .902, 'Different inputs, denominators and detection rules — this is not a performance ranking.', color=gray)
    setup(ax)
    ax.set_ylim(-1.6, 3.9)
    published = [r for r in rows if r['tool'] == 'fuzzd v0.13'][0]
    low, high = 100 * 367 / 491, 94.7
    ax.barh(3, published['percent'], height=.46, color=gray)
    ax.text(2, 3, '440/485 · 90.7% · publisher result', va='center', color='white')
    ax.barh(2, high-low, left=low, height=.46, color=amber, alpha=.5, hatch='//')
    ax.plot([low, high], [2, 2], '|', color=amber, markersize=21, markeredgewidth=2)
    ax.text(2, 2, '74.7% (367/491) ↔ 94.7% (n=491)', va='center', color=navy, fontsize=10)
    ax.text(2, 1.56, 'CONFLICTING READMEs at one pinned revision; band is not a confidence interval', color=amber, fontsize=9)
    ax.axhline(1.1, color='#D4DBE0', linewidth=1)
    fugu = [r for r in fresh if r['cohort'] == 'mcptox_pure']
    for y, mode in [(0, 'S0+S1'), (-1, 'S0+S1+S2')]:
        r = next(r for r in fugu if r['mode'] == mode)
        if r['percent'] is not None:
            if r['incomplete']:
                ax.barh(y, 100, height=.46, color='#EFF2F4')
                failed_percent = percentage(r['incomplete'], r['planned'])
                ax.barh(y, failed_percent, left=100-failed_percent, height=.46, color=amber, hatch='//')
            ax.barh(y, r['percent'], height=.46, color=teal if mode.endswith('+S2') else navy)
            text = f"{r['numerator']}/{r['denominator']} · {r['percent']:.1f}%"
            ax.text(r['percent']-2 if r['percent'] > 65 else r['percent']+2, y, text,
                    ha='right' if r['percent'] > 65 else 'left', va='center',
                    color='white' if r['percent'] > 65 else navy)
        if r['incomplete']:
            ax.text(1, y-.35, f"{live_misses} completed misses + {r['incomplete']} incomplete; conditional {conditional}", color=amber, fontsize=9)
    ax.set_yticks([3, 2, 0, -1], ['fuzzd v0.13\nPublished · name-in-output rule',
                                 'mcp-sec-audit\nPublished · unresolved conflict',
                                 'Fugu S0+S1\nFresh · full 485 description set',
                                 'Fugu S0+S1+S2\nFresh · balanced 30-case sample'])
    fig.text(.05, .17, 'Snyk Agent Scan: no comparable measurement; no zero-valued bar. Hosted authenticated analysis was not run.', fontsize=10, color=gray)
    fig.text(.05, .13, 'Historical Fugu 484/485 is excluded: benchmark labels appeared inside judge input. Competitor binaries were not rerun.', fontsize=10, color=navy)
    fig.text(.05, .09, 'Fresh Fugu uses name+description JSON packets and ≥medium severity. Comparator thresholds and artifacts differ.', fontsize=10, color=gray)
    fig.text(.05, .05, 'Primary sources, pinned revisions, exact counts and machine-readable values: comparison-data.csv and docs/head-to-head.md.', fontsize=10, color=gray)
    save(fig, 'competitor-context')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, default=DEFAULT_RESULTS)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rows = dataset(args.results)
    export_table(rows, args.output / 'comparison-data.csv')
    (args.output / 'comparison-data.json').write_text(json.dumps(rows, indent=2) + '\n')
    charts(rows, args.output)


if __name__ == '__main__':
    main()
