"""Charts from measured complete-case results; never hide exclusions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('measurement', type=Path)
    parser.add_argument('--output', type=Path,
                        help='Write charts here; defaults to MEASUREMENT/charts.')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np

    root = args.measurement
    data = json.loads((root / 'fugu.json').read_text())
    cmp = json.loads((root / 'mcp-sec-audit.json').read_text())
    by_id = {r['id']: r for r in cmp['results']}
    rows = data['rows']
    common = [r for r in rows if r['cohort'] in ('mcptox', 'clean_descriptions')
              and r['baseline']['complete'] and r['integrated']['complete']
              and by_id[r['id']]['complete']]
    attacks = [r for r in common if r['kind'] == 'malicious']
    clean = [r for r in common if r['kind'] == 'benign']

    def static_flag(row, variant):
        return any(f['severity'] in ('critical', 'high', 'medium')
                   for stage in row[variant]['stages'] if stage['stage'] in ('static', 'concealment')
                   for f in stage['findings'])

    labels = ['Fugu baseline\nS0/S1', 'Fugu integrated\nS0/S1',
              'Fugu baseline\nfull workflow', 'Fugu integrated\nfull workflow',
              'MCP-Sec-Audit\nrisk ≥25', 'MCP-Sec-Audit\nany finding']
    functions = [lambda r: static_flag(r, 'baseline'), lambda r: static_flag(r, 'integrated'),
                 lambda r: r['baseline']['detected'], lambda r: r['integrated']['detected'],
                 lambda r: by_id[r['id']]['flagged'], lambda r: by_id[r['id']]['native_flag']]
    attack_counts = [sum(fn(r) for r in attacks) for fn in functions]
    clean_counts = [sum(fn(r) for r in clean) for fn in functions]
    out = args.output or root / 'charts'
    out.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 10,
                         'axes.spines.top': False, 'axes.spines.right': False})
    colors = ['#8292a8', '#278d89', '#5464a8', '#215ae0', '#b09d75', '#b8ad9a']

    def save(fig, name):
        for ext in ('png', 'svg'):
            fig.savefig(out / f'{name}.{ext}', dpi=180, bbox_inches='tight', facecolor='white')
        plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(14, 6.5))
    for ax, counts, denom, title in [(axes[0], attack_counts, len(attacks), 'Attack cases flagged'),
                                   (axes[1], clean_counts, len(clean), 'Clean description alerts')]:
        ax.bar(np.arange(6), counts, color=colors)
        ax.set_xticks(np.arange(6), labels, fontsize=8)
        ax.set_ylim(0, max(denom, 1) + 1.5)
        ax.set_ylabel('Cases')
        ax.set_title(title)
        for i, count in enumerate(counts):
            ax.text(i, count + .2, f'{count}/{denom}', ha='center', fontweight='bold')
    fig.suptitle('Same descriptions: source scans and the full Fugu workflow', fontsize=15)
    fig.text(.5, .025, f'Matched complete cases only ({len(common)}/{20}); source-only competitor has narrower capabilities.\n'
             'Fugu: medium+; competitor risk≥25 and native any-finding rates shown separately. Thresholds are not calibrated.\n'
             'Alerts are not confirmed exploits. The complete clean control set is small.',
             ha='center', fontsize=9)
    fig.tight_layout(rect=(0, .19, 1, .95))
    save(fig, 'same-input-comparison')

    groups = [('mcptox', 'malicious'), ('crafted', 'malicious'), ('crafted', 'benign'),
              ('composition', 'malicious'), ('composition', 'benign'),
              ('reputation', 'vulnerable_dependency'), ('reputation', 'dependency_control')]
    names = ['External\nattacks', 'Crafted\nattacks', 'Crafted\ncontrols', 'Composition\nattacks',
             'Composition\ncontrols', 'Pinned\nvulnerable dep.', 'Former control\nnow affected']
    fig, ax = plt.subplots(figsize=(12, 6))
    chart_cohorts = []
    for shift, variant, color in [(-.18, 'baseline', colors[2]), (.18, 'integrated', colors[3])]:
        rates = []
        for cohort, kind in groups:
            planned = [r for r in rows if r['cohort'] == cohort and r['kind'] == kind]
            completed = [r for r in planned if r[variant]['complete']]
            flagged = sum(bool(r[variant]['detected']) for r in completed)
            rates.append(100 * flagged / len(completed) if completed else 0)
            chart_cohorts.append({'variant': variant, 'cohort': cohort, 'kind': kind,
                                 'planned': len(planned), 'complete': len(completed), 'flagged': flagged})
        bars = ax.bar(np.arange(len(groups)) + shift, rates, width=.34, color=color, label=f'Fugu {variant}')
        subset = chart_cohorts[-len(groups):]
        for bar, item in zip(bars, subset):
            label = f"{item['flagged']}/{item['complete']}" if item['complete'] else 'N/A'
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height()+2, label,
                    ha='center', fontsize=9, rotation=0)
    ax.set_xticks(np.arange(len(groups)), names)
    ax.set_ylim(0, 119)
    ax.set_ylabel('% of completed cases flagged')
    ax.set_title('Full workflow by case family — incomplete cases excluded', fontsize=14)
    ax.legend(frameon=False)
    fig.text(.5, .025, 'Composition uses composition-rule alerts; dependency probes use measured reputation evidence.\n'
             'Requests 2.32.5 is now affected by CVE-2026-25645; its alert is not a control error.\n'
             'Higher attack alerts / lower clean alerts are desirable. N/A means no complete case in that family.',
             ha='center', fontsize=9)
    fig.tight_layout(rect=(0, .20, 1, 1))
    save(fig, 'full-workflow-cohorts')

    stage_names = ['concealment', 'static', 'semantic', 'harness', 'detonation', 'reputation', 'composition']
    states = ['completed', 'not_applicable', 'partial', 'failed', 'unavailable', 'unattempted']
    palette = ['#278d89', '#b8c2cf', '#e9b34d', '#cb5b68', '#9e8dba', '#dddddd']
    matrix = []
    for name in stage_names:
        matrix.append([sum(s['stage'] == name and s['state'] == status for r in rows
                           for s in r['integrated']['stages']) for status in states])
    fig, ax = plt.subplots(figsize=(11, 5.5))
    left = np.zeros(len(stage_names))
    for index, status in enumerate(states):
        values = np.array([r[index] for r in matrix])
        ax.barh(stage_names, values, left=left, color=palette[index], label=status.replace('_', ' '))
        for y, (base, value) in enumerate(zip(left, values)):
            if value:
                ax.text(base + value/2, y, str(value), ha='center', va='center', fontsize=9)
        left += values
    ax.invert_yaxis()
    ax.set_xlabel('Case stage instances (including reused composition members)')
    ax.set_title('Every capability accounted for in the integrated workflow', fontsize=14)
    ax.legend(ncol=3, frameon=False, loc='upper center', bbox_to_anchor=(.5, -.16))
    fig.tight_layout()
    save(fig, 'capability-coverage')

    extended = json.loads((root / 'extended-static.json').read_text())
    ext_rows = extended['rows']
    ext_attack = [r for r in ext_rows if r['label'] == 'attack' and r['complete']]
    ext_clean = [r for r in ext_rows if r['label'] == 'benign' and r['complete']]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    vals = [sum(r['flagged'] for r in ext_attack), sum(r['flagged'] for r in ext_clean)]
    denoms = [len(ext_attack), len(ext_clean)]
    ax.bar(['External attacks', 'Clean descriptions'], vals, color=[colors[3], colors[1]])
    ax.set_ylim(0, 92)
    for i, (value, denom) in enumerate(zip(vals, denoms)):
        ax.text(i, value + 2, f'{value}/{denom}', ha='center', fontweight='bold')
    ax.set_ylabel('Cases flagged')
    ax.set_title('Additional 140-case static diagnostic — separate study')
    fig.text(.5, .025, 'Source-only S0/S1 integration check; does not measure full-workflow recall.', ha='center', fontsize=9)
    fig.tight_layout(rect=(0, .10, 1, 1))
    save(fig, 'extended-static-diagnostic')
    (out / 'chart-data.json').write_text(json.dumps({
        'common_complete_ids': [r['id'] for r in common], 'common_planned': 20,
        'labels': labels, 'attack_counts': attack_counts, 'attack_denominator': len(attacks),
        'clean_counts': clean_counts, 'clean_denominator': len(clean),
        'cohorts': chart_cohorts, 'stage_names': stage_names, 'states': states, 'coverage': matrix}, indent=2))


if __name__ == '__main__':
    main()
