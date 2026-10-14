"""Render the README chart offline from the adjacent reduced results.json.

Requires report-only matplotlib==3.10.8; adds no application dependency.
Run: python bench/results/2026-10-14-cost-pilot/render_chart.py
"""
from pathlib import Path
import json

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, PercentFormatter

HERE = Path(__file__).resolve().parent


def main():
    data = json.loads((HERE / 'results.json').read_text())
    cases, count = data['cases'], data['planned_cases']
    assert len(cases) == count == 12
    names, correct, costs = [], [], []
    for arm, prefix in [('fugu', 'fugu'), ('agent', 'base_agent')]:
        row = data['summary'][arm]
        assert sum(c[f'{prefix}_correct_final_decision'] for c in cases) == row['correct_final_decisions']
        assert sum(c[f'{prefix}_cost_micro'] for c in cases) == row['latest_cost_micro']
        assert row['issued_final_decisions'] == count
        names.append(row['label'])
        correct.append(row['correct_final_decisions'])
        costs.append(row['latest_cost_micro'] / 1_000_000 / count)

    plt.rcParams.update({
        'font.family': 'DejaVu Sans', 'font.size': 11,
        'axes.spines.top': False, 'axes.spines.right': False,
        'axes.spines.left': False, 'axes.edgecolor': '#D4DBE0',
        'svg.fonttype': 'none', 'svg.hashsalt': 'fugu-cost-pilot-20261014',
    })
    colors = ['#137F82', '#183548']
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 5.0))
    fig.subplots_adjust(left=.12, right=.96, top=.73, bottom=.30, wspace=.55)
    fig.suptitle('Fugu vs. base agent', x=.055, y=.96, ha='left',
                 fontsize=21, fontweight='bold', color='#183548')
    fig.text(.055, .875, 'Latest results on the same 12 pilot cases · 14 October 2026',
             color='#637381', fontsize=11)
    for ax in axes:
        ax.set_yticks([0, 1], names)
        ax.set_ylim(1.6, -.6)
        ax.grid(axis='x', color='#E5EAEE')
        ax.set_axisbelow(True)
        ax.tick_params(axis='both', length=0)
        ax.tick_params(axis='y', pad=8)
    ax = axes[0]
    percentages = [n / count * 100 for n in correct]
    ax.barh([0, 1], percentages, color=colors, height=.48, zorder=3)
    ax.set_xlim(0, 100)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.xaxis.set_major_formatter(PercentFormatter(100, decimals=0))
    ax.set_title('Correct final decision', loc='left', pad=14, fontweight='bold')
    ax.set_xlabel('Expected action matched · higher is better', labelpad=12, fontsize=10)
    for y, n, value in zip([0, 1], correct, percentages):
        ax.text(value + 2, y, f'{n}/{count} · {value:.1f}%', va='center', fontsize=11,
                fontweight='bold', color='#183548')
    ax = axes[1]
    ax.barh([0, 1], costs, color=colors, height=.48, zorder=3)
    ax.set_xlim(0, .70)
    ax.set_xticks([0, .20, .40, .60])
    ax.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f'${value:.2f}'))
    ax.set_title('Average cost per task', loc='left', pad=14, fontweight='bold')
    ax.set_xlabel('Estimated provider USD · lower is better', labelpad=12, fontsize=10)
    for y, value in zip([0, 1], costs):
        ax.text(value + .015, y, f'${value:.4f}', va='center', fontsize=11,
                fontweight='bold', color='#183548')
    fig.text(.055, .055,
             'All planned cases included; partial audits retained; multiple engine versions.\n'
             'Costs include retries in selected attempts; exclude superseded runs, fleet/judge inference and infrastructure.',
             color='#637381', fontsize=9, linespacing=1.5)
    for extension in ('svg', 'png'):
        metadata = {'Date': None} if extension == 'svg' else {}
        fig.savefig(HERE / f'decision-cost-comparison.{extension}', dpi=180,
                    facecolor='white', metadata=metadata)
        if extension == 'svg':
            path = HERE / 'decision-cost-comparison.svg'
            path.write_text('\n'.join(line.rstrip() for line in path.read_text().splitlines()) + '\n')
    plt.close(fig)
    print(f'Rendered SVG and PNG: decisions {correct}; USD/task {costs}.')


if __name__ == '__main__':
    main()
