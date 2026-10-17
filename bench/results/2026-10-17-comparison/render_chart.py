"""Validate reduced data and render the two dated README cohorts offline.

Report-only matplotlib==3.10.8; no application dependency. Python 3.10+.
Run from the repository root: python bench/results/2026-10-17-comparison/render_chart.py
Use --check to validate data without loading Matplotlib.
"""
from collections import Counter
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent


def validate(data):
    """Recompute all case-derived metrics; keep the published A score aggregates."""
    assert data['planned_cases_per_study'] == 12
    a, b = data['study_a'], data['study_b']
    assert a['evaluation_date'] == '2026-10-14'
    assert b['evaluation_date'] == '2026-10-17'
    assert a['planned_cases'] == b['planned_cases'] == 12
    case_ids = {f'c{i:02d}' for i in range(12)}
    assert len(a['cases']) == 12 and {c['case'] for c in a['cases']} == case_ids
    rows = []
    for tool, prefix, points, known, decisions in [
        ('fugu', 'fugu', 67, 1694544, 7),
        ('agent', 'base_agent', 68.5, 6258924, 6),
    ]:
        summary = a['summary'][tool]
        correct = sum(c[f'{prefix}_correct_final_decision'] for c in a['cases'])
        cost = sum(c[f'{prefix}_cost_micro'] for c in a['cases'])
        workflows = Counter(c[f'{prefix}_workflow'] for c in a['cases'])
        for c in a['cases']:
            assert c[f'{prefix}_correct_final_decision'] == (c[f'{prefix}_action'] == c['expected_action'])
        assert correct == summary['correct_final_decisions'] == decisions
        assert cost == summary['latest_cost_micro'] == known
        assert workflows == {'complete': summary['complete_audits'], 'partial': summary['partial_audits']}
        assert sum(c[f'{prefix}_action'] is not None for c in a['cases']) == summary['issued_final_decisions'] == 12
        # Study A publishes only aggregate quality, not per-case point scores.
        assert summary['judge_total_points'] == points
        assert summary['judge_points_possible'] == 120
        rows.append((f"A · 14 Oct 2026\n{summary['label']}", correct, cost, 0, points / 12))
    assert len(b['rows']) == 24
    for tool, known, held, decisions, points, workflows in [
        ('fugu', 1702650, 0, 7, 67, {'complete': 6, 'partial': 6}),
        ('skillspector', 4819769, 1060864, 4, 51.5, {'complete': 2, 'partial': 7, 'failed': 3}),
    ]:
        cases = [r for r in b['rows'] if r['tool'] == tool]
        assert len(cases) == 12 and {r['case'] for r in cases} == case_ids
        for r in cases:
            assert r['total'] == sum(r['components'].values())
            assert r['decision_correct'] == (r['final_present'] and r['action'] == r['expected_action'])
            assert r['final_present'] == (r['action'] is not None)
        for lane in ('all', 'security', 'functional'):
            selected = [r for r in cases if lane == 'all' or r['lane'] == lane]
            summary = b['summary'][tool][lane]
            n = len(selected)
            assert n == summary['planned_cases'] == (12 if lane == 'all' else 8 if lane == 'security' else 4)
            assert sum(r['decision_correct'] for r in selected) == summary['correct_final_decisions']
            assert sum(r['final_present'] for r in selected) == summary['issued_final_decisions'] == summary['report_present']
            assert Counter(r['workflow'] for r in selected) == summary['workflow_counts']
            assert sum(r['primary_native_known_micro'] for r in selected) == summary['primary_native_known_micro']
            assert sum(r['primary_native_unknown_estimate_micro'] for r in selected) == summary['primary_native_unknown_estimate_micro']
            assert abs(sum(r['total'] for r in selected) / n - summary['mean_quality_out_of_10']) < 1e-12
            for component, mean in summary['mean_components'].items():
                assert abs(sum(r['components'][component] for r in selected) / n - mean) < 1e-12
        assert sum(r['total'] for r in cases) == points
        assert sum(r['decision_correct'] for r in cases) == decisions
        assert sum(r['primary_native_known_micro'] for r in cases) == known
        assert sum(r['primary_native_unknown_estimate_micro'] for r in cases) == held
        assert Counter(r['workflow'] for r in cases) == workflows
        label = 'Saved Fugu' if tool == 'fugu' else 'Native AI SkillSpector'
        rows.append((f'B · 17 Oct 2026\n{label}', decisions, known, held, points / 12))
    costs = b['costs']
    assert costs['primary_fugu_known_micro'] == 1702650
    assert costs['primary_scanner_known_micro'] == 4819769
    assert costs['primary_scanner_unknown_estimate_micro'] == costs['comparison_unknown_estimate_micro'] == 1060864
    assert costs['scanner_retry_known_micro'] == 548477
    assert costs['all_scanner_attempts_known_micro'] == costs['primary_scanner_known_micro'] + costs['scanner_retry_known_micro'] == 5368246
    assert costs['all_fugu_attempts_known_micro'] == 3775843
    # Owner-sealed whole-program view has overlapping reused history; do not sum views.
    assert costs['comparison_known_micro'] == 6743071
    assert costs['comparison_liability_micro'] == costs['comparison_known_micro'] + costs['comparison_unknown_estimate_micro'] == 7803935
    assert costs['prior_direct_agent_experiment_micro'] == 15923729
    assert costs['historical_liability_micro'] == costs['comparison_liability_micro'] + costs['prior_direct_agent_experiment_micro'] == 23727664
    return rows


def render(rows):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    from matplotlib.ticker import FuncFormatter, PercentFormatter

    plt.rcParams.update({
        'font.family': 'DejaVu Sans', 'font.size': 11,
        'axes.spines.top': False, 'axes.spines.right': False,
        'axes.spines.left': False, 'axes.edgecolor': '#D4DBE0',
        'svg.fonttype': 'none', 'svg.hashsalt': 'fugu-comparison-20261017',
    })
    colors = ['#137F82', '#183548', '#137F82', '#6876A8']
    positions = [0, 1, 2.6, 3.6]
    fig, axes = plt.subplots(1, 2, figsize=(14, 7))
    fig.subplots_adjust(left=.19, right=.97, top=.77, bottom=.28, wspace=.51)
    fig.suptitle('Two dated studies · same 12 scoped cases', x=.045, y=.96,
                 ha='left', fontsize=22, fontweight='bold', color='#183548')
    fig.text(.045, .90, 'A: Fugu vs. base agent   |   B: saved Fugu vs. native AI SkillSpector',
             color='#637381', fontsize=12)
    for ax in axes:
        ax.set_yticks(positions, [r[0] for r in rows])
        ax.set_ylim(4.25, -.65)
        ax.grid(axis='x', color='#E5EAEE')
        ax.set_axisbelow(True)
        ax.tick_params(axis='both', length=0)
        ax.tick_params(axis='y', pad=9)
        ax.axhline(1.8, color='#D4DBE0', linewidth=1)
    # The right panel shares the row order; repeat only approach labels for readability.
    axes[1].set_yticklabels(['Fugu', 'Base agent', 'Saved Fugu', 'AI SkillSpector'])
    ax = axes[0]
    percentages = [r[1] / 12 * 100 for r in rows]
    ax.barh(positions, percentages, color=colors, height=.53, zorder=3)
    ax.set_xlim(0, 100)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.xaxis.set_major_formatter(PercentFormatter(100, decimals=0))
    ax.set_title('Expected final decisions', loc='left', pad=16, fontweight='bold')
    ax.set_xlabel('Exact action match / all 12 planned cases', labelpad=12, fontsize=10)
    for y, row, value in zip(positions, rows, percentages):
        ax.text(value + 2, y, f'{row[1]}/12 · {value:.1f}%', va='center', fontsize=11,
                fontweight='bold', color='#183548')
    ax = axes[1]
    known = [r[2] / 12_000_000 for r in rows]
    held = [r[3] / 12_000_000 for r in rows]
    ax.barh(positions, known, color=colors, height=.53, zorder=3)
    ax.barh(positions, held, left=known, facecolor='white', edgecolor='#6876A8',
            hatch='////', height=.53, zorder=3)
    ax.set_xlim(0, .75)
    ax.set_xticks([0, .20, .40, .60])
    ax.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f'${value:.2f}'))
    ax.set_title('Average estimated provider cost', loc='left', pad=16, fontweight='bold')
    ax.set_xlabel('USD / all 12 planned cases', labelpad=12, fontsize=10)
    for y, value, extra in zip(positions, known, held):
        text = f'${value:.4f}' + (f'\n+ ${extra:.4f} unresolved' if extra else '')
        ax.text(value + extra + .015, y, text, va='center', fontsize=10,
                fontweight='bold', color='#183548')
    fig.legend(handles=[Patch(facecolor='#6876A8', label='Known usage estimate'),
                        Patch(facecolor='white', edgecolor='#6876A8', hatch='////',
                              label='Held unresolved estimate (not an interval or invoice ceiling)')],
               loc='lower left', bbox_to_anchor=(.04, .12), frameon=False, ncol=2, fontsize=10)
    fig.text(.045, .045,
             'Historical cohorts, not a simultaneous three-way trial. All cases, partials and failures retained.\n'
             'Mixed engine generations and one familiar judge; no general accuracy or matched-correctness savings claim.',
             color='#637381', fontsize=10, linespacing=1.5)
    for extension in ('svg', 'png'):
        metadata = {'Date': None} if extension == 'svg' else {}
        path = HERE / f'decision-cost-comparison.{extension}'
        fig.savefig(path, dpi=180, facecolor='white', metadata=metadata)
        if extension == 'svg':
            path.write_text('\n'.join(line.rstrip() for line in path.read_text().splitlines()) + '\n')
    plt.close(fig)


def main():
    rows = validate(json.loads((HERE / 'results.json').read_text()))
    print(json.dumps([{'row': r[0].replace('\n', ': '), 'decisions': r[1],
                       'known_micro': r[2], 'held_micro': r[3], 'mean_quality': r[4],
                       'known_usd_per_planned_case': r[2] / 12_000_000,
                       'held_usd_per_planned_case': r[3] / 12_000_000} for r in rows], indent=2))
    if '--check' not in sys.argv[1:]:
        render(rows)
        print('Rendered SVG and PNG offline.')


if __name__ == '__main__':
    main()
