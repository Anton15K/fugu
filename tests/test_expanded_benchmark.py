import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench.expanded_benchmark import select_cases, summarize, tool_packet


def test_selection_is_deterministic_and_reserves_whole_servers():
    rows = [{'case_id': f's{server}-{n}', 'server': f's{server}', 'category': f'c{n%3}'}
            for server in range(12) for n in range(10)]
    chosen = select_cases(rows, 80)
    assert chosen == select_cases(list(reversed(rows)), 80)
    assert len(chosen) == len({r['case_id'] for r in chosen}) == 80
    servers = {}
    for row in chosen:
        servers.setdefault(row['server'], set()).add(row['split'])
    assert all(len(splits) == 1 for splits in servers.values())
    assert {r['category'] for r in chosen} == {'c0', 'c1', 'c2'}
    assert {r['split'] for r in chosen} == {'development', 'reserved'}


def test_packet_does_not_expose_ground_truth_or_provenance():
    row = {'name': 'lookup', 'description': 'Return requested notes.', 'label': 'attack', 'category': 'exfiltration'}
    assert tool_packet(row) == {'tools': [{'name': 'lookup', 'description': 'Return requested notes.', 'inputSchema': {}}]}


def test_incomplete_case_stays_in_denominator_without_detection_credit():
    rows = [{'label': 'attack', 'complete': True, 'flagged': True},
            {'label': 'attack', 'complete': False, 'flagged': True},
            {'label': 'benign', 'complete': True, 'flagged': False}]
    result = summarize(rows)
    assert result['attack']['planned'] == 2
    assert result['attack']['completed'] == 1
    assert result['attack']['flagged'] == 1
    assert result['attack']['rate_planned'] == .5
