"""Replay retained source-only results. No network or auditee execution."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    measured = json.loads((here / 'measured.json').read_text())
    adjudication = json.loads((here / 'adjudication.json').read_text())
    matches = [r for r in measured['rows'] if r['id'] == args.artifact]
    if not matches:
        parser.error('Unknown artifact; see measurement-plan.json')
    row = matches[0]
    print('RETAINED MEASUREMENT: S0/S1/S2 on selected source files, 2026-10-02')
    print(row['repository'], row['commit'])
    print('Selected files:', ', '.join(row['input_sha256']))
    print('S3/S4: not run. Whole repository and runtime behavior: unmeasured.')
    for stage in row['stages']:
        m = stage['metrics']
        coverage = f"{m['units_completed']}/{m['units_total']} units" if stage['stage'] == 'semantic' else f"{m['files_scanned']}/{m['files_seen']} files"
        print(stage['stage'], 'ok=' + str(stage['ok']), coverage, 'raw alerts=' + str(len(stage['findings'])))
        for i, finding in enumerate(stage['findings']):
            note = next(a for a in adjudication['alerts'] if
                        (a['artifact'], a['stage'], a['finding_index']) == (row['id'], stage['stage'], i))
            print(' ', finding['severity'].upper(), finding['confidence'], finding['title'])
            print('  Source adjudication:', note['classification'])
            print(' ', note['assessment'])
            print('  Source:', note['primary_url'])
    print('No vulnerability was confirmed in this scoped source review.')


if __name__ == '__main__':
    main()
