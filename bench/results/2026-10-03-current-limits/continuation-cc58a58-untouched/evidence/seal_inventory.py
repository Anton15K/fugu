"""Create the schema-2 inventory for this completed, leased data phase."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[5]
CHILD = Path(__file__).resolve().parents[1]
MANIFEST = CHILD / 'artifact-manifest.json'
REGISTRY = ROOT / ('bench/results/2026-10-03-current-limits/continuation-registry/'
                  '708623e0fac256a4cb2810bdddc2875ba22a1ad3b16bbdb7ed39324821d3b987.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert not MANIFEST.exists(), 'Preserve an existing seal rather than overwrite it'
    child_files = sorted(path for path in CHILD.rglob('*') if path.is_file())
    assert not any(path.is_symlink() for path in CHILD.rglob('*'))
    outside = [ROOT / 'docs/benchmark-current-limits-continuation.md', REGISTRY,
               REGISTRY.with_suffix('.lock')]
    guard = REGISTRY.with_suffix('.guard.json')
    if guard.exists():
        outside.append(guard)
    paths = sorted(child_files + outside)
    entries = [{'path': str(path.relative_to(ROOT)), 'sha256': digest(path)} for path in paths]
    assert all(path.is_file() and not path.is_symlink() for path in paths)
    assert len({row['path'] for row in entries}) == len(entries)
    registry = json.loads(REGISTRY.read_text())
    assert registry['attempts'] == 919 and registry['session_open'] is False
    assert registry['stop_reason'] is None and not guard.exists()
    inventory = {
        'schema': 2,
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'Every new child regular file, the exact outside registry/lock and the continuation report; excludes this manifest itself',
        'queue_id': 'qitem-20261003080043-770294f3',
        'review_queue_ref': 'qitem-20261003075455-5e493534',
        'reviewed_commit': '2b5e134f11ff4a1349d519dfaa2f0051c2012e1f',
        'source_commit': 'cc58a58d6cea861510980814ae2e70b7bdf24e63',
        'accepted_plan_sha256': 'ea8cff37184b4dd7efe06d3494643462298b398bebcb471d50ce0d6d76f32835',
        'parent_inventory_sha256': '63240327fc6adf050b6cefbd0340f1fb6c16700c48551bc12548b071a057783e',
        'parent_previous_inventory_sha256': '0aae4a79a057069dfd568d6e06fe01653e046bf5a8fba9868e0257a311aa3835',
        'measurement_status': 'child_completed_original_parent_partial_retained',
        'child_measurement_complete': True,
        'combined_measurement_complete': False,
        'counts': {
            'ledger_rows': 919, 'cumulative_ledger_rows': 1278, 'native_audits': 32,
            'child_cases_complete': 27, 'combined_cases_complete': 39,
            'combined_cases_partial': 1, 'measured_png': 3, 'measured_svg': 3,
            'child_regular_files': len(child_files), 'outside_regular_files': len(outside),
        },
        'bookkeeping': {
            'journal_lock_path': str((CHILD / '.journal.lock').relative_to(ROOT)),
            'registry_path': str(REGISTRY.relative_to(ROOT)),
            'registry_lock_path': str(REGISTRY.with_suffix('.lock').relative_to(ROOT)),
            'registry_guard_present': guard.exists(), 'registry_session_open': False,
        },
        'excluded_local_artifacts': {'engine_snapshot': True, 'copied_prepared_targets': True,
                                    'copied_scratch_targets': True, 'plotting_dependencies': True},
        'files': len(entries),
        'sha256': entries,
    }
    MANIFEST.write_text(json.dumps(inventory, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'manifest': str(MANIFEST.relative_to(ROOT)),
                      'sha256': digest(MANIFEST), 'files': len(entries),
                      'counts': inventory['counts']}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
